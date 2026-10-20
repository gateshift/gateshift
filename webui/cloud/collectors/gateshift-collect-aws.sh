#!/usr/bin/env bash
# Gateshift collector for AWS: reads an account's network and firewall
# resources with the AWS CLI and writes the bundle the Gateshift bundle
# upload takes. Run it where the CLI is signed in (AWS CloudShell has
# aws and jq ready). Nothing is changed in the account, the key needs
# read access only (EC2 Describe*, STS GetCallerIdentity and, where
# Network Firewall is in use, its List and Describe calls).
#
#   gateshift-collect-aws.sh [region ...]     default: the CLI's region
#
# The bundle holds the describe outputs as the CLI prints them, keyed
# Vpcs, Subnets, RouteTables, SecurityGroups, NetworkAcls,
# NetworkInterfaces, PrefixLists, PrefixListEntries, NetworkFirewalls,
# NetworkFirewallPolicies and NetworkFirewallRuleGroups, every item
# tagged with its Region. Upload the file under Devices > Add Device >
# Amazon Web Services (bundle upload).
set -euo pipefail
command -v aws >/dev/null 2>&1 || { echo "aws CLI not found" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }

regions=("$@")
if [ ${#regions[@]} -eq 0 ]; then
  r=$(aws configure get region 2>/dev/null || true)
  [ -n "${AWS_DEFAULT_REGION:-}" ] && r=$AWS_DEFAULT_REGION
  [ -n "${AWS_REGION:-}" ] && r=$AWS_REGION
  [ -z "$r" ] && { echo "no region configured: pass one or more regions" >&2; exit 1; }
  regions=("$r")
fi
account=$(aws sts get-caller-identity --query Account --output text)
out="gateshift-aws-${account}-$(date -u +%Y%m%dT%H%M%SZ).json"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo '{"PrefixListEntries": {}}' > "$tmp/bundle.json"

# add <key> <region> <file holding {key: [...]}>: append the list, each item tagged with Region
add() {
  jq --arg k "$1" --arg r "$2" --slurpfile new "$3" \
     '.[$k] = ((.[$k] // []) + (($new[0][$k] // []) | map(. + {Region: $r})))' \
     "$tmp/bundle.json" > "$tmp/b2" && mv "$tmp/b2" "$tmp/bundle.json"
}

for region in "${regions[@]}"; do
  echo "region $region" >&2
  for pair in Vpcs:describe-vpcs Subnets:describe-subnets RouteTables:describe-route-tables \
              SecurityGroups:describe-security-groups NetworkAcls:describe-network-acls \
              NetworkInterfaces:describe-network-interfaces; do
    key=${pair%%:*}; cmd=${pair#*:}
    aws ec2 "$cmd" --region "$region" --output json > "$tmp/$key.json"
    add "$key" "$region" "$tmp/$key.json"
    echo "  $key: $(jq --arg k "$key" '.[$k] | length' "$tmp/$key.json")" >&2
  done

  # managed prefix lists: the account's own, plus AWS-managed ones a group references
  aws ec2 describe-managed-prefix-lists --region "$region" --output json > "$tmp/pls.json"
  jq -r '[.SecurityGroups[] | (.IpPermissions[]?, .IpPermissionsEgress[]?) | .PrefixListIds[]?.PrefixListId] | unique | .[]' \
     "$tmp/SecurityGroups.json" | jq -R . | jq -s . > "$tmp/referenced.json"
  jq --arg acct "$account" --slurpfile ref "$tmp/referenced.json" \
     '{PrefixLists: [.PrefixLists[] | select(.OwnerId == $acct or (.PrefixListId as $id | $ref[0] | index($id)))]}' \
     "$tmp/pls.json" > "$tmp/PrefixLists.json"
  add PrefixLists "$region" "$tmp/PrefixLists.json"
  for id in $(jq -r '.PrefixLists[].PrefixListId' "$tmp/PrefixLists.json"); do
    aws ec2 get-managed-prefix-list-entries --region "$region" --prefix-list-id "$id" --output json \
      > "$tmp/entries.json" 2>/dev/null || echo '{"Entries": []}' > "$tmp/entries.json"
    jq --arg id "$id" --slurpfile e "$tmp/entries.json" '.PrefixListEntries[$id] = ($e[0].Entries // [])' \
       "$tmp/bundle.json" > "$tmp/b2" && mv "$tmp/b2" "$tmp/bundle.json"
  done
  echo "  PrefixLists: $(jq '.PrefixLists | length' "$tmp/PrefixLists.json")" >&2

  # Network Firewall, when the account uses it and the key may read it
  if aws network-firewall list-firewalls --region "$region" --output json > "$tmp/fws.json" 2>/dev/null; then
    for arn in $(jq -r '.Firewalls[].FirewallArn' "$tmp/fws.json"); do
      aws network-firewall describe-firewall --region "$region" --firewall-arn "$arn" --output json \
        | jq --arg r "$region" '. + {Region: $r}' > "$tmp/fw.json"
      jq --slurpfile f "$tmp/fw.json" '.NetworkFirewalls = ((.NetworkFirewalls // []) + $f)' \
         "$tmp/bundle.json" > "$tmp/b2" && mv "$tmp/b2" "$tmp/bundle.json"
    done
    for parn in $(jq -r --arg r "$region" '[.NetworkFirewalls[]? | select(.Region == $r) | .Firewall.FirewallPolicyArn] | unique | .[]' "$tmp/bundle.json"); do
      aws network-firewall describe-firewall-policy --region "$region" --firewall-policy-arn "$parn" --output json \
        | jq --arg r "$region" '. + {Region: $r}' > "$tmp/pol.json"
      jq --slurpfile p "$tmp/pol.json" '.NetworkFirewallPolicies = ((.NetworkFirewallPolicies // []) + $p)' \
         "$tmp/bundle.json" > "$tmp/b2" && mv "$tmp/b2" "$tmp/bundle.json"
    done
    for garn in $(jq -r --arg r "$region" '[.NetworkFirewallPolicies[]? | select(.Region == $r) | .FirewallPolicy | (.StatelessRuleGroupReferences[]?, .StatefulRuleGroupReferences[]?) | .ResourceArn] | unique | .[]' "$tmp/bundle.json"); do
      aws network-firewall describe-rule-group --region "$region" --rule-group-arn "$garn" --output json \
        | jq --arg r "$region" '. + {Region: $r}' > "$tmp/rg.json"
      jq --slurpfile g "$tmp/rg.json" '.NetworkFirewallRuleGroups = ((.NetworkFirewallRuleGroups // []) + $g)' \
         "$tmp/bundle.json" > "$tmp/b2" && mv "$tmp/b2" "$tmp/bundle.json"
    done
    echo "  NetworkFirewalls: $(jq '.Firewalls | length' "$tmp/fws.json")" >&2
  else
    echo "  Network Firewall: not readable or not in use, skipped" >&2
  fi
done

printf '%s\n' "${regions[@]}" | jq -R . | jq -s . > "$tmp/regions.json"
jq --arg a "$account" --slurpfile regs "$tmp/regions.json" \
   '. + {accountId: $a, regions: $regs[0], fetchedAt: (now | todate), collector: "gateshift-collect-aws"}' \
   "$tmp/bundle.json" > "$out"
echo "bundle written: $out" >&2
