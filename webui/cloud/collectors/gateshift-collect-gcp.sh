#!/usr/bin/env bash
# Gateshift collector for Google Cloud: reads a project's networks,
# firewall rules, policies, instances and routes with gcloud and writes
# the bundle the Gateshift bundle upload takes. Run it where gcloud is
# signed in (Google Cloud Shell has gcloud and jq ready). Nothing is
# changed in the project, the account needs read access to Compute
# Engine (and to Network Security address groups and the instances'
# effective tags where policies use them).
#
#   gateshift-collect-gcp.sh [project-id]     default: the CLI's project
#
# The bundle holds the REST resources as gcloud prints them, keyed
# networks, subnetworks, firewalls, networkFirewallPolicies (global and
# regional, each with its rules), firewallPolicies (the hierarchical
# policies as each network sees them), instances, routes, addressGroups
# and instanceTags. Upload the file under Devices > Add Device > Google
# Cloud (bundle upload).
set -euo pipefail
command -v gcloud >/dev/null 2>&1 || { echo "gcloud not found" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }

project=${1:-$(gcloud config get-value project 2>/dev/null || true)}
[ -z "$project" ] && { echo "no project: pass a project id" >&2; exit 1; }
out="gateshift-gcp-${project}-$(date -u +%Y%m%dT%H%M%SZ).json"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# g <file> <gcloud args...>: JSON output, an empty list when the call is refused
g() {
  local file=$1; shift
  gcloud --project "$project" --format=json --quiet "$@" > "$file" 2>/dev/null || echo '[]' > "$file"
}

g "$tmp/networks.json" compute networks list
g "$tmp/subnetworks.json" compute networks subnets list
g "$tmp/firewalls.json" compute firewall-rules list
g "$tmp/instances.json" compute instances list
g "$tmp/routes.json" compute routes list
for f in networks subnetworks firewalls instances routes; do
  echo "  $f: $(jq 'length' "$tmp/$f.json")" >&2
done

# network firewall policies: the list carries no rules, describe each one
echo '[]' > "$tmp/policies.json"
g "$tmp/plist.json" compute network-firewall-policies list --global
for name in $(jq -r '.[].name' "$tmp/plist.json"); do
  g "$tmp/p.json" compute network-firewall-policies describe "$name" --global
  jq --slurpfile p "$tmp/p.json" '. + [$p[0]]' "$tmp/policies.json" > "$tmp/l2" && mv "$tmp/l2" "$tmp/policies.json"
done
for region in $(jq -r '[.[].region | split("/") | last] | unique | .[]' "$tmp/subnetworks.json"); do
  g "$tmp/plist.json" compute network-firewall-policies list --region "$region"
  for name in $(jq -r '.[].name' "$tmp/plist.json"); do
    g "$tmp/p.json" compute network-firewall-policies describe "$name" --region "$region"
    jq --arg r "$region" --slurpfile p "$tmp/p.json" '. + [$p[0] + {region: $r}]' "$tmp/policies.json" > "$tmp/l2" && mv "$tmp/l2" "$tmp/policies.json"
  done
done
echo "  networkFirewallPolicies: $(jq 'length' "$tmp/policies.json")" >&2

# hierarchical policies, as each network sees them (no organisation read needed)
echo '[]' > "$tmp/hier.json"
for net in $(jq -r '.[].name' "$tmp/networks.json"); do
  g "$tmp/eff.json" compute networks get-effective-firewalls "$net"
  jq --arg n "$net" --slurpfile e "$tmp/eff.json" \
     '. + [(($e[0].firewallPolicys // [])[] | select(.type == "HIERARCHY")
           | {name: .name, displayName: (.displayName // .name), type: "HIERARCHY", rules: (.rules // []), networks: [$n]})]' \
     "$tmp/hier.json" > "$tmp/l2" && mv "$tmp/l2" "$tmp/hier.json"
done
echo "  firewallPolicies (hierarchical): $(jq 'length' "$tmp/hier.json")" >&2

# address groups (Network Security API), when it is enabled
g "$tmp/groups.json" network-security address-groups list --location=global

# secure tags per instance, only when a policy references them
echo '{}' > "$tmp/tags.json"
if jq -e '[.[] | .rules[]? | ((.match.srcSecureTags // []) + (.targetSecureTags // []))] | flatten | length > 0' "$tmp/policies.json" >/dev/null; then
  jq -r '.[] | "\(.selfLink)|\(.zone | split("/") | last)|\(.id)"' "$tmp/instances.json" | while IFS='|' read -r link zone id; do
    # a zonal resource's tags answer only on the zone's endpoint (--location)
    g "$tmp/t.json" resource-manager tags bindings list --effective --location="$zone" --parent="//compute.googleapis.com/projects/$project/zones/$zone/instances/$id"
    jq --arg l "$link" --slurpfile t "$tmp/t.json" '. + {($l): $t[0]}' "$tmp/tags.json" > "$tmp/l2" && mv "$tmp/l2" "$tmp/tags.json"
  done
  echo "  instanceTags: $(jq 'length' "$tmp/tags.json") instance(s)" >&2
fi

jq -n --arg p "$project" \
   --slurpfile networks "$tmp/networks.json" --slurpfile subnetworks "$tmp/subnetworks.json" \
   --slurpfile firewalls "$tmp/firewalls.json" --slurpfile policies "$tmp/policies.json" \
   --slurpfile hier "$tmp/hier.json" --slurpfile instances "$tmp/instances.json" \
   --slurpfile routes "$tmp/routes.json" --slurpfile groups "$tmp/groups.json" --slurpfile tags "$tmp/tags.json" \
   '{project: $p, fetchedAt: (now | todate), collector: "gateshift-collect-gcp",
     networks: $networks[0], subnetworks: $subnetworks[0], firewalls: $firewalls[0],
     networkFirewallPolicies: $policies[0], firewallPolicies: $hier[0], instances: $instances[0],
     routes: $routes[0], addressGroups: $groups[0], instanceTags: $tags[0]}' > "$out"
echo "bundle written: $out" >&2
