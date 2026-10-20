#!/usr/bin/env bash
# Gateshift collector for Microsoft Azure: reads a subscription's network
# and firewall resources through the Resource Manager API (az rest) and
# writes the bundle the Gateshift bundle upload takes. Run it where the
# Azure CLI is signed in (Azure Cloud Shell has az and jq ready). Nothing
# is changed in the subscription, the account needs the Reader role.
#
#   gateshift-collect-azure.sh [subscription-id] [resource-group ...]
#   default: the CLI's current subscription, the whole subscription
#
# The bundle holds the Resource Manager list results (the shape with
# `properties`, not the flattened `az network ... list` output), keyed
# virtualNetworks, networkSecurityGroups, applicationSecurityGroups,
# networkInterfaces, routeTables, ipGroups, firewallPolicies (each with
# its ruleCollectionGroups) and azureFirewalls. Upload the file under
# Devices > Add Device > Microsoft Azure (bundle upload).
set -euo pipefail
command -v az >/dev/null 2>&1 || { echo "az CLI not found" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }

sub=${1:-$(az account show --query id -o tsv)}
[ -z "$sub" ] && { echo "no subscription: sign in or pass a subscription id" >&2; exit 1; }
[ $# -gt 0 ] && shift
api="2023-09-01"
out="gateshift-azure-${sub:0:8}-$(date -u +%Y%m%dT%H%M%SZ).json"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

scopes=()
if [ $# -gt 0 ]; then
  for rg in "$@"; do scopes+=("/subscriptions/$sub/resourceGroups/$rg"); done
else
  scopes=("/subscriptions/$sub")
fi

# list <path> <file>: the value arrays of every page, following nextLink
list() {
  local url="https://management.azure.com$1?api-version=$api"
  echo '[]' > "$2"
  while [ -n "$url" ]; do
    az rest --method get --url "$url" -o json > "$tmp/page.json"
    jq --slurpfile p "$tmp/page.json" '. + ($p[0].value // [])' "$2" > "$tmp/l2" && mv "$tmp/l2" "$2"
    url=$(jq -r '.nextLink // empty' "$tmp/page.json")
  done
}

jq -n --arg s "$sub" --arg api "$api" \
   '{subscriptionId: $s, apiVersion: $api, fetchedAt: (now | todate), collector: "gateshift-collect-azure"}' > "$tmp/bundle.json"
for type in virtualNetworks networkSecurityGroups applicationSecurityGroups networkInterfaces \
            routeTables ipGroups firewallPolicies azureFirewalls; do
  echo '[]' > "$tmp/$type.json"
  for scope in "${scopes[@]}"; do
    if list "$scope/providers/Microsoft.Network/$type" "$tmp/part.json"; then
      jq --slurpfile p "$tmp/part.json" '. + $p[0]' "$tmp/$type.json" > "$tmp/l2" && mv "$tmp/l2" "$tmp/$type.json"
    else
      echo "  $type in $scope: not readable, skipped" >&2
    fi
  done
  jq --arg t "$type" --slurpfile i "$tmp/$type.json" '.[$t] = $i[0]' "$tmp/bundle.json" > "$tmp/b2" && mv "$tmp/b2" "$tmp/bundle.json"
  echo "  $type: $(jq 'length' "$tmp/$type.json")" >&2
done

# a policy's rules live in its rule collection groups, a sub-resource
for id in $(jq -r '.firewallPolicies[].id' "$tmp/bundle.json"); do
  list "$id/ruleCollectionGroups" "$tmp/groups.json" || echo '[]' > "$tmp/groups.json"
  jq --arg id "$id" --slurpfile g "$tmp/groups.json" \
     '(.firewallPolicies[] | select(.id == $id)).ruleCollectionGroups = $g[0]' \
     "$tmp/bundle.json" > "$tmp/b2" && mv "$tmp/b2" "$tmp/bundle.json"
done

cp "$tmp/bundle.json" "$out"
echo "bundle written: $out" >&2
