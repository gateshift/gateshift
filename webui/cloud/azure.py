# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Microsoft Azure as a SOURCE: network security groups and the network
they attach to, read from a subscription (ARM REST) or from an uploaded
bundle of the same JSON, parsed into the shapes the Gateshift import and
collect handlers store.

Model (docs/CLOUD_SOURCES_PLAN.md, D2/D3): one device row = one
subscription (optionally filtered to resource groups or VNets). Zones are
topological: every subnet is a zone and a pseudo-interface without an
address. Application security groups, IP groups and explicit prefix lists
are address groups whose members are resolved at import time; they are
never zones. NSG rules become one ordered rulebase; a rule's zones follow
from the subnets the NSG is attached to (subnet-level NSG: the subnet,
NIC-level NSG: the subnet the NIC sits in).

The bundle is a dict of ARM list results keyed by resource type (the
plural ARM names): virtualNetworks, networkSecurityGroups,
applicationSecurityGroups, networkInterfaces, routeTables. The fetcher
(`fetch_bundle`) produces it; an upload carries the same keys. Shapes
follow the Microsoft.Network REST reference (api-version 2023-09-01):
every resource is {id, name, location, properties: {...}}.

Nothing here talks to the database or to main.py; `register()` in the
package wires the two entry points into the import/collect registries.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from ._common import literal_ref, member_objects, port_literal, service_ref

API_VERSION = "2023-09-01"
ARM = "https://management.azure.com"
LOGIN = "https://login.microsoftonline.com"

# Resource types the bundle carries, in the order the fetcher reads them.
# The firewall types (P4) are optional in an upload: a subscription without
# Azure Firewall simply has empty lists. Every firewall policy carries its
# rule collection groups under `ruleCollectionGroups` (read per policy).
# A firewall in a Virtual WAN hub (SKU AZFW_Hub) lists like a VNet firewall
# and is read through its policy the same way; its rules are marked with
# the hub firewall's name. Verified live 2026-10-09 against a secured hub
# in the lab subscription (`_seed_estate.py` with GS_AZURE_HUB=1).
BUNDLE_TYPES = ("virtualNetworks", "networkSecurityGroups", "applicationSecurityGroups",
                "networkInterfaces", "routeTables", "ipGroups", "firewallPolicies", "azureFirewalls")

# Service tags with a fixed meaning. VirtualNetwork is replaced by the VNet's
# own address space at parse time; everything else here is a literal.
_TAG_LOADBALANCER = "168.63.129.16/32"


class AzureAuthError(Exception):
    """Token refused or the subscription is not readable with it."""


# ── ARM helpers ────────────────────────────────────────────────────────

def rid_name(resource_id: str | None) -> str:
    """The last path element of an ARM id (the resource name)."""
    return (resource_id or "").rstrip("/").rsplit("/", 1)[-1]


def rid_parent(resource_id: str | None, kind: str) -> str:
    """The name of the `kind` segment's owner in an ARM id, e.g. the VNet
    of '/.../virtualNetworks/hub/subnets/web' for kind='virtualNetworks'."""
    parts = (resource_id or "").split("/")
    for i, p in enumerate(parts):
        if p.lower() == kind.lower() and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _props(r: dict) -> dict:
    """The resource's properties. The Resource Manager API nests them under
    `properties`; the Azure CLI's `az network ... list` flattens them into
    the object, so an upload of that shape is read the same way."""
    if not isinstance(r, dict):
        return {}
    if isinstance(r.get("properties"), dict):
        return r["properties"]
    return r


def _ids(items) -> list[str]:
    return [x.get("id") for x in (items or []) if isinstance(x, dict) and x.get("id")]


# ── Fetch ──────────────────────────────────────────────────────────────

def get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """OAuth2 client credentials against Entra ID for the ARM audience."""
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": client_id,
        "client_secret": client_secret, "scope": f"{ARM}/.default"}).encode()
    req = urllib.request.Request(f"{LOGIN}/{tenant_id}/oauth2/v2.0/token", data=data)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise AzureAuthError(f"Azure login rejected (HTTP {exc.code}): check tenant id, "
                             f"client id and client secret. {detail}")
    except urllib.error.URLError as exc:
        raise AzureAuthError(f"Azure login endpoint unreachable: {exc.reason}")
    token = body.get("access_token")
    if not token:
        raise AzureAuthError("Azure token response carried no access_token")
    return token


def arm_list(token: str, path: str, api_version: str = API_VERSION) -> list[dict]:
    """GET an ARM list endpoint, following nextLink paging."""
    url = f"{ARM}{path}?api-version={api_version}"
    out: list[dict] = []
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                                   "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            if exc.code in (401, 403):
                raise AzureAuthError(f"Azure refused {path} (HTTP {exc.code}): the app needs "
                                     f"the Reader role on the subscription. {detail}")
            raise RuntimeError(f"Azure GET {path} failed (HTTP {exc.code}): {detail}")
        out.extend(payload.get("value") or [])
        url = payload.get("nextLink")
    return out


def fetch_bundle(tenant_id: str, client_id: str, client_secret: str, subscription_id: str,
                 resource_groups: list[str] | None = None) -> dict:
    """Read the subscription (or the given resource groups) into a bundle."""
    token = get_token(tenant_id, client_id, client_secret)
    bundle: dict = {"subscriptionId": subscription_id, "apiVersion": API_VERSION,
                    "fetchedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    scopes = ([f"/subscriptions/{subscription_id}/resourceGroups/{rg}" for rg in resource_groups]
              if resource_groups else [f"/subscriptions/{subscription_id}"])
    for rtype in BUNDLE_TYPES:
        items: list[dict] = []
        for scope in scopes:
            items.extend(arm_list(token, f"{scope}/providers/Microsoft.Network/{rtype}"))
        bundle[rtype] = items
    # a policy's rules live in its rule collection groups, a sub-resource
    for pol in bundle.get("firewallPolicies") or []:
        if pol.get("id"):
            pol["ruleCollectionGroups"] = arm_list(token, f"{pol['id']}/ruleCollectionGroups")
    return bundle


def device_settings(device: dict) -> dict:
    """The azure block of the device's config JSON."""
    try:
        return (json.loads(device.get("config") or "{}") or {}).get("azure") or {}
    except Exception:
        return {}


def bundle_for_device(device: dict) -> dict:
    """Live fetch when credentials are on the row, else the stored upload."""
    cfg = device_settings(device)
    secret = device.get("api_key") or ""
    if secret and cfg.get("tenant_id") and cfg.get("client_id") and cfg.get("subscription_id"):
        rgs = [x.strip() for x in str(cfg.get("resource_groups") or "").split(",") if x.strip()]
        return fetch_bundle(cfg["tenant_id"], cfg["client_id"], secret, cfg["subscription_id"], rgs or None)
    raw = cfg.get("bundle")
    if raw:
        return json.loads(raw) if isinstance(raw, str) else raw
    raise AzureAuthError("no Azure credentials and no uploaded bundle on this device")


# ── Parse ──────────────────────────────────────────────────────────────

def _cidr(value: str):
    """A prefix of either family (docs/IPV6_PLAN.md, phase 4), or None."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except Exception:
        return None


def _host_cidr(value: str) -> str:
    """A bare address as a host prefix of its family, a prefix as is."""
    v = str(value).strip()
    return v if "/" in v else f"{v}/{128 if ':' in v else 32}"


def _ports_of(p: dict) -> list[str]:
    ranges = [x for x in (p.get("destinationPortRanges") or []) if x]
    single = p.get("destinationPortRange")
    if not ranges and single:
        ranges = [single]
    return [str(x).strip() for x in ranges if str(x).strip()]


def _source_ports_of(p: dict) -> list[str]:
    ranges = [x for x in (p.get("sourcePortRanges") or []) if x]
    single = p.get("sourcePortRange")
    if not ranges and single:
        ranges = [single]
    return [str(x).strip() for x in ranges if str(x).strip() and str(x).strip() != "*"]


def _services_of(p: dict) -> list[str]:
    """Protocol + destination ports → canonical service literals.
    '*' with ports means TCP and UDP; '*' without ports means any."""
    proto = str(p.get("protocol") or "*").lower()
    ports = _ports_of(p)
    if proto in ("icmp", "esp", "ah"):
        return [proto]
    if proto == "*":
        if not ports or ports == ["*"]:
            return ["any"]
        return [x for x in (port_literal(pr, pt) for pr in ("tcp", "udp") for pt in ports) if x]
    if not ports or ports == ["*"]:
        return [f"{proto}/1-65535"]
    return [x for x in (port_literal(proto, pt) for pt in ports) if x] or [f"{proto}/1-65535"]


def _prefixes_of(p: dict, side: str) -> list[str]:
    many = [x for x in (p.get(f"{side}AddressPrefixes") or []) if x]
    single = p.get(f"{side}AddressPrefix")
    if not many and single:
        many = [single]
    return [str(x).strip() for x in many if str(x).strip()]


class _Net:
    """Everything the parse needs to know about the subscription's network."""

    def __init__(self, bundle: dict):
        self.vnets = bundle.get("virtualNetworks") or []
        self.nsgs = bundle.get("networkSecurityGroups") or []
        self.asgs = bundle.get("applicationSecurityGroups") or []
        self.nics = bundle.get("networkInterfaces") or []
        self.route_tables = bundle.get("routeTables") or []
        self.ip_groups_raw = bundle.get("ipGroups") or []
        self.policies_raw = bundle.get("firewallPolicies") or []
        self.firewalls = bundle.get("azureFirewalls") or []
        self.vnet_space: dict[str, list[str]] = {}
        self.subnets: dict[str, dict] = {}        # subnet id (lower) -> info
        self.zone_of_subnet: dict[str, str] = {}
        self.nic_ips: dict[str, list[tuple[str, str]]] = {}   # nic id -> [(ip, subnet id)]
        self.asg_members: dict[str, list[str]] = {}            # asg id -> ips
        self.ip_groups: dict[str, dict] = {}                   # ip group id (lower) -> {name, cidrs}
        self.ip_groups_used: dict[str, dict] = {}              # name -> {cidrs}
        self.policies: dict[str, dict] = {}                    # policy id (lower) -> resource
        self.fqdns: dict[str, str] = {}                        # object name -> host
        self.synth: dict[str, dict] = {}                       # address objects made from literals
        self.synth_svc: dict[str, dict] = {}       # service objects made from the rules' protocol/port literals
        self.drops: dict[str, list[str]] = {}
        self._index()

    def drop(self, key: str, what: str) -> None:
        self.drops.setdefault(key, []).append(what)

    def _index(self) -> None:
        names_seen: dict[str, int] = {}
        for v in self.vnets:
            vp = _props(v)
            self.vnet_space[v.get("id", "").lower()] = list((vp.get("addressSpace") or {}).get("addressPrefixes") or [])
            for s in vp.get("subnets") or []:
                sp = _props(s)
                cidrs = [x for x in (sp.get("addressPrefixes") or []) if x] or \
                        ([sp.get("addressPrefix")] if sp.get("addressPrefix") else [])
                names_seen[s.get("name", "")] = names_seen.get(s.get("name", ""), 0) + 1
                self.subnets[s.get("id", "").lower()] = {
                    "id": s.get("id"), "name": s.get("name"), "vnet": v.get("name"),
                    "vnet_id": v.get("id", "").lower(), "location": v.get("location"),
                    "cidrs": cidrs, "nsg": ((sp.get("networkSecurityGroup") or {}).get("id") or "").lower(),
                    "route_table": ((sp.get("routeTable") or {}).get("id") or "").lower(),
                }
        # zone names: the subnet name, prefixed with the VNet when it repeats
        for sid, s in self.subnets.items():
            zone = s["name"] if names_seen.get(s["name"], 0) == 1 else f"{s['vnet']}-{s['name']}"
            self.zone_of_subnet[sid] = zone
            s["zone"] = zone
        for n in self.nics:
            ips: list[tuple[str, str]] = []
            for ipc in _props(n).get("ipConfigurations") or []:
                ipp = _props(ipc)
                ip = (ipp.get("privateIPAddress") or "").strip()
                sid = ((ipp.get("subnet") or {}).get("id") or "").lower()
                if ip:
                    ips.append((ip, sid))
                for asg in ipp.get("applicationSecurityGroups") or []:
                    aid = (asg.get("id") or "").lower()
                    if ip and ":" not in ip:
                        self.asg_members.setdefault(aid, []).append(ip)
            self.nic_ips[n.get("id", "").lower()] = ips
        for g in self.ip_groups_raw:
            name = g.get("name") or rid_name(g.get("id"))
            cidrs: list[str] = []
            for a in _props(g).get("ipAddresses") or []:
                a = str(a).strip()
                if _cidr(a) is not None:
                    cidrs.append(a if "/" in a else f"{a}/32")
            self.ip_groups[(g.get("id") or "").lower()] = {"name": name, "cidrs": cidrs}
        for pol in self.policies_raw:
            self.policies[(pol.get("id") or "").lower()] = pol

    def fqdn_object(self, host: str) -> str:
        host = host.strip().rstrip(".")
        name = "fqdn-" + host.replace("*", "wildcard")
        self.fqdns[name] = host
        return name

    def ip_group(self, gid: str, owner: str) -> str:
        g = self.ip_groups.get((gid or "").lower())
        if g is None:
            name = rid_name(gid) or "ip-group"
            self.ip_groups_used.setdefault(name, {"cidrs": []})
            self.drop("ip_group_unresolved", f"{owner}:{name}")
            return name
        self.ip_groups_used.setdefault(g["name"], {"cidrs": list(g["cidrs"])})
        return g["name"]

    def subnet_for_ip(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.IPv4Address(ip)
        except Exception:
            return None
        for s in self.subnets.values():
            for c in s["cidrs"]:
                net = _cidr(c)
                if net and addr in net:
                    return s
        return None

    def zones_for_prefixes(self, prefixes: list[str]) -> list[str]:
        """The subnets (as zones) a list of CIDRs falls into; 'any' when a
        prefix lies outside every subnet or the list is empty."""
        zones: list[str] = []
        for pfx in prefixes:
            net = _cidr(pfx)
            if net is None:
                return ["any"]
            hit = False
            for s in self.subnets.values():
                for c in s["cidrs"]:
                    sn = _cidr(c)
                    if sn and sn.version == net.version and (net.subnet_of(sn) or sn.subnet_of(net)):
                        if s["zone"] not in zones:
                            zones.append(s["zone"])
                        hit = True
            if not hit:
                return ["any"]
        return zones or ["any"]


def _nsg_scope(net: _Net, nsg: dict) -> tuple[list[dict], list[tuple[str, str]]]:
    """(subnets the NSG is attached to, NIC (ip, subnet id) pairs it is
    attached to)."""
    p = _props(nsg)
    subnets = [net.subnets[i.lower()] for i in _ids(p.get("subnets")) if i.lower() in net.subnets]
    nics: list[tuple[str, str]] = []
    for nid in _ids(p.get("networkInterfaces")):
        nics.extend(net.nic_ips.get(nid.lower(), []))
    return subnets, nics


def _resolve_side(net: _Net, p: dict, side: str, scope_literals: list[str],
                  scope_zones: list[str], is_scope_side: bool,
                  unresolved: list[str], owner: str = "rule") -> tuple[list[str], list[str]]:
    """One side of a rule → (address literals / group names, zones).

    Service tags: VirtualNetwork becomes the VNet address space,
    AzureLoadBalancer its documented address, Internet and '*' become
    'any'; any other tag is unresolved (the rule is imported disabled).
    Application security groups become group names. On the side the NSG
    is attached to, '*' means the attachment scope (subnet CIDRs or NIC
    addresses) and the zones are the attached subnets."""
    asgs = [rid_name(i) for i in _ids(p.get(f"{side}ApplicationSecurityGroups"))]
    prefixes = _prefixes_of(p, side)
    if asgs:
        return asgs, (scope_zones if is_scope_side else ["any"])
    literals: list[str] = []
    for pfx in prefixes:
        if pfx == "*":
            if is_scope_side and scope_literals:
                literals.extend(scope_literals)
            else:
                return ["any"], (scope_zones if is_scope_side else ["any"])
        elif pfx.lower() == "internet":
            return ["any"], ["any"]
        elif pfx.lower() == "virtualnetwork":
            space = [c for cs in net.vnet_space.values() for c in cs]
            if not space:
                return ["any"], (scope_zones if is_scope_side else ["any"])
            literals.extend(space)
        elif pfx.lower() == "azureloadbalancer":
            literals.append(_TAG_LOADBALANCER)
        elif _cidr(pfx) is not None:
            literals.append(_host_cidr(pfx))
        else:
            unresolved.append(pfx)
    if not literals:
        return ["any"], (scope_zones if is_scope_side else ["any"])
    if is_scope_side:
        zones = scope_zones
    else:
        zones = net.zones_for_prefixes(literals)
    # a rule side holds object names, never literals (see _common.literal_ref)
    names: list[str] = []
    for lit in literals:
        n = literal_ref(lit, owner, net.synth)
        if n not in names:
            names.append(n)
    return names, zones


def _parse_rules(net: _Net) -> list[dict]:
    rules: list[dict] = []
    seq = 0
    for nsg in sorted(net.nsgs, key=lambda n: n.get("name") or ""):
        nsg_name = nsg.get("name") or rid_name(nsg.get("id"))
        subnets, nics = _nsg_scope(net, nsg)
        scope_literals = [c for s in subnets for c in s["cidrs"]] + [ip if "/" in ip else f"{ip}/32" for ip, _ in nics]
        scope_zones: list[str] = []
        for s in subnets:
            if s["zone"] not in scope_zones:
                scope_zones.append(s["zone"])
        for ip, sid in nics:
            z = net.zone_of_subnet.get(sid) or (net.subnet_for_ip(ip) or {}).get("zone")
            if z and z not in scope_zones:
                scope_zones.append(z)
        if not scope_zones:
            net.drop("nsg_unattached", nsg_name)
            scope_zones = ["any"]
        p = _props(nsg)
        entries = [(r, False) for r in p.get("securityRules") or []] + \
                  [(r, True) for r in p.get("defaultSecurityRules") or []]
        for direction in ("Inbound", "Outbound"):
            ordered = sorted((e for e in entries
                              if str(_props(e[0]).get("direction") or "").lower() == direction.lower()),
                             key=lambda e: (int(_props(e[0]).get("priority") or 0)))
            for r, is_default in ordered:
                rp = _props(r)
                name = r.get("name") or f"rule-{seq}"
                unresolved: list[str] = []
                dropped: list[str] = []
                raw_extras: dict = {"azure_nsg": nsg_name, "azure_priority": rp.get("priority"),
                                    "azure_direction": direction, "azure_rule_id": r.get("id")}
                inbound = direction == "Inbound"
                owner = f"{nsg_name}-{name}"
                src, src_zones = _resolve_side(net, rp, "source", scope_literals, scope_zones,
                                               is_scope_side=not inbound, unresolved=unresolved, owner=owner)
                dst, dst_zones = _resolve_side(net, rp, "destination", scope_literals, scope_zones,
                                               is_scope_side=inbound, unresolved=unresolved, owner=owner)
                disabled = 0
                description = (rp.get("description") or "").strip()
                if unresolved:
                    # per rule only (dropped_inputs): the import route counts
                    # those by rule and adds the object-level drops on top
                    raw_extras["azure_unresolved_tags"] = list(unresolved)
                    dropped.append("service_tag_unresolved")
                    disabled = 1
                    description = (description + " " if description else "") + \
                        f"[not imported: service tag {', '.join(unresolved)} has no address form]"
                src_ports = _source_ports_of(rp)
                if src_ports:
                    raw_extras["azure_source_ports"] = src_ports
                    dropped.append("source_ports")
                rule = {
                    "rule_name":      f"{nsg_name}-{name}",
                    "seq_num":        seq,
                    "action":         "allow" if str(rp.get("access") or "").lower() == "allow" else "deny",
                    "src_zones":      src_zones,
                    "dst_zones":      dst_zones,
                    "sources":        src,
                    "destinations":   dst,
                    "services":       _services_of(rp),
                    "applications":   [],
                    "description":    description,
                    "disabled":       disabled,
                    "tags":           [],
                    "negate_source":      0,
                    "negate_destination": 0,
                    "negate_service":     0,
                    "schedule":       None,
                    "source_identities": None,
                    "raw_extras":     raw_extras,
                    "dropped_inputs": dropped,
                }
                if is_default:
                    rule["default_rule_kind"] = f"azure-nsg-{name.lower()}"
                rules.append(rule)
                seq += 1
    return rules


# ── Azure Firewall (P4a): policies, classic collections, DNAT ──────────

def _fw_services(protocols, ports, owner: str, net: _Net) -> list[str]:
    """Network-rule ipProtocols x destinationPorts -> service literals.
    'Any' with ports means TCP and UDP; 'Any' without ports means any."""
    protos = [str(p).lower() for p in (protocols or []) if str(p).strip()] or ["any"]
    ports = [str(p).strip() for p in (ports or []) if str(p).strip()] or ["*"]
    out: list[str] = []
    for proto in protos:
        if proto == "any":
            if ports == ["*"]:
                return ["any"]
            cands = ["tcp", "udp"]
        elif proto in ("tcp", "udp"):
            cands = [proto]
        elif proto == "icmp":
            cands = ["icmp"]
        else:
            net.drop("protocol_unsupported", f"{owner}:{proto}")
            continue
        for c in cands:
            if c == "icmp":
                lits = ["icmp"]
            else:
                lits = [x for x in (port_literal(c, p) for p in ports) if x]
            for lit in lits:
                if lit not in out:
                    out.append(lit)
    return out or ["any"]


def _fw_side(net: _Net, addresses, ip_groups, fqdns, owner: str,
             unresolved: list[str]) -> tuple[list[str], list[str]]:
    """One side of a firewall rule -> (literals, group names and FQDN
    objects; zones). Service tags follow the NSG rules: Internet and '*'
    are any, VirtualNetwork the VNet space, other tags are unresolved."""
    out: list[str] = []
    zones: list[str] = []
    any_seen = False
    for a in addresses or []:
        a = str(a).strip()
        if not a:
            continue
        if a == "*" or a.lower() == "internet":
            any_seen = True
        elif a.lower() == "virtualnetwork":
            out.extend(c for cs in net.vnet_space.values() for c in cs if c not in out)
        elif a.lower() == "azureloadbalancer":
            out.append(_TAG_LOADBALANCER)
        elif _cidr(a) is not None:
            lit = _host_cidr(a)
            if lit not in out:
                out.append(lit)
        else:
            unresolved.append(a)
    for gid in ip_groups or []:
        name = net.ip_group(gid, owner)
        if name not in out:
            out.append(name)
        for c in net.ip_groups_used.get(name, {}).get("cidrs") or []:
            zones = _merge_zones(zones, net.zones_for_prefixes([c]))
    for host in fqdns or []:
        if str(host).strip():
            name = net.fqdn_object(str(host))
            if name not in out:
                out.append(name)
            zones = ["any"]
    if any_seen:
        return ["any"], ["any"]
    if not out:
        return ["any"], ["any"]
    lits = [x for x in out if _cidr(x) is not None]
    if lits and zones != ["any"]:
        zones = _merge_zones(zones, net.zones_for_prefixes(lits))
    # literals become address objects the rule references by name
    named: list[str] = []
    for x in out:
        n = literal_ref(x, owner, net.synth) if _cidr(x) is not None else x
        if n not in named:
            named.append(n)
    return named, (zones or ["any"])


def _merge_zones(acc: list[str], more: list[str]) -> list[str]:
    if "any" in acc or "any" in more:
        return ["any"]
    for z in more:
        if z not in acc:
            acc.append(z)
    return acc


def _policy_chain(net: _Net, pol: dict) -> list[dict]:
    """[parent ..., policy]: Azure evaluates the parent's rules first."""
    chain: list[dict] = []
    seen: set[str] = set()
    cur: dict | None = pol
    while cur is not None:
        cid = (cur.get("id") or "").lower()
        if cid in seen:
            break
        seen.add(cid)
        chain.insert(0, cur)
        base = ((_props(cur).get("basePolicy") or {}).get("id") or "").lower()
        if not base:
            break
        cur = net.policies.get(base)
        if cur is None:
            net.drop("policy_parent_unread", f"{pol.get('name')}:{rid_name(base)}")
            break
    return chain


def _collections(pol: dict) -> list[tuple[int, int, str, dict]]:
    """(group priority, collection priority, group name, collection) of a
    policy, in Azure's order. A classic firewall is given as a pseudo
    policy whose collections sit in one group."""
    out: list[tuple[int, int, str, dict]] = []
    for g in sorted(pol.get("ruleCollectionGroups") or [], key=lambda x: int(_props(x).get("priority") or 0)):
        gp = _props(g)
        for col in sorted(gp.get("ruleCollections") or [], key=lambda x: int(x.get("priority") or 0)):
            out.append((int(gp.get("priority") or 0), int(col.get("priority") or 0), g.get("name") or "", col))
    return out


def _classic_as_policy(fw: dict) -> dict:
    """The rule collections of a firewall without a policy, in the shape of
    a policy with one rule collection group per collection type."""
    p = _props(fw)
    groups = []
    for kind, key, action_default in (("nat", "natRuleCollections", "Dnat"),
                                      ("network", "networkRuleCollections", None),
                                      ("application", "applicationRuleCollections", None)):
        cols = []
        for col in p.get(key) or []:
            cp = _props(col)
            rules = []
            for r in cp.get("rules") or []:
                rr = dict(r)
                rr.setdefault("ruleType", {"nat": "NatRule", "network": "NetworkRule", "application": "ApplicationRule"}[kind])
                if "protocols" in rr and kind != "application":
                    rr.setdefault("ipProtocols", rr.get("protocols"))
                rules.append(rr)
            cols.append({"name": col.get("name"), "priority": cp.get("priority"),
                         "ruleCollectionType": "FirewallPolicyNatRuleCollection" if kind == "nat" else "FirewallPolicyFilterRuleCollection",
                         "action": cp.get("action") or ({"type": action_default} if action_default else {}),
                         "rules": rules})
        if cols:
            groups.append({"name": f"{fw.get('name')}-{kind}", "properties": {"priority": {"nat": 100, "network": 200, "application": 300}[kind],
                                                                              "ruleCollections": cols}})
    return {"name": fw.get("name"), "id": fw.get("id"), "properties": {}, "ruleCollectionGroups": groups}


def _parse_firewall_rules(net: _Net, seq: int, rules: list[dict], nat_rules: list[dict]) -> int:
    """The Azure Firewall block(s), in front of the NSG rules: per attached
    policy (and per classic firewall) DNAT, then network, then application
    rules, the parent policy's rules before the child's, groups and
    collections by priority, rules in order. Returns the next seq."""
    attached: dict[str, list[str]] = {}         # policy id -> firewall names
    hubs: dict[str, list[str]] = {}             # policy id -> the firewalls among them that sit in a Virtual WAN hub
    classic: list[dict] = []
    for fw in sorted(net.firewalls, key=lambda f: f.get("name") or ""):
        fp = _props(fw)
        name = fw.get("name") or rid_name(fw.get("id"))
        pid = ((fp.get("firewallPolicy") or {}).get("id") or "").lower()
        # a hub firewall (SKU AZFW_Hub, placed by its virtual hub, addresses
        # under hubIPAddresses) has no ipConfigurations and always carries a
        # policy; its rules read like a VNet firewall's
        is_hub = str((fp.get("sku") or {}).get("name") or "").upper() == "AZFW_HUB" or bool(fp.get("virtualHub"))
        if pid:
            attached.setdefault(pid, []).append(name)
            if is_hub:
                hubs.setdefault(pid, []).append(name)
        elif is_hub:
            net.drop("hub_firewall_without_policy", name)
        else:
            classic.append(_classic_as_policy(fw))
    parents = {((_props(p).get("basePolicy") or {}).get("id") or "").lower() for p in net.policies_raw}
    blocks: list[tuple[str, dict, list[str]]] = []
    for pol in sorted(net.policies_raw, key=lambda p: p.get("name") or ""):
        pid = (pol.get("id") or "").lower()
        if pid in attached:
            blocks.append((pol.get("name") or rid_name(pol.get("id")), pol, attached[pid]))
        elif pid in parents:
            continue                        # read within its children's blocks
        else:
            net.drop("policy_unattached", pol.get("name") or rid_name(pol.get("id")))
            blocks.append((pol.get("name") or rid_name(pol.get("id")), pol, []))
    read_ids = {(p.get("id") or "").lower() for p in net.policies_raw}
    for pid, fw_names in attached.items():
        if pid not in read_ids:
            # the policy lives outside the read (another subscription, a
            # central Virtual WAN policy): the firewall's rules are not here
            for name in fw_names:
                net.drop("firewall_policy_unread", f"{name}:{rid_name(pid)}")
    for fw_pol in classic:
        blocks.append((fw_pol["name"], fw_pol, [fw_pol["name"]]))

    # rule names are unique across the whole firewall block: a parent policy
    # shared by two firewalls repeats its rules in the second block, and the
    # review attributes hashless drops by rule name
    names_taken: set[str] = set()
    for block_name, pol, fw_names in blocks:
        chain = _policy_chain(net, pol) if pol.get("ruleCollectionGroups") is not None and pol in net.policies_raw else [pol]
        hub_names = [n for n in fw_names if n in (hubs.get((pol.get("id") or "").lower()) or [])]

        def rule_name(col_name: str, r_name: str) -> str:
            name = f"{col_name}-{r_name}"
            if name in names_taken:
                name = f"{block_name}-{name}"
            names_taken.add(name)
            return name

        for want in ("NatRule", "NetworkRule", "ApplicationRule"):
            for pol_level in chain:
                pol_name = pol_level.get("name") or block_name
                for g_prio, c_prio, g_name, col in _collections(pol_level):
                    action_type = str(((col.get("action") or {}).get("type")) or "").lower()
                    for r in col.get("rules") or []:
                        rtype = str(r.get("ruleType") or "NetworkRule")
                        if rtype != want:
                            continue
                        r_name = r.get("name") or f"rule-{seq}"
                        name = rule_name(col.get("name") or "collection", r_name)
                        unresolved: list[str] = []
                        dropped: list[str] = []
                        notes: list[str] = []
                        raw_extras = {"azure_firewall_policy": pol_name, "azure_firewalls": fw_names,
                                      "azure_rule_collection_group": g_name, "azure_rule_collection": col.get("name"),
                                      "azure_collection_priority": c_prio, "azure_rule_type": rtype,
                                      "azure_collection_action": action_type}
                        if hub_names:
                            raw_extras["azure_hub_firewalls"] = hub_names
                        src, src_zones = _fw_side(net, r.get("sourceAddresses"), r.get("sourceIpGroups"), [], name, unresolved)
                        if rtype == "NatRule":
                            # the NAT rule, plus the allow Azure adds for the translated traffic
                            orig_dst = [str(a).strip() for a in r.get("destinationAddresses") or [] if str(a).strip()]
                            services = _fw_services(r.get("ipProtocols"), r.get("destinationPorts"), name, net)
                            trans = str(r.get("translatedAddress") or r.get("translatedFqdn") or "").strip()
                            tport = str(r.get("translatedPort") or "").strip()
                            nat_rules.append({
                                "position": len(nat_rules), "name": name, "nat_type": "dnat",
                                "src_zones": [], "dst_zones": [],
                                "orig_src": [] if src == ["any"] else src,
                                "orig_dst": [a if "/" in a else f"{a}/32" for a in orig_dst if _cidr(a) is not None],
                                "orig_service": [] if services == ["any"] else services,
                                "trans_src": None, "trans_src_type": "none",
                                "trans_dst": trans or None, "trans_dst_port": tport or None,
                                "disabled": False, "description": (r.get("description") or "").strip() or None,
                                "properties": {"azure_firewall_policy": pol_name, "azure_rule_collection": col.get("name")},
                                "source_vendor_id": name,
                            })
                            if trans and _cidr(trans) is not None:
                                tlit = trans if "/" in trans else f"{trans}/32"
                                tservices = ([f"{s.split('/')[0]}/{tport}" for s in services if "/" in s] if tport else services) or ["any"]
                                # its own name: the review keys drops by rule name
                                # where a hash is missing, and the NAT rule carries
                                # this one, so a shared name would misattribute a
                                # dropped NAT rule to the security rule
                                rule = _rule_dict(f"{name}-allow", seq, "allow", src, src_zones,
                                                  [literal_ref(tlit, name, net.synth)], net.zones_for_prefixes([tlit]),
                                                  tservices, "[allow Azure adds for the translated traffic of this DNAT rule]",
                                                  0, dict(raw_extras, azure_dnat_implicit_allow=True), [])
                                rules.append(rule)
                                seq += 1
                            else:
                                net.drop("dnat_translated_fqdn", name)
                            continue
                        if rtype == "ApplicationRule":
                            dst, dst_zones = _fw_side(net, r.get("destinationAddresses"), [], r.get("targetFqdns"), name, unresolved)
                            services = []
                            for pr in r.get("protocols") or []:
                                ptype = str(pr.get("protocolType") or "").lower()
                                port = str(pr.get("port") or {"http": "80", "https": "443", "mssql": "1433"}.get(ptype, "")).strip()
                                lit = port_literal("tcp", port) if port else None
                                if lit and lit not in services:
                                    services.append(lit)
                            services = services or ["any"]
                            for key, field in (("fqdnTags", "fqdn_tags"), ("webCategories", "web_categories"),
                                               ("targetUrls", "target_urls")):
                                if r.get(key):
                                    dropped.append(field)
                                    raw_extras[f"azure_{key}"] = r[key]
                            if r.get("terminateTLS"):
                                dropped.append("terminate_tls")
                            if any("*" in str(h) for h in r.get("targetFqdns") or []):
                                dropped.append("fqdn_wildcard")
                            if not (r.get("targetFqdns") or r.get("destinationAddresses")):
                                notes.append("[not imported: the rule matches only on "
                                             + ", ".join(f for f in dropped if f != "terminate_tls") + ", which no target holds]")
                        else:
                            dst, dst_zones = _fw_side(net, r.get("destinationAddresses"), r.get("destinationIpGroups"),
                                                      r.get("destinationFqdns"), name, unresolved)
                            services = _fw_services(r.get("ipProtocols"), r.get("destinationPorts"), name, net)
                        disabled = 0
                        if unresolved:
                            dropped.append("service_tag_unresolved")
                            raw_extras["azure_unresolved_tags"] = list(unresolved)
                            notes.append(f"[not imported: service tag {', '.join(unresolved)} has no address form]")
                        if notes:
                            disabled = 1
                        description = " ".join([x for x in [(r.get("description") or "").strip()] + notes if x])
                        rules.append(_rule_dict(name, seq, "deny" if action_type == "deny" else "allow", src, src_zones,
                                                dst, dst_zones, services, description, disabled, raw_extras, dropped))
                        seq += 1
        deny_extras = {"azure_firewall_policy": block_name, "azure_firewalls": fw_names, "azure_implicit": True}
        if hub_names:
            deny_extras["azure_hub_firewalls"] = hub_names
        deny = _rule_dict(f"{block_name}-implicit-deny", seq, "deny", ["any"], ["any"], ["any"], ["any"], ["any"],
                          "Azure Firewall denies what no rule allowed, for the traffic routed through it. Imported "
                          "disabled, the network security groups close the ruleset", 1, deny_extras, [])
        deny["default_rule_kind"] = "azure-fw-implicit-deny"
        rules.append(deny)
        seq += 1
    return seq


def _rule_dict(name, seq, action, src, src_zones, dst, dst_zones, services, description, disabled, raw_extras, dropped) -> dict:
    return {
        "rule_name":      name,
        "seq_num":        seq,
        "action":         action,
        "src_zones":      src_zones,
        "dst_zones":      dst_zones,
        "sources":        src,
        "destinations":   dst,
        "services":       services,
        "applications":   [],
        "description":    description,
        "disabled":       disabled,
        "tags":           [],
        "negate_source":      0,
        "negate_destination": 0,
        "negate_service":     0,
        "schedule":       None,
        "source_identities": None,
        "raw_extras":     raw_extras,
        "dropped_inputs": dropped,
    }


def _parse_objects(net: _Net) -> list[dict]:
    """ASGs and IP groups as address groups whose members are address
    objects synthesised from the resolved addresses (_common.member_objects),
    plus the FQDN objects the firewall rules referenced."""
    objects: list[dict] = []
    synth = net.synth        # one registry: rule literals and members share objects
    for asg in sorted(net.asgs, key=lambda a: a.get("name") or ""):
        name = asg.get("name") or rid_name(asg.get("id"))
        members = sorted(set(net.asg_members.get((asg.get("id") or "").lower(), [])))
        if not members:
            net.drop("membership_empty", name)
        objects.append({"obj_type": "address_group", "name": name, "value": {
            "type": "static", "members": member_objects([f"{m}/32" for m in members], name, synth),
            "description": f"Azure application security group, {len(members)} member(s) resolved at import",
        }})
    for name in sorted(net.ip_groups_used):
        cidrs = net.ip_groups_used[name]["cidrs"]
        if not cidrs:
            net.drop("membership_empty", name)
        objects.append({"obj_type": "address_group", "name": name, "value": {
            "type": "static", "members": member_objects(list(cidrs), name, synth),
            "description": f"Azure IP group, {len(cidrs)} address(es)",
        }})
    for name in sorted(net.fqdns):
        objects.append({"obj_type": "address", "name": name,
                        "value": {"type": "fqdn", "value": net.fqdns[name], "description": "Azure Firewall FQDN target"}})
    return objects + list(synth.values()) + list(net.synth_svc.values())


def _parse_network(net: _Net) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """(interfaces, zones, routes, vrfs).

    A route table is a routing domain of its own in Azure (each subnet
    follows exactly one, or the system routes), so every route table is
    a VR named after it and a subnet without a table sits in 'default'.
    That keeps two tables' default routes apart, which one VR could not
    hold (found on the first live seed, 2026-10-08)."""
    interfaces: list[dict] = []
    zones: list[dict] = []
    vrfs: list[dict] = []
    members_by_vr: dict[str, list[str]] = {}
    rt_name = {rt.get("id", "").lower(): (rt.get("name") or rid_name(rt.get("id")))
               for rt in net.route_tables}
    for sid, s in net.subnets.items():
        vr = rt_name.get(s["route_table"], "default") if s["route_table"] else "default"
        s["vr"] = vr
        iface = {
            "name":         s["zone"],
            "zone":         s["zone"],
            "description":  f"{s['vnet']} {', '.join(s['cidrs'])} {s['location'] or ''}".strip(),
            "ips":          [],
            "type":         "physical",
            "vr_name":      vr,
            "role":         None,
            "dhcp_enabled": False,
            "enabled":      True,
        }
        interfaces.append(iface)
        zones.append({"name": s["zone"], "members": [s["zone"]],
                      "properties": {"azure_vnet": s["vnet"], "azure_subnet": s["name"],
                                     "azure_cidrs": s["cidrs"]}})
        members_by_vr.setdefault(vr, []).append(s["zone"])
    for vr, members in members_by_vr.items():
        if vr != "default":
            vrfs.append({"name": vr, "interface_members": members,
                         "properties": {"interface_members": members}})
    routes: list[dict] = []
    for rt in net.route_tables:
        rtp = _props(rt)
        vr = rt_name.get(rt.get("id", "").lower(), "default")
        for r in rtp.get("routes") or []:
            rp = _props(r)
            prefix, hop_type = rp.get("addressPrefix"), rp.get("nextHopType") or ""
            net_ = _cidr(prefix or "")
            if net_ is None:
                net.drop("route_unresolved", f"{rt.get('name')}/{r.get('name')}:{prefix}")
                continue
            if hop_type != "VirtualAppliance" or not rp.get("nextHopIpAddress"):
                net.drop("route_hop_type", f"{rt.get('name')}/{r.get('name')}:{prefix} via {hop_type or '?'}")
                continue
            hop = rp["nextHopIpAddress"]
            egress = net.subnet_for_ip(hop)
            routes.append({
                "prefix":   str(net_.network_address),
                "plen":     net_.prefixlen,
                "iface":    egress["zone"] if egress else None,
                "next_hop": hop,
                "vr":       vr,
            })
    return interfaces, zones, routes, vrfs


def parse_bundle(bundle: dict) -> dict:
    """The whole subscription in one pass: rules, objects, drops and the
    network strand. Import and collect each take their half."""
    net = _Net(bundle)
    rules: list[dict] = []
    nat_rules: list[dict] = []
    seq = _parse_firewall_rules(net, 0, rules, nat_rules)
    for r in _parse_rules(net):
        r["seq_num"] = seq
        rules.append(r)
        seq += 1
    for r in rules:
        # a rule side holds service names, never literals (see _common.service_ref)
        r["services"] = [service_ref(s, net.synth_svc) for s in (r.get("services") or ["any"])]
    objects = _parse_objects(net)
    interfaces, zones, routes, vrfs = _parse_network(net)
    warnings: list[str] = []
    if net.drops:
        warnings.append("drops: " + ", ".join(f"{k}({len(v)})" for k, v in net.drops.items()))
    sub = bundle.get("subscriptionId") or ""
    return {
        "rules": rules, "nat_rules": nat_rules, "objects": objects, "drops": net.drops,
        "errors": [], "hostname": f"azure-{sub[:8]}" if sub else "azure",
        "interfaces": interfaces, "zones": zones, "routes": routes, "vrfs": vrfs,
        "warnings": warnings,
    }


# ── Entry points (registered into main by the package) ─────────────────

def run_import(device: dict) -> dict:
    parsed = parse_bundle(bundle_for_device(device))
    out = {k: parsed[k] for k in ("rules", "nat_rules", "objects", "drops", "errors", "hostname")}
    # A cloud account is named by the operator (D2); the import must not
    # rename the row the way an appliance import adopts the box hostname.
    if device.get("host_name"):
        out["hostname"] = device["host_name"]
    return out


def collect_network(device: dict) -> dict:
    parsed = parse_bundle(bundle_for_device(device))
    return {k: parsed[k] for k in ("interfaces", "routes", "vrfs", "zones", "errors", "warnings")}


def validate_bundle(raw: str) -> tuple[dict | None, str | None]:
    """An uploaded bundle: JSON with at least the NSG and VNet lists."""
    try:
        data = json.loads(raw)
    except Exception as exc:
        return None, f"not JSON: {exc}"
    if not isinstance(data, dict):
        return None, "the bundle must be a JSON object keyed by resource type"
    missing = [t for t in ("virtualNetworks", "networkSecurityGroups") if t not in data]
    if missing:
        return None, "bundle lacks " + ", ".join(missing)
    for t in BUNDLE_TYPES:
        if t in data and not isinstance(data[t], list):
            return None, f"{t} must be a list"
    return data, None
