# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Google Cloud as a SOURCE: VPC firewall rules and network firewall
policies with the VPC networks they protect, read from a project (Compute
Engine REST with a service-account token, no SDK) or from an uploaded
bundle of the same JSON, parsed into the shapes the Gateshift import and
collect handlers store.

Model (docs/CLOUD_SOURCES_PLAN.md, D2/D3): one device row = one project
(optionally filtered to networks). Zones are topological: every
subnetwork is a zone and a pseudo-interface without an address; every
VPC network is a virtual router. Network tags, service accounts, secure
tags and address groups are address groups whose members are resolved at
import time (the instances' internal addresses, the group's entries);
they are never zones.

The ruleset is ONE ordered rulebase that flattens the evaluation order
Google documents, network by network: hierarchical policies (as the
network sees them), then the VPC firewall rules and the global and
regional network policies in the network's enforcement order (classic
rules first by default), each block by priority. Two implied rules close
it: the implied allow-egress, expressed as "from the subnets to anything
OUTSIDE the subnets" (a negated destination), because inside the VPC the
destination's ingress rules still decide and a plain any-to-any allow
would silently override them; and the implied deny-ingress as the final
any-to-any deny. Both are marked default rules.

The bundle is a dict keyed by resource type in the REST (and gcloud JSON)
spelling: networks, subnetworks, firewalls, networkFirewallPolicies
(global and regional, each carrying its associations), firewallPolicies
(hierarchical, as networks.getEffectiveFirewalls reports them),
instances, routes, addressGroups, plus instanceTags (instance selfLink to
its effective secure tags). The fetcher produces it; an upload carries
the same keys.

Nothing here talks to the database or to main.py; `register()` in the
package wires the two entry points into the import/collect registries.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from ._common import literal_ref, member_objects, port_literal, service_ref

COMPUTE = "https://compute.googleapis.com/compute/v1"
NETSEC = "https://networksecurity.googleapis.com/v1"
CRM = "https://cloudresourcemanager.googleapis.com/v3"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"

BUNDLE_KEYS = ("networks", "subnetworks", "firewalls", "networkFirewallPolicies", "firewallPolicies",
               "instances", "routes", "addressGroups")

_PROTO_NUM = {"6": "tcp", "17": "udp", "1": "icmp", "50": "esp", "51": "ah", "47": "gre", "132": "sctp"}
_PROTO_NAMES = {"tcp", "udp", "icmp", "esp", "ah", "gre", "sctp"}
_MAX_TAGGED_INSTANCES = 300


class GcpAuthError(Exception):
    """Key refused, API not enabled, or the project is not readable."""


class GcpApiError(RuntimeError):
    def __init__(self, code: int, message: str, url: str):
        super().__init__(f"GCP GET {url} failed (HTTP {code}): {message}")
        self.code = code


# ── Auth + REST ────────────────────────────────────────────────────────

def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def get_token(sa: dict, scope: str = SCOPE) -> str:
    """A service-account JWT (RS256) exchanged for an access token."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    for k in ("client_email", "private_key", "token_uri"):
        if not sa.get(k):
            raise GcpAuthError(f"the service-account key lacks {k}")
    now = int(time.time())
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64(json.dumps({"iss": sa["client_email"], "scope": scope, "aud": sa["token_uri"],
                              "iat": now, "exp": now + 3600}).encode())
    try:
        key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
    except Exception as exc:
        raise GcpAuthError(f"the service-account private key is not readable: {exc}")
    signature = _b64(key.sign(header + b"." + claims, padding.PKCS1v15(), hashes.SHA256()))
    assertion = (header + b"." + claims + b"." + signature).decode()
    data = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "assertion": assertion}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(sa["token_uri"], data=data), timeout=30) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise GcpAuthError(f"Google token endpoint rejected the service-account key (HTTP {exc.code}): {detail}")
    except urllib.error.URLError as exc:
        raise GcpAuthError(f"Google token endpoint unreachable: {exc.reason}")
    token = body.get("access_token")
    if not token:
        raise GcpAuthError("Google token response carried no access_token")
    return token


def api_request(token: str, url: str, method: str = "GET", body: dict | None = None,
                params: dict | None = None) -> dict:
    """One authenticated REST call; the JSON answer (or {} for an empty one)."""
    full = url + ("?" + urllib.parse.urlencode(params) if params else "")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(full, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        msg = detail[:300]
        try:
            msg = ((json.loads(detail).get("error") or {}).get("message") or msg)[:300]
        except Exception:
            pass
        if exc.code == 403 and ("has not been used" in msg or "is disabled" in msg):
            raise GcpAuthError(f"an API this read needs is not enabled in the project: {msg}")
        if exc.code in (401, 403):
            raise GcpAuthError(f"Google refused {url} (HTTP {exc.code}): the service account needs read access "
                               f"to the project's network resources. {msg}")
        raise GcpApiError(exc.code, msg, url)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Google endpoint unreachable: {exc.reason}")


def api_get(token: str, url: str, params: dict | None = None) -> dict:
    return api_request(token, url, "GET", None, params)


def api_list(token: str, url: str, params: dict | None = None, key: str = "items") -> list[dict]:
    """A paged list; aggregated lists (items keyed by scope) are flattened."""
    out: list[dict] = []
    page = None
    while True:
        p = dict(params or {})
        if page:
            p["pageToken"] = page
        resp = api_get(token, url, p)
        items = resp.get(key)
        if isinstance(items, dict):            # aggregatedList: {"regions/x": {"subnetworks": [...]}}
            for scope in items.values():
                if not isinstance(scope, dict):
                    continue
                for v in scope.values():
                    if isinstance(v, list):
                        out.extend(x for x in v if isinstance(x, dict))
        elif isinstance(items, list):
            out.extend(x for x in items if isinstance(x, dict))
        page = resp.get("nextPageToken")
        if not page:
            break
    return out


def _base(link: str | None) -> str:
    return (link or "").rstrip("/").rsplit("/", 1)[-1]


def _region_of(link: str | None) -> str:
    m = re.search(r"/regions/([^/]+)", link or "")
    return m.group(1) if m else ""


def tag_host(zone: str) -> str:
    """The Resource Manager host that answers tag reads for a zonal
    resource: the zone-prefixed one. The global host refuses an instance
    parent with HTTP 400 ("must be a tag-compatible global resource"),
    found on the first live secure-tag import 2026-10-09."""
    return CRM.replace("https://", f"https://{zone}-", 1) if zone else CRM


# ── Fetch ──────────────────────────────────────────────────────────────

def fetch_bundle(sa: dict, project: str | None = None, networks: list[str] | None = None) -> dict:
    """Read the project into a bundle. `sa` is the parsed service-account
    key; the project defaults to the key's project."""
    project = (project or sa.get("project_id") or "").strip()
    if not project:
        raise GcpAuthError("no project id: set it on the device or use a key that names one")
    token = get_token(sa)
    bundle: dict = {"project": project, "principal": sa.get("client_email") or "",
                    "fetchedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "warnings": []}
    base = f"{COMPUTE}/projects/{project}"
    nets = api_list(token, f"{base}/global/networks")
    if networks:
        wanted = set(networks)
        nets = [n for n in nets if n.get("name") in wanted]
    bundle["networks"] = nets
    net_links = {n.get("selfLink") for n in nets}
    subnets = api_list(token, f"{base}/aggregated/subnetworks")
    bundle["subnetworks"] = [s for s in subnets if not networks or s.get("network") in net_links]
    regions = sorted({_region_of(s.get("selfLink") or s.get("region")) for s in bundle["subnetworks"]} - {""})
    fws = api_list(token, f"{base}/global/firewalls")
    bundle["firewalls"] = [f for f in fws if not networks or f.get("network") in net_links]
    policies = api_list(token, f"{base}/global/firewallPolicies")
    for region in regions:
        try:
            for pol in api_list(token, f"{base}/regions/{region}/firewallPolicies"):
                pol["region"] = region
                policies.append(pol)
        except GcpApiError as exc:
            bundle["warnings"].append(f"regional firewall policies in {region} not readable (HTTP {exc.code})")
    bundle["networkFirewallPolicies"] = policies
    # hierarchical policies, as each network sees them (needs no org read)
    hier: dict[str, dict] = {}
    for n in nets:
        try:
            eff = api_get(token, f"{base}/global/networks/{n.get('name')}/getEffectiveFirewalls")
        except (GcpApiError, GcpAuthError) as exc:
            bundle["warnings"].append(f"effective firewalls of {n.get('name')} not readable: {str(exc)[:120]}")
            continue
        for pol in eff.get("firewallPolicys") or []:
            if str(pol.get("type") or "").upper() != "HIERARCHY":
                continue
            key = pol.get("name") or pol.get("displayName") or ""
            entry = hier.setdefault(key, {"name": key, "displayName": pol.get("displayName") or key,
                                          "type": "HIERARCHY", "rules": pol.get("rules") or [], "networks": []})
            entry["networks"].append(n.get("name"))
    bundle["firewallPolicies"] = list(hier.values())
    instances = api_list(token, f"{base}/aggregated/instances")
    bundle["instances"] = [i for i in instances if not networks or any(
        (ni.get("network") in net_links) for ni in i.get("networkInterfaces") or [])]
    routes = api_list(token, f"{base}/global/routes")
    bundle["routes"] = [r for r in routes if not networks or r.get("network") in net_links]
    groups: list[dict] = []
    for loc in ["global"] + regions:
        try:
            groups.extend(api_list(token, f"{NETSEC}/projects/{project}/locations/{loc}/addressGroups",
                                   key="addressGroups"))
        except (GcpApiError, GcpAuthError) as exc:
            if loc == "global":
                bundle["warnings"].append(f"address groups not readable: {str(exc)[:120]}")
            break
    bundle["addressGroups"] = groups
    # secure tags: only when a policy references them, one read per instance
    uses_tags = any((r.get("match") or {}).get("srcSecureTags") or r.get("targetSecureTags")
                    for pol in policies + bundle["firewallPolicies"] for r in pol.get("rules") or [])
    bundle["instanceTags"] = {}
    if uses_tags:
        if len(bundle["instances"]) > _MAX_TAGGED_INSTANCES:
            bundle["warnings"].append(f"secure tags not resolved: {len(bundle['instances'])} instances exceed "
                                      f"the {_MAX_TAGGED_INSTANCES} the import reads tags for")
        else:
            for inst in bundle["instances"]:
                zone = _base(inst.get("zone"))
                parent = f"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{inst.get('id')}"
                try:
                    tags = api_get(token, f"{tag_host(zone)}/effectiveTags", {"parent": parent}).get("effectiveTags") or []
                except (GcpApiError, GcpAuthError) as exc:
                    bundle["warnings"].append(f"secure tags not readable: {str(exc)[:120]}")
                    break
                if tags:
                    bundle["instanceTags"][inst.get("selfLink") or inst.get("name")] = tags
    return bundle


def device_settings(device: dict) -> dict:
    """The gcp block of the device's config JSON."""
    try:
        return (json.loads(device.get("config") or "{}") or {}).get("gcp") or {}
    except Exception:
        return {}


def _csv(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value or "").replace(";", ",").split(",") if x.strip()]


def parse_key(raw: str | None) -> dict | None:
    """The service-account key JSON, or None when the text is not one."""
    try:
        sa = json.loads(raw or "")
    except Exception:
        return None
    return sa if isinstance(sa, dict) and sa.get("client_email") and sa.get("private_key") else None


def bundle_for_device(device: dict) -> dict:
    """Live fetch when a key is on the row, else the stored upload."""
    cfg = device_settings(device)
    sa = parse_key(device.get("api_key"))
    if sa:
        return fetch_bundle(sa, cfg.get("project_id") or None, _csv(cfg.get("networks")) or None)
    raw = cfg.get("bundle")
    if raw:
        return json.loads(raw) if isinstance(raw, str) else raw
    raise GcpAuthError("no service-account key and no uploaded bundle on this device")


# ── Parse helpers ──────────────────────────────────────────────────────

def _cidr(value):
    """A prefix of either family (docs/IPV6_PLAN.md, phase 4), or None."""
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except Exception:
        return None


def _host_cidr(value: str) -> str:
    """A bare address as a host prefix of its family, a prefix as is."""
    v = str(value).strip()
    return v if "/" in v else f"{v}/{128 if ':' in v else 32}"


def _any_token(cidr: str) -> list[str] | None:
    """The D5 token a catch-all prefix stands for, None for the rest."""
    c = str(cidr or "").strip()
    return ["any4"] if c == "0.0.0.0/0" else (["any6"] if c == "::/0" else None)


def _side_with_tokens(out: list[str], zones: list[str], toks: set) -> tuple[list[str], list[str]]:
    """A rule side and its zones once the catch-alls are known: both
    families whole is `any`, one family's whole is its token beside the
    names, and a catch-all makes the zones `any`."""
    if {"any4", "any6"} <= toks:
        return ["any"], ["any"]
    if toks:
        return [t for t in ("any4", "any6") if t in toks] + [o for o in out if o not in ("any4", "any6")], ["any"]
    return out, (zones or ["any"])


def _proto_of(raw) -> str | None:
    p = str(raw if raw is not None else "all").strip().lower()
    if p in ("all", "-1", ""):
        return "any"
    if p in _PROTO_NAMES:
        return p
    return _PROTO_NUM.get(p)


def _service_literals(entries: list[dict], owner: str, net: "_Net") -> list[str]:
    """allowed / denied / layer4Configs entries -> canonical service literals."""
    out: list[str] = []
    for e in entries or []:
        proto = _proto_of(e.get("IPProtocol") if "IPProtocol" in e else e.get("ipProtocol"))
        if proto is None:
            net.drop("protocol_unsupported", f"{owner}:{e.get('IPProtocol') or e.get('ipProtocol')}")
            continue
        if proto == "any":
            return ["any"]
        ports = [str(p).strip() for p in (e.get("ports") or []) if str(p).strip()]
        if proto not in ("tcp", "udp", "sctp"):
            lit = [proto]
        elif not ports:
            lit = [f"{proto}/1-65535"]
        else:
            lit = [x for x in (port_literal(proto, p) for p in ports) if x]
        for l in lit:
            if l not in out:
                out.append(l)
    return out or ["any"]


_POLICY_DEFAULT_PRIORITY = 2147483644     # the four implicit goto_next rules of every policy


def _sa_group_name(email: str) -> str:
    return "sa-" + email.split("@", 1)[0]


class _Net:
    """Everything the parse needs to know about the project's network."""

    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.drops: dict[str, list[str]] = {}
        self.networks: dict[str, dict] = {}          # name -> {name, order, subnets, selfLink}
        self.subnets: dict[str, dict] = {}           # selfLink -> info (zone, cidrs, nets, network, region)
        self.tag_members: dict[str, list[tuple[str, str]]] = {}      # tag -> [(ip, subnet link)]
        self.sa_members: dict[str, list[tuple[str, str]]] = {}       # sa email -> [(ip, subnet link)]
        self.stag_members: dict[str, list[tuple[str, str]]] = {}     # tagValues/N -> [(ip, subnet link)]
        self.stag_names: dict[str, str] = {}                         # tagValues/N -> namespaced value
        self.addr_groups: dict[str, dict] = {}      # resource name -> {name, cidrs}
        self.instances_by_link: dict[str, dict] = {}
        self.groups_used: dict[str, dict] = {}      # group name -> {"members": [(ip, subnet)], "kind", "ref"}
        self.fqdns: dict[str, str] = {}             # object name -> host
        self.synth: dict[str, dict] = {}            # address objects made from literals (members, rule sides)
        self.synth_svc: dict[str, dict] = {}       # service objects made from the rules' protocol/port literals
        self._index()

    def drop(self, key: str, what: str) -> None:
        self.drops.setdefault(key, []).append(what)

    def _index(self) -> None:
        b = self.bundle
        for n in b.get("networks") or []:
            name = n.get("name") or _base(n.get("selfLink"))
            self.networks[name] = {"name": name, "selfLink": n.get("selfLink") or "",
                                   "order": str(n.get("networkFirewallPolicyEnforcementOrder") or "AFTER_CLASSIC_FIREWALL"),
                                   "subnets": [], "auto": bool(n.get("autoCreateSubnetworks"))}
        link_to_net = {v["selfLink"]: k for k, v in self.networks.items() if v["selfLink"]}
        counts: dict[str, int] = {}
        for s in b.get("subnetworks") or []:
            counts[s.get("name") or ""] = counts.get(s.get("name") or "", 0) + 1
        # zone names first, in a sorted pass so they are stable: an auto-mode
        # network carries one subnet named like the network in every region,
        # so a repeated name takes the region, then the network as well
        taken: set[str] = set()
        zone_of: dict[str, str] = {}
        for s in sorted(b.get("subnetworks") or [],
                        key=lambda x: (_base(x.get("network")), _region_of(x.get("region") or x.get("selfLink")), x.get("name") or "")):
            link = s.get("selfLink") or s.get("name") or ""
            net_name = link_to_net.get(s.get("network") or "") or _base(s.get("network"))
            name = s.get("name") or _base(link)
            region = _region_of(s.get("region") or link)
            zone = name
            if counts.get(name, 0) > 1 or name in taken:
                for cand in (f"{name}-{region}", f"{net_name}-{name}-{region}", f"{net_name}-{name}-{_base(link)}"):
                    if cand not in taken:
                        zone = cand
                        break
            taken.add(zone)
            zone_of[link] = zone
        for s in b.get("subnetworks") or []:
            link = s.get("selfLink") or ""
            net_name = link_to_net.get(s.get("network") or "") or _base(s.get("network"))
            cidrs = [str(_cidr(c)) for c in [s.get("ipCidrRange")] + [r.get("ipCidrRange") for r in s.get("secondaryIpRanges") or []]
                     if c and _cidr(c) is not None]
            if not cidrs:
                self.drop("subnet_no_ipv4", s.get("name") or link)
                continue
            # a dual-stack subnet (docs/IPV6_PLAN.md, phase 6) carries a ULA or
            # an external IPv6 prefix: it joins the zone's ranges, in the
            # canonical spelling (the API prints the ULA uncompressed)
            cidrs += [str(_cidr(c)) for c in (s.get("internalIpv6Prefix"), s.get("externalIpv6Prefix"))
                      if c and _cidr(c) is not None and str(_cidr(c)) not in cidrs]
            name = s.get("name") or _base(link)
            zone = zone_of.get(link or name, name)
            self.subnets[link or name] = {"link": link, "zone": zone, "network": net_name,
                                          "region": _region_of(s.get("region") or link), "cidrs": cidrs,
                                          "nets": [_cidr(c) for c in cidrs]}
            self.networks.setdefault(net_name, {"name": net_name, "selfLink": s.get("network") or "",
                                                "order": "AFTER_CLASSIC_FIREWALL", "subnets": []})
            self.networks[net_name]["subnets"].append(link or name)
        tag_names = b.get("instanceTags") or {}
        for inst in b.get("instances") or []:
            link = inst.get("selfLink") or inst.get("name") or ""
            self.instances_by_link[link] = inst
            tags = list((inst.get("tags") or {}).get("items") or [])
            emails = [sa.get("email") for sa in inst.get("serviceAccounts") or [] if sa.get("email")]
            for ni in inst.get("networkInterfaces") or []:
                ip = str(ni.get("networkIP") or "").strip()
                if not ip or ":" in ip:
                    continue
                sl = ni.get("subnetwork") or ""
                for t in tags:
                    self.tag_members.setdefault(t, []).append((ip, sl))
                for e in emails:
                    self.sa_members.setdefault(e, []).append((ip, sl))
                for t in tag_names.get(link) or []:
                    tv = t.get("tagValue") or ""
                    if tv:
                        self.stag_members.setdefault(tv, []).append((ip, sl))
                        if t.get("namespacedTagValue"):
                            self.stag_names[tv] = t["namespacedTagValue"]
        # An auto-mode network carries one subnet in every region whether
        # anything lives there or not (a project's `default` network: 40+
        # regional subnets). The empty ones hold nothing to migrate and would
        # bury the estate under zones named default-<region> (0.9.4 matrix,
        # 2026-10-18), so a regional subnet of an auto-mode network stays only
        # when an instance sits in it. The rest are left out and counted. A
        # custom-mode subnet is always kept, someone created it on purpose. An
        # auto-mode network left without subnets goes with them, its rules
        # guard nothing.
        used = {str(ni.get("subnetwork") or "") for inst in (b.get("instances") or [])
                for ni in inst.get("networkInterfaces") or []}
        for key, s in list(self.subnets.items()):
            netinfo = self.networks.get(s["network"]) or {}
            if netinfo.get("auto") and s["link"] not in used:
                self.drop("subnet_auto_unused", s["zone"])
                if key in netinfo.get("subnets", []):
                    netinfo["subnets"].remove(key)
                del self.subnets[key]
        for name in [n for n, v in self.networks.items() if v.get("auto") and not v["subnets"]]:
            self.drop("network_auto_unused", name)
            for fw in b.get("firewalls") or []:
                if _base(fw.get("network")) == name:
                    self.drop("rule_network_unused", fw.get("name") or "")
            del self.networks[name]
        for g in b.get("addressGroups") or []:
            rname = g.get("name") or ""
            cidrs: list[str] = []
            for it in g.get("items") or []:
                v = it if isinstance(it, str) else (it.get("value") or "")
                if _cidr(v) is not None and v not in cidrs:
                    cidrs.append(v)
            self.addr_groups[rname] = {"name": _base(rname), "cidrs": cidrs}

    # -- lookups ----------------------------------------------------------
    def subnet_for_ip(self, ip: str, network: str | None = None) -> dict | None:
        try:
            addr = ipaddress.IPv4Address(ip)
        except Exception:
            return None
        for s in self.subnets.values():
            if network and s["network"] != network:
                continue
            if any(addr in n for n in s["nets"]):
                return s
        return None

    def zones_for_prefix(self, prefix: str) -> list[str]:
        net = _cidr(prefix)
        if net is None:
            return ["any"]
        for s in self.subnets.values():
            if any(net.version == n.version and net.subnet_of(n) for n in s["nets"]):
                return [s["zone"]]
        return ["any"]

    def zones_of_members(self, members: list[tuple[str, str]], network: str | None = None) -> list[str]:
        zones: list[str] = []
        for ip, sl in members:
            s = self.subnets.get(sl) or self.subnet_for_ip(ip, network)
            if s and s["zone"] not in zones:
                zones.append(s["zone"])
        return zones or ["any"]

    def network_cidrs(self, network: str) -> tuple[list[str], list[str]]:
        """(subnet CIDRs, zones) of a network: the scope of a rule without targets."""
        lits: list[str] = []
        zones: list[str] = []
        for sl in self.networks.get(network, {}).get("subnets") or []:
            s = self.subnets.get(sl)
            if not s:
                continue
            lits.extend(c for c in s["cidrs"] if c not in lits)
            if s["zone"] not in zones:
                zones.append(s["zone"])
        return lits, (zones or ["any"])

    def network_scope(self, network: str, owner: str = "network") -> tuple[list[str], list[str]]:
        """The scope as a rule side: the subnets' address objects, zones."""
        lits, zones = self.network_cidrs(network)
        return ([literal_ref(c, owner, self.synth) for c in lits] or ["any"]), zones

    def group(self, name: str, members: list[tuple[str, str]], kind: str, ref: str) -> str:
        g = self.groups_used.setdefault(name, {"members": [], "kind": kind, "ref": ref})
        for m in members:
            if m not in g["members"]:
                g["members"].append(m)
        return name

    def secure_tag_name(self, tv: str) -> str:
        ns = self.stag_names.get(tv) or ""
        if ns:
            parts = ns.split("/")
            return "-".join(parts[-2:]) if len(parts) >= 2 else ns
        return tv.replace("/", "-")


def _merge_zones(acc: list[str], more: list[str]) -> list[str]:
    if "any" in acc or "any" in more:
        return ["any"]
    for z in more:
        if z not in acc:
            acc.append(z)
    return acc


def _targets(net: _Net, rule: dict, network: str, owner: str) -> tuple[list[str], list[str]]:
    """The instances a rule applies to: (literals or group names, zones).
    No target means every instance in the network."""
    out: list[str] = []
    zones: list[str] = []
    for t in rule.get("targetTags") or []:
        members = [m for m in net.tag_members.get(t, []) if (net.subnets.get(m[1]) or {}).get("network", network) == network]
        out.append(net.group(t, members, "tag", owner))
        zones = _merge_zones(zones, net.zones_of_members(members, network)) if members else zones
    for e in rule.get("targetServiceAccounts") or []:
        members = net.sa_members.get(e, [])
        out.append(net.group(_sa_group_name(e), members, "service_account", owner))
        zones = _merge_zones(zones, net.zones_of_members(members, network)) if members else zones
    for st in rule.get("targetSecureTags") or []:
        tv = st.get("name") if isinstance(st, dict) else str(st)
        members = net.stag_members.get(tv or "", [])
        out.append(net.group(net.secure_tag_name(tv or ""), members, "secure_tag", owner))
        zones = _merge_zones(zones, net.zones_of_members(members, network)) if members else zones
    if not out:
        return net.network_scope(network, owner)
    return out, (zones or ["any"])


def _far_side(net: _Net, ranges: list[str], tags: list[str], sas: list[str], stags: list, agroups: list[str],
              fqdns: list[str], unresolvable: list[str], owner: str) -> tuple[list[str], list[str], bool]:
    """The other side of a rule: (literals, group names and FQDN objects;
    zones; whether the side only consisted of matches no target can hold)."""
    out: list[str] = []
    zones: list[str] = []
    toks: set[str] = set()
    for r in ranges or []:
        r = str(r).strip()
        if not r:
            continue
        if _any_token(r):
            toks.add(_any_token(r)[0])
            continue
        n = _cidr(r)
        if n is None:
            net.drop("address_unresolved", f"{owner}:{r}")
            continue
        lit = str(n) if "/" in r else _host_cidr(r)
        name = literal_ref(lit, owner, net.synth)
        if name not in out:
            out.append(name)
        zones = _merge_zones(zones, net.zones_for_prefix(lit))
    for t in tags or []:
        members = net.tag_members.get(t, [])
        out.append(net.group(t, members, "tag", owner))
        zones = _merge_zones(zones, net.zones_of_members(members)) if members else _merge_zones(zones, ["any"])
    for e in sas or []:
        members = net.sa_members.get(e, [])
        out.append(net.group(_sa_group_name(e), members, "service_account", owner))
        zones = _merge_zones(zones, net.zones_of_members(members)) if members else _merge_zones(zones, ["any"])
    for st in stags or []:
        tv = st.get("name") if isinstance(st, dict) else str(st)
        members = net.stag_members.get(tv or "", [])
        out.append(net.group(net.secure_tag_name(tv or ""), members, "secure_tag", owner))
        zones = _merge_zones(zones, net.zones_of_members(members)) if members else _merge_zones(zones, ["any"])
    for ag in agroups or []:
        g = net.addr_groups.get(ag)
        if g is None:
            name = _base(ag)
            net.group(name, [], "address_group", owner)
            net.drop("address_group_unresolved", f"{owner}:{ag}")
            zones = _merge_zones(zones, ["any"])
        else:
            name = net.group(g["name"], [(c, "") for c in g["cidrs"]], "address_group", owner)
            for c in g["cidrs"]:
                zones = _merge_zones(zones, net.zones_for_prefix(c))
        if name not in out:
            out.append(name)
    for host in fqdns or []:
        host = str(host).strip().rstrip(".")
        if not host:
            continue
        name = f"fqdn-{host}"
        net.fqdns[name] = host
        if name not in out:
            out.append(name)
        zones = _merge_zones(zones, ["any"])
    out, zones = _side_with_tokens(out, zones, toks)
    if not out:
        if unresolvable:
            return ["any"], ["any"], True
        return ["any"], ["any"], False
    return out, zones, False


def _rule(name, seq, action, src, src_zones, dst, dst_zones, services, description, disabled, raw_extras, dropped,
          negate_destination=0) -> dict:
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
        "negate_destination": negate_destination,
        "negate_service":     0,
        "schedule":       None,
        "source_identities": None,
        "raw_extras":     raw_extras,
        "dropped_inputs": dropped,
    }


def _legacy_rule(net: _Net, fw: dict, network: str, seq: int) -> dict | None:
    name = fw.get("name") or f"firewall-{seq}"
    direction = str(fw.get("direction") or "INGRESS").upper()
    allowed, denied = fw.get("allowed") or [], fw.get("denied") or []
    action = "deny" if denied and not allowed else "allow"
    services = _service_literals(denied if action == "deny" else allowed, name, net)
    raw_extras = {"gcp_kind": "firewall", "gcp_network": network, "gcp_priority": fw.get("priority", 1000),
                  "gcp_direction": direction, "gcp_logging": bool((fw.get("logConfig") or {}).get("enable")),
                  "gcp_self_link": fw.get("selfLink")}
    scope, scope_zones = _targets(net, fw, network, name)
    if direction == "INGRESS":
        far, far_zones, _ = _far_side(net, fw.get("sourceRanges") or [], fw.get("sourceTags") or [],
                                      fw.get("sourceServiceAccounts") or [], [], [], [], [], name)
        if not (fw.get("sourceRanges") or fw.get("sourceTags") or fw.get("sourceServiceAccounts")):
            far, far_zones = ["any"], ["any"]
        elif far == ["any"] and fw.get("sourceRanges") and all(":" in str(r) for r in fw["sourceRanges"]) \
                and not (fw.get("sourceTags") or fw.get("sourceServiceAccounts")):
            net.drop("rule_remote_empty", name)
            return None
        rule = _rule(name, seq, action, far, far_zones, scope, scope_zones, services,
                     (fw.get("description") or "").strip(), 1 if fw.get("disabled") else 0, raw_extras, [])
    else:
        far, far_zones, _ = _far_side(net, fw.get("destinationRanges") or [], [], [], [], [], [], [], name)
        if not fw.get("destinationRanges"):
            far, far_zones = ["any"], ["any"]
        elif far == ["any"] and all(":" in str(r) for r in fw["destinationRanges"]):
            net.drop("rule_remote_empty", name)
            return None
        rule = _rule(name, seq, action, scope, scope_zones, far, far_zones, services,
                     (fw.get("description") or "").strip(), 1 if fw.get("disabled") else 0, raw_extras, [])
    return rule


def _policy_rule(net: _Net, pol_name: str, kind: str, r: dict, network: str, seq: int) -> dict:
    prio = r.get("priority")
    direction = str(r.get("direction") or "INGRESS").upper()
    m = r.get("match") or {}
    is_default = int(prio or 0) >= _POLICY_DEFAULT_PRIORITY
    name = f"{pol_name}-{prio}"
    if is_default:
        v6 = any(":" in str(x) for x in (m.get("srcIpRanges") or []) + (m.get("destIpRanges") or []))
        name = f"{pol_name}-default-{'in' if direction == 'INGRESS' else 'out'}{'-ipv6' if v6 else ''}"
    gcp_action = str(r.get("action") or "allow").lower()
    raw_extras = {"gcp_kind": kind, "gcp_policy": pol_name, "gcp_network": network, "gcp_priority": prio,
                  "gcp_direction": direction, "gcp_action": gcp_action,
                  "gcp_logging": bool(r.get("enableLogging")), "gcp_rule_name": r.get("ruleName")}
    dropped: list[str] = []
    notes: list[str] = []
    disabled = 1 if r.get("disabled") else 0
    # per-rule declarations go into dropped_inputs ONLY: the import route
    # aggregates those by rule name and adds the object-level drops dict on
    # top, so a field in both would count twice
    if gcp_action == "apply_security_profile_group":
        action = "allow"
        dropped.append("security_profile_group")
        raw_extras["gcp_security_profile_group"] = r.get("securityProfileGroup")
        notes.append("[layer 7 inspection by a security profile group is not migrated, the rule allows]")
    elif gcp_action == "goto_next":
        action = "allow"
        disabled = 1
        dropped.append("action_goto_next")
        notes.append("[goto_next decides nothing, imported disabled]")
    else:
        action = "deny" if gcp_action == "deny" else "allow"
    unresolvable: list[str] = []
    for key in ("srcRegionCodes", "destRegionCodes", "srcThreatIntelligences", "destThreatIntelligences"):
        if m.get(key):
            unresolvable.append(key)
            raw_extras[f"gcp_{key}"] = m[key]
    services = _service_literals(m.get("layer4Configs") or [], name, net)
    scope, scope_zones = _targets(net, r, network, name)
    if direction == "INGRESS":
        far, far_zones, only_unresolvable = _far_side(
            net, m.get("srcIpRanges") or [], [], [], m.get("srcSecureTags") or [], m.get("srcAddressGroups") or [],
            m.get("srcFqdns") or [], unresolvable, name)
        src, src_zones, dst, dst_zones = far, far_zones, scope, scope_zones
    else:
        far, far_zones, only_unresolvable = _far_side(
            net, m.get("destIpRanges") or [], [], [], [], m.get("destAddressGroups") or [],
            m.get("destFqdns") or [], unresolvable, name)
        src, src_zones, dst, dst_zones = scope, scope_zones, far, far_zones
    if only_unresolvable:
        disabled = 1
        dropped.append("match_unresolved")
        notes.append(f"[not imported: the rule matches only on {', '.join(unresolvable)}, which no target holds]")
    elif unresolvable:
        dropped.append("match_narrowed")
        notes.append(f"[{', '.join(unresolvable)} dropped from the match, the rule is wider than the source]")
    description = " ".join([x for x in [(r.get("description") or "").strip()] + notes if x])
    rule = _rule(name, seq, action, src, src_zones, dst, dst_zones, services, description, disabled, raw_extras, dropped)
    if is_default:
        rule["default_rule_kind"] = "gcp-policy-default"
    return rule


def _parse_rules(net: _Net) -> list[dict]:
    rules: list[dict] = []
    seq = 0
    b = net.bundle
    hier = b.get("firewallPolicies") or []
    policies = b.get("networkFirewallPolicies") or []
    fws = b.get("firewalls") or []

    def attached(pol: dict, network: str) -> bool:
        for a in pol.get("associations") or []:
            if _base(a.get("attachmentTarget")) == network:
                return True
        return False

    for network in sorted(net.networks):
        n = net.networks[network]
        blocks: list[tuple[str, list[tuple[str, dict]]]] = []
        hier_rules = [(pol.get("displayName") or pol.get("name") or "hierarchical", r)
                      for pol in hier if not pol.get("networks") or network in pol["networks"]
                      for r in sorted(pol.get("rules") or [], key=lambda x: int(x.get("priority") or 0))]
        blocks.append(("hierarchical_policy", hier_rules))
        legacy = sorted((f for f in fws if _base(f.get("network")) == network),
                        key=lambda f: (int(f.get("priority") or 1000), f.get("name") or ""))
        glob = [(pol.get("name") or "policy", r) for pol in policies if not pol.get("region") and attached(pol, network)
                for r in sorted(pol.get("rules") or [], key=lambda x: int(x.get("priority") or 0))]
        regional = [(pol.get("name") or "policy", r) for pol in sorted(policies, key=lambda p: p.get("region") or "")
                    if pol.get("region") and attached(pol, network)
                    for r in sorted(pol.get("rules") or [], key=lambda x: int(x.get("priority") or 0))]
        if n["order"] == "BEFORE_CLASSIC_FIREWALL":
            blocks += [("network_policy", glob), ("regional_policy", regional), ("firewall", [("", f) for f in legacy])]
        else:
            blocks += [("firewall", [("", f) for f in legacy]), ("network_policy", glob), ("regional_policy", regional)]
        for kind, entries in blocks:
            for pol_name, r in entries:
                if kind == "firewall":
                    rule = _legacy_rule(net, r, network, seq)
                else:
                    rule = _policy_rule(net, pol_name, kind, r, network, seq)
                if rule is None:
                    continue
                rules.append(rule)
                seq += 1
    # implied rules: egress allowed to anything outside the subnets, ingress denied
    all_lits: list[str] = []
    all_zones: list[str] = []
    for s in net.subnets.values():
        all_lits.extend(c for c in s["cidrs"] if c not in all_lits)
        if s["zone"] not in all_zones:
            all_zones.append(s["zone"])
    all_names = [literal_ref(c, "implied-allow-egress", net.synth) for c in all_lits]
    egress = _rule("implied-allow-egress", seq, "allow", all_names or ["any"], all_zones or ["any"],
                   all_names or ["any"], ["any"], ["any"],
                   "Implied allow egress: from the subnets to anything outside them. Inside the VPC the "
                   "destination's ingress rules decide, so the destination is negated", 0,
                   {"gcp_kind": "implied", "gcp_direction": "EGRESS"}, [], negate_destination=1 if all_lits else 0)
    egress["default_rule_kind"] = "gcp-implied-allow-egress"
    rules.append(egress)
    seq += 1
    deny = _rule("implied-deny-ingress", seq, "deny", ["any"], ["any"], ["any"], ["any"], ["any"],
                 "Implied deny ingress: everything no rule allowed", 0,
                 {"gcp_kind": "implied", "gcp_direction": "INGRESS"}, [])
    deny["default_rule_kind"] = "gcp-implied-deny-ingress"
    rules.append(deny)
    return rules


def _parse_objects(net: _Net) -> list[dict]:
    objects: list[dict] = []
    synth = net.synth        # one registry: rule literals and members share objects
    # every network tag an instance carries is a group, even unreferenced
    for t, members in net.tag_members.items():
        net.group(t, members, "tag", "instances")
    kinds = {"tag": "network tag", "service_account": "service account", "secure_tag": "secure tag",
             "address_group": "address group"}
    for name in sorted(net.groups_used):
        g = net.groups_used[name]
        if g["kind"] == "address_group":
            cidrs = [ip for ip, _ in g["members"]]
        else:
            ips = sorted({ip for ip, _ in g["members"]}, key=lambda ip: ipaddress.IPv4Address(ip))
            cidrs = [f"{ip}/32" for ip in ips]
        if not cidrs:
            net.drop("membership_empty", name)
        objects.append({"obj_type": "address_group", "name": name, "value": {
            "type": "static", "members": member_objects(cidrs, name, synth),
            "description": f"GCP {kinds.get(g['kind'], g['kind'])}, {len(cidrs)} member(s) resolved at import",
        }})
    for name in sorted(net.fqdns):
        objects.append({"obj_type": "address", "name": name,
                        "value": {"type": "fqdn", "value": net.fqdns[name], "description": "GCP FQDN match"}})
    return objects + list(synth.values()) + list(net.synth_svc.values())


def _parse_network(net: _Net) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """(interfaces, zones, routes, vrfs): every VPC network is a VR."""
    interfaces: list[dict] = []
    zones: list[dict] = []
    vrfs: list[dict] = []
    routes: list[dict] = []
    members_by_vr: dict[str, list[str]] = {}
    for s in sorted(net.subnets.values(), key=lambda x: (x["network"], x["zone"])):
        interfaces.append({
            "name":         s["zone"],
            "zone":         s["zone"],
            "description":  f"{s['network']} {', '.join(s['cidrs'])} {s['region']}".strip(),
            "ips":          [],
            "type":         "physical",
            "vr_name":      s["network"],
            "role":         None,
            "dhcp_enabled": False,
            "enabled":      True,
        })
        zones.append({"name": s["zone"], "members": [s["zone"]],
                      "properties": {"gcp_network": s["network"], "gcp_subnetwork": s["link"],
                                     "gcp_cidrs": s["cidrs"], "gcp_region": s["region"]}})
        members_by_vr.setdefault(s["network"], []).append(s["zone"])
    for name in sorted(net.networks):
        if name != "default":
            vrfs.append({"name": name, "interface_members": members_by_vr.get(name, []),
                         "properties": {"interface_members": members_by_vr.get(name, []),
                                        "gcp_enforcement_order": net.networks[name]["order"]}})
    for r in net.bundle.get("routes") or []:
        network = _base(r.get("network"))
        dest = str(r.get("destRange") or "").strip()
        rname = r.get("name") or dest
        if r.get("nextHopNetwork"):
            continue        # the subnet routes, implied by the subnets
        n = _cidr(dest)
        if n is None:
            net.drop("route_unresolved", f"{rname}:{dest}")
            continue
        hop_ip = str(r.get("nextHopIp") or "").strip()
        if not hop_ip and r.get("nextHopInstance"):
            inst = net.instances_by_link.get(r["nextHopInstance"]) or next(
                (i for l, i in net.instances_by_link.items() if _base(l) == _base(r["nextHopInstance"])), None)
            for ni in (inst or {}).get("networkInterfaces") or []:
                if _base(ni.get("network")) == network and ni.get("networkIP"):
                    hop_ip = ni["networkIP"]
                    break
        if not hop_ip:
            hop = (r.get("nextHopGateway") or r.get("nextHopIlb") or r.get("nextHopVpnTunnel")
                   or r.get("nextHopPeering") or r.get("nextHopInstance") or r.get("nextHopHub") or "?")
            net.drop("route_hop_type", f"{rname}:{dest} via {_base(hop)}")
            continue
        if r.get("tags"):
            net.drop("route_tagged", f"{rname}:{dest} applies to tags {','.join(r['tags'])}")
        egress = net.subnet_for_ip(hop_ip, network)
        routes.append({
            "prefix":   str(n.network_address),
            "plen":     n.prefixlen,
            "iface":    egress["zone"] if egress else None,
            "next_hop": hop_ip,
            "vr":       network or "default",
        })
    return interfaces, zones, routes, vrfs


def parse_bundle(bundle: dict) -> dict:
    """The whole project in one pass: rules, objects, drops and the network
    strand. Import and collect each take their half."""
    net = _Net(bundle)
    rules = _parse_rules(net)
    for r in rules:
        # a rule side holds service names, never literals (see _common.service_ref)
        r["services"] = [service_ref(s, net.synth_svc) for s in (r.get("services") or ["any"])]
    objects = _parse_objects(net)
    interfaces, zones, routes, vrfs = _parse_network(net)
    warnings: list[str] = list(bundle.get("warnings") or [])
    if net.drops:
        warnings.append("drops: " + ", ".join(f"{k}({len(v)})" for k, v in net.drops.items()))
    project = str(bundle.get("project") or "")
    return {
        "rules": rules, "nat_rules": [], "objects": objects, "drops": net.drops,
        "errors": [], "hostname": f"gcp-{project}" if project else "gcp",
        "interfaces": interfaces, "zones": zones, "routes": routes, "vrfs": vrfs,
        "warnings": warnings,
    }


# ── Entry points (registered into main by the package) ─────────────────

def run_import(device: dict) -> dict:
    parsed = parse_bundle(bundle_for_device(device))
    out = {k: parsed[k] for k in ("rules", "nat_rules", "objects", "drops", "errors", "hostname")}
    if device.get("host_name"):
        out["hostname"] = device["host_name"]
    return out


def collect_network(device: dict) -> dict:
    parsed = parse_bundle(bundle_for_device(device))
    return {k: parsed[k] for k in ("interfaces", "routes", "vrfs", "zones", "errors", "warnings")}


def validate_bundle(raw: str) -> tuple[dict | None, str | None]:
    """An uploaded bundle: JSON with at least the network, subnetwork and
    firewall lists, keyed like the REST resources."""
    try:
        data = json.loads(raw)
    except Exception as exc:
        return None, f"not JSON: {exc}"
    if not isinstance(data, dict):
        return None, "the bundle must be a JSON object keyed by resource type"
    missing = [t for t in ("networks", "subnetworks", "firewalls") if t not in data]
    if missing:
        return None, "bundle lacks " + ", ".join(missing)
    for t in BUNDLE_KEYS:
        if t in data and not isinstance(data[t], list):
            return None, f"{t} must be a list"
    if "instanceTags" in data and not isinstance(data["instanceTags"], dict):
        return None, "instanceTags must be an object keyed by instance"
    return data, None
