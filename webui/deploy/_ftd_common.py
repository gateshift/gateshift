# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
Shared Cisco FTD (FDM REST API) helpers + parsers.

FTD is a SOURCE-ONLY platform (platform key 'firepower'): standalone /
FDM-managed boxes are imported via the on-box FDM REST API. There is no
push target - FMC-managed estates are out of scope (EE backlog), and an
FTD registered to an FMC has its FDM API permanently disabled anyway.

Auth: OAuth2 password grant against POST /api/fdm/latest/fdm/token with
the FDM admin credentials - FDM has no static API keys. The username
lives in device.config.ftd.username (default 'admin'), the password in
fw_devices.api_key (the platform's API-credential-secret column).

Envelope: every list endpoint returns {"items": [...], "paging":
{"count", "offset", "limit", ...}} - api_get_items() pages via
limit/offset until exhausted. Rule/NAT references are typed object refs
({id, type, name}) with the name INLINE, so no object-dictionary merge
is needed (unlike CP rulebases).

Shapes verified live against FTDv 7.6.4-69 (2026-08-06).
"""

from __future__ import annotations

import ipaddress
import json

import requests

# Mirrors _CONNECT_TIMEOUT in _forti_common.py / checkpoint.py / panw.py.
_CONNECT_TIMEOUT = 5

_API_ROOT = "/api/fdm/latest"


# ── REST API ─────────────────────────────────────────────────────

def base_url_for(device: dict) -> str:
    host = device.get("mgmt_ip") or device.get("host_name")
    port = device.get("mgmt_port") or 443
    return f"https://{host}:{port}"


def username_for(device: dict) -> str:
    """FDM admin username from device.config.ftd.username (default 'admin')."""
    try:
        cfg = json.loads(device.get("config") or "{}")
        return (cfg.get("ftd") or {}).get("username") or "admin"
    except Exception:
        return "admin"


class FtdAuthError(Exception):
    """Raised when the token grant is rejected (wrong credentials) or the
    box is unreachable. The import route maps this onto its generic
    _ImportAuthError so the banner stays honest instead of erroring per
    endpoint."""


def get_token(base_url: str, username: str, password: str) -> str:
    """OAuth2 password grant. FDM answers 400 (not 401) on a wrong
    password - both spellings mean bad credentials here."""
    try:
        resp = requests.post(
            f"{base_url}{_API_ROOT}/fdm/token",
            json={"grant_type": "password",
                  "username": username, "password": password},
            verify=False, timeout=(_CONNECT_TIMEOUT, 30))
    except requests.RequestException as exc:
        raise FtdAuthError(f"device unreachable: {exc}")
    if resp.status_code in (400, 401, 403):
        raise FtdAuthError(
            f"FDM login rejected (HTTP {resp.status_code}) - check the "
            "admin username/password")
    resp.raise_for_status()
    token = (resp.json() or {}).get("access_token")
    if not token:
        raise FtdAuthError("FDM token response carried no access_token")
    return token


def api_get_items(base_url: str, token: str, path: str,
                  limit: int = 1000) -> list[dict]:
    """GET a list endpoint, following limit/offset paging until the
    items are exhausted. Returns the concatenated items list."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    items: list[dict] = []
    offset = 0
    while True:
        sep = "&" if "?" in path else "?"
        url = f"{base_url}{_API_ROOT}{path}{sep}limit={limit}&offset={offset}"
        resp = requests.get(url, headers=headers, verify=False,
                            timeout=(_CONNECT_TIMEOUT, 30))
        resp.raise_for_status()
        payload = resp.json() or {}
        page = payload.get("items") or []
        items.extend(page)
        paging = payload.get("paging") or {}
        count = paging.get("count")
        if not page or count is None or offset + len(page) >= count:
            return items
        offset += len(page)


def fetch_hostname(base_url: str, token: str) -> str | None:
    try:
        items = api_get_items(base_url, token,
                              "/devicesettings/default/devicehostnames")
        if items:
            return items[0].get("hostname") or None
    except Exception:
        return None
    return None


# ── Reference helpers ────────────────────────────────────────────

# FDM's any-objects: system-defined networks that ARE the any-semantics.
# Skipped at object import; a rule ref collapses to 'any' (passing the
# literal name through would dangle on any cross-vendor render).
_ANY_NETWORKS = {"any-ipv4", "any-ipv6"}


def ref_names(items) -> list[str]:
    """Extract 'name' from a typed-ref list [{id, type, name}, ...]."""
    if not items:
        return []
    return [x.get("name", "") for x in items if isinstance(x, dict) and x.get("name")]


def any_net_names(items) -> list[str]:
    """ref_names + any-normalization for network refs: an empty list or a
    list containing an any-object collapses to ['any']."""
    names = ref_names(items)
    if not names:
        return ["any"]
    if any(n in _ANY_NETWORKS for n in names):
        return ["any"]
    return names


def _ref_name(item) -> str | None:
    """Single typed ref → name (None when absent)."""
    if isinstance(item, dict):
        return item.get("name") or None
    return None


# ── Object parsers ───────────────────────────────────────────────

def parse_networks(items: list[dict]) -> tuple[list[dict], dict[str, list[str]]]:
    """FDM /object/networks → address objects.

    subType HOST/NETWORK → ip-netmask, RANGE → ip-range, FQDN → fqdn.
    IPv6 values are dropped (platform-wide V1 limit); the any-objects are
    skipped silently (mapped to 'any' at the rule refs).
    """
    objects: list[dict] = []
    drops: dict[str, list[str]] = {}
    for e in items or []:
        name = e.get("name") or ""
        if not name or name in _ANY_NETWORKS:
            continue
        value = (e.get("value") or "").strip()
        sub = (e.get("subType") or "").upper()
        if ":" in value:
            drops.setdefault("address_ipv6", []).append(name)
            continue
        desc = e.get("description") or ""
        if sub in ("HOST", "NETWORK"):
            val = {"type": "ip-netmask", "value": value, "description": desc}
        elif sub == "RANGE":
            val = {"type": "ip-range", "value": value, "description": desc}
        elif sub == "FQDN":
            val = {"type": "fqdn", "value": value, "description": desc}
        else:
            drops.setdefault("address_unsupported", []).append(f"{name}({sub})")
            continue
        objects.append({"obj_type": "address", "name": name, "value": val})
    return objects, drops


def parse_network_groups(items: list[dict]) -> list[dict]:
    """FDM /object/networkgroups → address_group objects. Members are
    typed refs (objects or nested groups) - names retained verbatim."""
    objects: list[dict] = []
    for e in items or []:
        name = e.get("name") or ""
        if not name:
            continue
        objects.append({"obj_type": "address_group", "name": name, "value": {
            "type": "static",
            "members": ref_names(e.get("objects")),
            "description": e.get("description") or "",
        }})
    return objects


def parse_ports(items: list[dict], protocol: str) -> list[dict]:
    """FDM /object/tcpports | /object/udpports → service objects.

    'port' is a single port or a 'low-high' range. System-defined entries
    (FDM ships ~30) are imported too - rules reference them by name, and
    cross-vendor pushes materialize them like any custom object."""
    objects: list[dict] = []
    for e in items or []:
        name = e.get("name") or ""
        port = str(e.get("port") or "").strip()
        if not name or not port:
            continue
        val = {"protocol": protocol, "port": port,
               "description": e.get("description") or ""}
        if e.get("isSystemDefined"):
            val["predefined"] = True
        objects.append({"obj_type": "service", "name": name, "value": val})
    return objects


# FDM spells icmpv4Type as a STRING enum; the canonical service vocab (and
# every cross-vendor renderer) expects the numeric RFC 792 type. 'ANY' or an
# unknown spelling → no icmp_type (matches any).
_ICMP4_TYPE_NUM = {
    "ECHO_REPLY": 0, "DESTINATION_UNREACHABLE": 3, "SOURCE_QUENCH": 4,
    "REDIRECT_MESSAGE": 5, "ALTERNATE_HOST_ADDRESS": 6, "ECHO_REQUEST": 8,
    "ROUTER_ADVERTISEMENT": 9, "ROUTER_SOLICITATION": 10, "TIME_EXCEEDED": 11,
    "PARAMETER_PROBLEM": 12, "TIMESTAMP": 13, "TIMESTAMP_REPLY": 14,
    "INFORMATION_REQUEST": 15, "INFORMATION_REPLY": 16,
    "ADDRESS_MASK_REQUEST": 17, "ADDRESS_MASK_REPLY": 18, "TRACEROUTE": 30,
}


def parse_icmp_ports(items: list[dict]) -> list[dict]:
    """FDM /object/icmpv4ports → icmp service objects. String type-enums
    normalized to numeric RFC 792 types (live-verified: a passed-through
    'ECHO_REQUEST' crashes the Forti render's int())."""
    objects: list[dict] = []
    for e in items or []:
        name = e.get("name") or ""
        if not name:
            continue
        val: dict = {"protocol": "icmp",
                     "description": e.get("description") or ""}
        t = _ICMP4_TYPE_NUM.get(str(e.get("icmpv4Type") or "").upper())
        if t is not None:
            val["icmp_type"] = t
        if e.get("icmpv4Code") not in (None, ""):
            val["icmp_code"] = e.get("icmpv4Code")
        if e.get("isSystemDefined"):
            val["predefined"] = True
        objects.append({"obj_type": "service", "name": name, "value": val})
    return objects


def parse_port_groups(items: list[dict]) -> list[dict]:
    """FDM /object/portgroups → service_group objects."""
    objects: list[dict] = []
    for e in items or []:
        name = e.get("name") or ""
        if not name:
            continue
        objects.append({"obj_type": "service_group", "name": name, "value": {
            "members": ref_names(e.get("objects")),
            "description": e.get("description") or "",
        }})
    return objects


# ── Access rules ─────────────────────────────────────────────────

def parse_access_rules(items: list[dict]) -> tuple[list[dict], dict[str, list[str]]]:
    """FDM access rules → agnostic rule dicts (same shape as the PA/CP/
    Forti importers).

    ruleAction PERMIT→allow, DENY→deny, TRUST→allow (bypass-inspection
    intent kept in raw_extras.ftd_trust + drop-logged). FDM rules carry
    no disabled state (the UI has none) → disabled=0. Source-port
    matches, app/URL/user conditions and intrusion/file policies survive
    in raw_extras + drop channels - never silently.
    """
    rules: list[dict] = []
    drops: dict[str, list[str]] = {}
    for i, e in enumerate(items or []):
        name = e.get("name") or f"rule-{e.get('ruleId', i)}"
        raw_extras: dict = {}
        dropped: list[str] = []

        action = (e.get("ruleAction") or "").upper()
        if action == "PERMIT":
            act = "allow"
        elif action == "TRUST":
            act = "allow"
            raw_extras["ftd_trust"] = True
            dropped.append("ftd_trust_action")
        else:
            act = "deny"

        services = ref_names(e.get("destinationPorts")) or ["any"]
        src_ports = ref_names(e.get("sourcePorts"))
        if src_ports:
            raw_extras["ftd_source_ports"] = src_ports
            dropped.append("source_ports")

        log_action = (e.get("eventLogAction") or "").upper()
        if log_action and log_action != "LOG_NONE":
            raw_extras["log_setting"] = log_action.lower()
            dropped.append("log_setting")

        if e.get("embeddedAppFilter"):
            raw_extras["ftd_app_filter"] = True
            dropped.append("application_ctrl")
        if e.get("urlFilter"):
            raw_extras["ftd_url_filter"] = True
            dropped.append("url_filter")
        for pol_field, extras_key in (("intrusionPolicy", "intrusion_policy"),
                                      ("filePolicy", "file_policy")):
            ref = _ref_name(e.get(pol_field))
            if ref:
                raw_extras.setdefault("security_profile_individual", {})[extras_key] = ref
                if "security_profile_individual" not in dropped:
                    dropped.append("security_profile_individual")

        time_ranges = ref_names(e.get("timeRangeObjects"))
        if time_ranges:
            raw_extras["schedule"] = time_ranges[0]
            dropped.append("schedule")

        identities = [{"name": n, "kind": "user"}
                      for n in ref_names(e.get("users"))]
        if e.get("identitySources"):
            drops.setdefault("identity_sources", []).append(name)

        rules.append({
            "rule_name":      name,
            "seq_num":        i,
            "action":         act,
            "src_zones":      ref_names(e.get("sourceZones")) or ["any"],
            "dst_zones":      ref_names(e.get("destinationZones")) or ["any"],
            "sources":        any_net_names(e.get("sourceNetworks")),
            "destinations":   any_net_names(e.get("destinationNetworks")),
            "services":       services,
            "applications":   [],
            "description":    "",
            "disabled":       0,
            "tags":           [],
            "negate_source":      0,
            "negate_destination": 0,
            "negate_service":     0,
            "schedule":       None,
            "source_identities": identities or None,
            "raw_extras":     raw_extras or None,
            "dropped_inputs": dropped,
        })
    return rules, drops


# ── NAT ──────────────────────────────────────────────────────────

def _nat_type_for(e: dict) -> str:
    """natType DYNAMIC → snat; STATIC with only a translated destination →
    dnat; STATIC otherwise → static (bidirectional)."""
    if (e.get("natType") or "").upper() == "DYNAMIC":
        return "snat"
    if e.get("translatedDestination") and not e.get("translatedSource"):
        return "dnat"
    return "static"


def parse_manual_nat_rules(items: list[dict], position_base: int = 0) -> list[dict]:
    """FDM manual NAT rules (one Before/After container's rules) →
    fw_nat_rules dicts. sourceInterface/destinationInterface are
    INTERFACE refs on FDM (NAT scopes by interface, not by zone - live
    422-verified) → their logical names land in src/dst zones, the same
    interface-as-scope mapping the Forti central-snat parser uses."""
    rules: list[dict] = []
    for i, e in enumerate(items or []):
        name = e.get("name") or f"manual-nat-{position_base + i}"
        src_zone = _ref_name(e.get("sourceInterface"))
        dst_zone = _ref_name(e.get("destinationInterface"))

        if e.get("interfaceInTranslatedSource"):
            trans_src, trans_type = None, "interface-address"
        else:
            trans_src = _ref_name(e.get("translatedSource"))
            trans_type = ("dynamic-ip-and-port"
                          if (e.get("natType") or "").upper() == "DYNAMIC"
                          else "static-ip") if trans_src else "none"

        orig_svc = _ref_name(e.get("originalDestinationPort")) \
            or _ref_name(e.get("originalSourcePort"))
        rules.append({
            "position":        position_base + i,
            "name":            name,
            "nat_type":        _nat_type_for(e),
            "disabled":        0 if e.get("enabled", True) else 1,
            "src_zones":       [src_zone] if src_zone else ["any"],
            "dst_zones":       [dst_zone] if dst_zone else ["any"],
            "interface_name":  None,
            "orig_src":        [_ref_name(e.get("originalSource")) or "any"],
            "orig_dst":        [_ref_name(e.get("originalDestination")) or "any"],
            "orig_service":    [orig_svc or "any"],
            "trans_src":       trans_src,
            "trans_src_type":  trans_type,
            "trans_dst":       _ref_name(e.get("translatedDestination")),
            "trans_dst_port":  _ref_name(e.get("translatedDestinationPort")),
            "description":     e.get("description") or "",
            "negate_source":      0,
            "negate_destination": 0,
            "negate_service":     0,
        })
    return rules


def parse_object_nat_rules(items: list[dict], position_base: int = 0) -> list[dict]:
    """FDM object (auto) NAT rules → fw_nat_rules dicts. The object-NAT
    model hangs the rule off ONE network object (originalNetwork); FDM
    inserts these between the Before/After manual containers - mirrored
    via position_base."""
    rules: list[dict] = []
    for i, e in enumerate(items or []):
        name = e.get("name") or f"object-nat-{position_base + i}"
        src_zone = _ref_name(e.get("sourceInterface"))
        dst_zone = _ref_name(e.get("destinationInterface"))
        orig = _ref_name(e.get("originalNetwork")) or _ref_name(e.get("originalSource"))

        if e.get("interfaceInTranslatedNetwork") or e.get("interfaceInTranslatedSource"):
            trans_src, trans_type = None, "interface-address"
        else:
            trans_src = (_ref_name(e.get("translatedNetwork"))
                         or _ref_name(e.get("translatedSource")))
            trans_type = ("dynamic-ip-and-port"
                          if (e.get("natType") or "").upper() == "DYNAMIC"
                          else "static-ip") if trans_src else "none"

        rules.append({
            "position":        position_base + i,
            "name":            name,
            "nat_type":        "snat" if (e.get("natType") or "").upper() == "DYNAMIC" else "static",
            "disabled":        0 if e.get("enabled", True) else 1,
            "src_zones":       [src_zone] if src_zone else ["any"],
            "dst_zones":       [dst_zone] if dst_zone else ["any"],
            "interface_name":  None,
            "orig_src":        [orig or "any"],
            "orig_dst":        ["any"],
            "orig_service":    ["any"],
            "trans_src":       trans_src,
            "trans_src_type":  trans_type,
            "trans_dst":       None,
            "trans_dst_port":  None,
            "description":     e.get("description") or "",
            "negate_source":      0,
            "negate_destination": 0,
            "negate_service":     0,
        })
    return rules


# ── Network strand (interfaces / zones / routes) ─────────────────

def _netmask_to_prefix(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return None


def _iface_ipv4_cidr(e: dict) -> tuple[str | None, bool]:
    """(host-preserving CIDR or None, dhcp_enabled) from an FDM interface
    entry's ipv4 block."""
    ipv4 = e.get("ipv4") or {}
    if ipv4.get("ipType", "").upper() == "DHCP" or ipv4.get("dhcp"):
        return None, True
    addr = (ipv4.get("ipAddress") or {})
    ip = (addr.get("ipAddress") or "").strip()
    mask = (addr.get("netmask") or "").strip()
    if not ip:
        return None, False
    if "/" in mask:  # FDM tolerates prefix-style netmask input
        prefix = mask.lstrip("/")
        return (f"{ip}/{prefix}", False) if prefix.isdigit() else (None, False)
    prefix = _netmask_to_prefix(mask) if mask else 32
    return (f"{ip}/{prefix}", False) if prefix is not None else (None, False)


def parse_interfaces(items: list[dict],
                     subs_by_parent: dict[str, list[dict]],
                     zone_map: dict[str, str]) -> tuple[list[dict], dict[str, list[str]]]:
    """FDM physical interfaces + their subinterfaces → collector-shaped
    iface dicts. The logical name (nameif, e.g. 'inside') is the identity
    - it's what zones, NAT and routes reference (ASA precedent); the
    hardware name (TenGigabitEthernet0/1) rides along as description
    context. Unnamed (unconfigured) ports are skipped + drop-logged;
    management-only interfaces are skipped (out-of-band, never in
    policy)."""
    interfaces: list[dict] = []
    drops: dict[str, list[str]] = {}

    def _one(e: dict, parent_name: str | None) -> None:
        name = (e.get("name") or "").strip()
        hw = (e.get("hardwareName") or "").strip()
        if not name:
            drops.setdefault("interface_unnamed", []).append(hw or "?")
            return
        if e.get("managementOnly"):
            drops.setdefault("interface_system", []).append(name)
            return
        ip_cidr, dhcp_on = _iface_ipv4_cidr(e)
        desc = (e.get("description") or "").strip()
        if hw and hw != name:
            desc = f"{desc} [{hw}]".strip()
        iface: dict = {
            "name":         name,
            "zone":         zone_map.get(name),
            "description":  desc or None,
            "ips":          [ip_cidr] if ip_cidr else [],
            "type":         "vlan" if parent_name else "physical",
            "vr_name":      "default",   # per-VR membership resolved by the collector
            "role":         None,
            "dhcp_enabled": dhcp_on,
            "enabled":      bool(e.get("enabled", True)),
        }
        if parent_name:
            iface["parent"] = parent_name
            try:
                vid = int(e.get("vlanId") or 0)
                if vid > 0:
                    iface["vlan_tag"] = vid
            except (TypeError, ValueError):
                pass
        interfaces.append(iface)

    for e in items or []:
        _one(e, None)
        parent = (e.get("name") or "").strip()
        for sub in subs_by_parent.get(e.get("id") or "", []):
            _one(sub, parent or (e.get("hardwareName") or "").strip() or None)
    return interfaces, drops


def parse_zones(items: list[dict]) -> tuple[dict[str, str], list[dict]]:
    """FDM /object/securityzones → (iface→zone map, zone-object dicts).
    Zone members are typed interface refs whose name is the logical
    iface name."""
    iface_to_zone: dict[str, str] = {}
    zones: list[dict] = []
    for z in items or []:
        zname = z.get("name") or ""
        if not zname:
            continue
        members = ref_names(z.get("interfaces"))
        for m in members:
            iface_to_zone[m] = zname
        zones.append({
            "name": zname,
            "properties": {
                "ftd_mode": (z.get("mode") or "").lower() or None,
                "ftd_description": (z.get("description") or "").strip() or None,
            },
            "members": members,
        })
    return iface_to_zone, zones


def parse_static_routes(items: list[dict], vr_name: str,
                        networks_by_name: dict[str, str],
                        iface_names: set[str]) -> tuple[list[dict], dict[str, list[str]]]:
    """FDM staticrouteentries (one virtual router's) → route dicts.

    FDM expresses both the destination networks AND the gateway as
    network-object refs - networks_by_name maps object name → literal
    value (CIDR / host IP) for resolution. One FDM entry can carry
    several destination networks → one route row each. IPv6 entries are
    dropped (V1 platform limit)."""
    routes: list[dict] = []
    drops: dict[str, list[str]] = {}
    for e in items or []:
        if (e.get("ipType") or "IPv4").upper() != "IPV4":
            drops.setdefault("route_ipv6", []).append(e.get("name") or "?")
            continue
        gw_ref = _ref_name(e.get("gateway"))
        next_hop = None
        if gw_ref:
            gw_val = networks_by_name.get(gw_ref, gw_ref)
            next_hop = gw_val.split("/")[0] if gw_val else None
        iface_name = _ref_name(e.get("iface"))
        if iface_name and iface_names and iface_name not in iface_names:
            iface_name = None
        for net_ref in ref_names(e.get("networks")) or []:
            val = networks_by_name.get(net_ref, net_ref)
            try:
                net = ipaddress.IPv4Network(val, strict=False)
            except Exception:
                drops.setdefault("route_unresolved", []).append(
                    f"{e.get('name') or '?'}→{net_ref}")
                continue
            routes.append({
                "prefix":   str(net.network_address),
                "plen":     net.prefixlen,
                "ip_from":  int(net.network_address),
                "ip_to":    int(net.broadcast_address),
                "iface":    iface_name,
                "next_hop": next_hop,
                "vr":       vr_name,
            })
    return routes, drops
