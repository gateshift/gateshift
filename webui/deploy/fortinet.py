# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
FortiGate (FortiOS) deploy driver.

Renders config as JSON per FortiOS v2 REST API schema and pushes via
HTTPS Bearer-token auth. No commit step - FortiOS changes are live on
successful POST/PUT/DELETE.

V1 scope: IPv4, single VDOM (from device.config.fortigate.vdom, default
'root'). NAT, IPv6, UTM/security profiles, multi-VDOM are out of scope.
"""

from __future__ import annotations

import base64
import dataclasses
import html
import ipaddress
import json
import logging
import re
import urllib.parse
from typing import Iterator

import requests

from . import _forti_common as _f
from . import integrity as _integ
from .base import (
    DeployDriver,
    DroppedField,
    StepResult,
    error_hint,
    register_driver,
)

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

log = logging.getLogger(__name__)


# ── Push-error explainers ────────────────────────────────────────
# A readable table of (condition → human hint) consulted by the push loop when
# a step fails, instead of inline if/elif chains at the error sites. Each fn
# takes the error `ctx` dict the push builds and returns the hint text (with its
# leading ' - …' separator) when it applies, else ''. base.error_hint() returns
# the first match. ctx fields: phase ('primary' = the initial POST/PUT failed |
# 'retry' = the -5→PUT fallback failed), step (label), errcode, status_code,
# use_put, entry, entry_id, cli_error, captive_physicals.

def _hint_iface_overlap5(ctx: dict) -> str:
    if ctx.get("phase") == "retry" and ctx.get("step") == "Interfaces":
        return (" - for an interface, -5 can mean the IP/subnet overlaps another "
                "interface, not just a name conflict")
    return ""


def _hint_iface_overlap54(ctx: dict) -> str:
    # -54 on an interface CREATE (POST): the new interface's subnet overlaps an
    # interface still on the target. The common cause after renaming a
    # policy-referenced interface: the OLD interface survived the wipe because
    # firewall policies still reference it - a network push deliberately does
    # NOT delete policy-referenced interfaces (see the delete-phase comment) -
    # so it kept its IP and the new interface collides. Forti reports only the
    # opaque "subnets overlap", hiding the real blocker, so name it and point at
    # the fix. cli_error: "Subnets overlap between '<new>' with primary IP of
    # '<blocker>'".
    if (ctx.get("phase") == "primary" and ctx.get("step") == "Interfaces"
            and ctx.get("errcode") == -54 and not ctx.get("use_put")):
        m = re.search(r"primary IP of '([^']+)'", ctx.get("cli_error") or "")
        blocker = m.group(1) if m else None
        who = f"target interface '{blocker}'" if blocker else "an interface still on the target"
        return (f" - {who} holds an overlapping subnet. If you renamed a "
                f"policy-referenced interface, the old one likely survived the "
                f"wipe (a network push won't delete policy-referenced interfaces, "
                f"nor VPN tunnels that policies still reference) - push the "
                f"Policy strand first to clear those rules, or remove them, "
                f"then re-push Network.")
    return ""


def _hint_iface_404(ctx: dict) -> str:
    # A physical-interface PUT that 404s = the name doesn't exist on the target
    # box. FortiGate physical ports are fixed hardware (port1..portN), so a
    # source physical (e.g. PA "ethernet1/X") that wasn't mapped to a real
    # target port has nowhere to land. Spell that out instead of the bare 404.
    if (ctx.get("phase") == "primary" and ctx.get("step") == "Interfaces"
            and ctx.get("use_put") and ctx.get("status_code") == 404):
        return (f" - interface '{ctx.get('entry_id')}' does not exist on the "
                f"FortiGate (physical ports are fixed hardware: port1..portN). "
                f"Map it to a target port in Network > Interfaces before pushing.")
    return ""


def _hint_iface_651_captive(ctx: dict) -> str:
    # -651 on an aggregate POST whose members are still claimed by a target
    # aggregate the delete phase couldn't unwind (captive physicals).
    if (ctx.get("phase") == "primary" and ctx.get("step") == "Interfaces"
            and ctx.get("errcode") == -651 and not ctx.get("use_put")):
        e = ctx.get("entry") or {}
        captive_physicals = ctx.get("captive_physicals") or {}
        members = [m.get("interface-name") for m in (e.get("member") or [])
                   if isinstance(m, dict)]
        captive = [(m, captive_physicals[m]) for m in members
                   if m in captive_physicals]
        if captive:
            captors = sorted({c for _, c in captive})
            phys = sorted({p for p, _ in captive})
            return (f" - likely cause: {', '.join(phys)} still member(s) of target "
                    f"aggregate {', '.join(captors)} (delete soft-failed, check "
                    f"policy references and remove the target aggregate manually)")
    return ""


# firewall/policy fields that reference a UTM/security profile by name.
_FORTI_UTM_POLICY_FIELDS = (
    "av-profile", "webfilter-profile", "dnsfilter-profile",
    "ips-sensor", "application-list", "ssl-ssh-profile",
)


def _hint_utm_not_attachable(ctx: dict) -> str:
    # A policy push -3 whose unparseable value is one of the rule's UTM profile
    # refs: the profile exists in the target catalog but isn't attachable to a
    # firewall policy (e.g. a sniffer/monitor-only profile, indistinguishable
    # from a normal one via the API → can't be pre-filtered). Point the operator
    # at the UTM Profiles enrichment tab.
    if (ctx.get("phase") == "primary" and ctx.get("step") == "Rules"
            and ctx.get("errcode") == -3):
        m = re.search(r"value parse error before '([^']+)'",
                      ctx.get("cli_error") or "")
        if m:
            val = m.group(1)
            e = ctx.get("entry") or {}
            if val in {e.get(f) for f in _FORTI_UTM_POLICY_FIELDS}:
                return (f" - UTM profile '{val}' can't be attached to a firewall "
                        f"policy on this FortiGate (it exists but isn't a valid "
                        f"policy profile - e.g. a sniffer/monitor-only profile). "
                        f"Change or clear it in the UTM Profiles enrichment tab.")
    return ""


def _hint_api_401(exc) -> str:
    """Explain a bare 401 from the FortiGate REST API.

    Two operator traps produce it: API keys are PER-MEMBER in an FGCP cluster
    (FortiOS deliberately does NOT sync them, so a key minted on the other
    member - or before a config-sync event - is rejected), and api-user
    trusthosts restrict the caller's source IP. Both cost real debugging time
    when all you see is 'Unauthorized' (QA finding, FGCP leg)."""
    code = getattr(getattr(exc, "response", None), "status_code", None)
    if code != 401:
        return ""
    return (" - the FortiGate rejected the API key. On an HA cluster keys are "
            "per-member and are NOT synced: regenerate one on the CURRENT "
            "primary (`execute api-user generate-key <user>`) and update the "
            "device. Also check the api-user's trusthost covers this server's "
            "egress IP.")


_FORTI_ERROR_HINTS = [
    _hint_iface_overlap5,
    _hint_iface_overlap54,
    _hint_iface_404,
    _hint_iface_651_captive,
    _hint_utm_not_attachable,
]


# ── Constants ────────────────────────────────────────────────────

# Cap the TCP-connect phase so an unreachable/blackholed device fails in
# seconds instead of blocking the full read-timeout per call. Read-timeout
# stays 30s. Mirrors checkpoint.py / panw.py's _CONNECT_TIMEOUT.
_CONNECT_TIMEOUT = 5

# Forti allows [A-Za-z0-9._-] in names. Anything else gets sanitised. The
# first char must be alphanumeric (vendor enforces - leading punctuation
# gets stripped before length-trim).
_FORTI_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._\-]")
_FORTI_NAME_LEAD_RE = re.compile(r"^[^A-Za-z0-9]+")

# Per-section name length caps. Forti rejects oversize names with errcode -3.
_LIM_POLICY = 35
_LIM_OBJ    = 79
_LIM_ZONE   = 35

# Builtin reserved names - must NOT be pushed as custom. Rule refs to these
# names work natively (Forti resolves the builtin).
_FORTI_BUILTIN_ADDRS    = {"all", "none"}

# Named IP protocols -> protocol numbers for service rendering. Same table
# the CP renderer uses (_IP_PROTO_NAMES there, asa2cp QA fix) - an ASA
# inline service like 'esp any' arrives with protocol='esp' and previously
# hit the unsupported-protocol drop while the rule kept the reference
# (errcode -3 at rule push, asa2fgt finding 2026-09-01).
_FORTI_IP_PROTO_NAMES = {
    "igmp": 2, "ipip": 4, "gre": 47, "esp": 50, "ah": 51,
    "ospf": 89, "pim": 103, "vrrp": 112,
}
_FORTI_BUILTIN_IFACES   = {"any"}


def _forti_is_any_addr(v: dict) -> bool:
    """True for an all-addresses object - 0.0.0.0/0, or the full
    0.0.0.0-255.255.255.255 range. Forti rejects an address whose start-ip is
    0.0.0.0 (`start-ip can not be 0`); such objects map to the builtin `all`
    instead of being pushed as a concrete address (BUG-021)."""
    t = (v.get("type") or "").lower()
    val = (v.get("value") or "").strip()
    if t in ("ip-netmask", "ipmask"):
        try:
            return ipaddress.ip_network(val, strict=False).prefixlen == 0
        except ValueError:
            return False
    if t == "ip-range":
        a, _, b = val.partition("-")
        return a.strip() == "0.0.0.0" and b.strip() == "255.255.255.255"
    return False


def _toposort_groups(entries: list[dict]) -> list[dict]:
    """Order group entries member-first (invariant I2, shared implementation)."""
    return _integ.toposort_by_members(
        entries,
        name_of=lambda e: e.get("name"),
        members_of=lambda e: [m.get("name") for m in (e.get("member") or [])
                              if isinstance(m, dict)],
    )


# Pass-through rule fields the V1 driver does not render. Each non-empty
# occurrence is reported via DroppedField so the UI surfaces it before push.
_UNSUPPORTED_RULE_FIELDS = (
    "application",
    "url_category",
    "user_identity",
    "profile_group",
)


def _safe_name(name: str, max_len: int) -> str:
    """Sanitise a name to Forti's allowed subset and trim to max_len."""
    s = _FORTI_NAME_SAFE_RE.sub("-", name or "")
    s = _FORTI_NAME_LEAD_RE.sub("", s)
    return s[:max_len] or "obj"


def _verify_tls(device: dict) -> bool:
    try:
        cfg = json.loads(device.get("config") or "{}")
        return bool((cfg.get("fortigate") or {}).get("verify_tls"))
    except Exception:
        return False


def _mgmt_iface_name(device: dict) -> str:
    """Mgmt-IF name to protect from delete/PUT in the network-strand push.
    Default 'port1' (FortiOS factory default for the mgmt iface)."""
    try:
        cfg = json.loads(device.get("config") or "{}")
        return ((cfg.get("fortigate") or {}).get("mgmt_iface") or "port1").strip() or "port1"
    except Exception:
        return "port1"


def _parse_ha_reserved(ha: dict) -> set[str]:
    """Interface names reserved by FGCP HA - the heartbeat devices (`hbdev`) and
    the reserved-management interfaces (`ha-mgmt-interfaces`). The network-strand
    push must NEVER delete or overwrite these: clobbering a heartbeat link splits
    the cluster (split-brain), clobbering ha-mgmt severs management. Parsed from a
    `cmdb/system/ha` object. `hbdev` comes back CLI-shaped (`"port3" 50 "port4"
    100` - iface/priority pairs); ha-mgmt-interfaces as a list of {interface}."""
    reserved: set[str] = set()
    hb = ha.get("hbdev")
    if isinstance(hb, str):
        names = re.findall(r'"([^"]+)"', hb)
        if not names:  # unquoted CLI form - keep the non-numeric (name) tokens
            names = [t for t in hb.split() if not t.isdigit()]
        reserved |= set(names)
    elif isinstance(hb, list):
        for m in hb:
            if isinstance(m, dict):
                reserved.add(str(m.get("interface-name") or m.get("interface") or ""))
            elif isinstance(m, str):
                reserved.add(m)
    for m in (ha.get("ha-mgmt-interfaces") or []):
        if isinstance(m, dict) and m.get("interface"):
            reserved.add(str(m["interface"]))
    reserved.discard("")
    return reserved


def _read_ha_context(device: dict, base: str, token: str, vdom: str,
                     verify: bool) -> dict:
    """Cluster context for a push: is HA enabled, are we on the PRIMARY (FGCP
    cmdb writes must land there - a subordinate's config DB is read-only synced
    from the primary), and which interfaces are HA-reserved. Fail-OPEN
    (enabled=False) on any read error so a monitor hiccup or a standalone box
    never blocks a normal push; `is_primary` defaults True so only an AFFIRMATIVE
    subordinate reading aborts the push."""
    ctx: dict = {"enabled": False, "is_primary": True, "reserved": set(),
                 "hostname": "", "detail": ""}
    try:
        ha = _list(base, token, "/system/ha", vdom, verify)
    except Exception:
        return ctx
    if isinstance(ha, list):
        ha = ha[0] if ha else {}
    if not isinstance(ha, dict) or (ha.get("mode") or "standalone").lower() in ("", "standalone"):
        return ctx
    ctx["enabled"] = True
    ctx["reserved"] = _parse_ha_reserved(ha)
    # Primary confirmation: match our own serial against the ha-peer roster.
    try:
        base_url = _f.base_url_for(device)
        st = _f.api_get(base_url, token, "/api/v2/monitor/system/status", vdom) or {}
        local_serial = str(st.get("serial") or "").strip()
        peers = _f.api_get(base_url, token, "/api/v2/monitor/system/ha-peer", vdom) or {}
        roster = peers.get("results") if isinstance(peers, dict) else peers
        if isinstance(roster, list) and local_serial:
            me = next((p for p in roster
                       if str(p.get("serial_no") or "") == local_serial), None)
            if me is not None:
                ctx["hostname"] = me.get("hostname") or ""
                ctx["is_primary"] = bool(me.get("primary") or me.get("master"))
                if not ctx["is_primary"]:
                    ctx["detail"] = (
                        f"reached node {ctx['hostname'] or local_serial} is a cluster "
                        "SUBORDINATE - FGCP config belongs to the primary (older "
                        "FortiOS rejects subordinate writes, recent releases silently "
                        "forward them). Point the device's mgmt IP at the current "
                        "primary and re-push.")
    except Exception:
        pass  # can't confirm → fail-open (assume primary; never block the push)

    # Cloud clusters (AWS/Azure) frequently give each member its OWN
    # DHCP-assigned address on the mgmt + heartbeat ports. Those addresses are
    # per-member state, but a config change on the primary triggers an FGCP
    # sync that can propagate the PRIMARY's addressing onto the secondary -
    # both members then answer on the same heartbeat IP and the cluster splits
    # brain. The driver already leaves hbdev/ha-mgmt untouched on the primary,
    # but it cannot control what FGCP replicates afterwards, so WARN when the
    # reserved interfaces run DHCP (QA finding, live split-brain on an AWS
    # FGCP pair). Purely informational - the push proceeds.
    try:
        if ctx["enabled"] and ctx["reserved"]:
            _dhcp_res = []
            for _r in sorted(ctx["reserved"]):
                _i = _list(base, token, f"/system/interface/{_r}", vdom, verify)
                _i = (_i[0] if isinstance(_i, list) and _i else _i) or {}
                if str(_i.get("mode") or "").lower() == "dhcp":
                    _dhcp_res.append(_r)
            if _dhcp_res:
                ctx["dhcp_reserved"] = _dhcp_res
    except Exception:
        pass
    return ctx


# ── REST API helpers (driver-side) ───────────────────────────────

class _FortiError(Exception):
    """Wraps a Forti API error. Captures errcode so the push loop can
    decide whether to treat it as recoverable (errcode -5 = already exists)."""
    def __init__(self, errcode: int, message: str, status_code: int = 0):
        self.errcode = errcode
        self.message = message
        self.status_code = status_code
        super().__init__(f"errcode {errcode}: {message} (HTTP {status_code})")


def _api_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


def _cmdb_base(device: dict) -> str:
    return _f.base_url_for(device) + "/api/v2/cmdb"


def _import_local_cert(device: dict, token: str, vdom: str, verify: bool,
                       certname: str, cert_pem: str, key_pem: str) -> dict:
    """Import a local identity cert + key (VPN cert push step, CR-3) via the
    monitor endpoint. PEM cert + key are base64-wrapped; the key is provisioned
    on-box for IKE signature auth. Never logged."""
    url = (_f.base_url_for(device)
           + f"/api/v2/monitor/vpn-certificate/local/import?vdom={vdom}")
    body = {
        "type": "regular", "scope": "vdom", "certname": certname,
        "file_content": base64.b64encode(cert_pem.encode()).decode(),
        "key_file_content": base64.b64encode(key_pem.encode()).decode(),
        "password": "",
    }
    resp = requests.post(url, headers=_api_headers(token), data=json.dumps(body),
                         verify=verify, timeout=(_CONNECT_TIMEOUT, 30))
    return _resp_unwrap(resp)


def _resp_unwrap(resp) -> dict:
    """Forti API returns 200 with success-shape OR 4xx/5xx with error-shape.
    Error shape: {status: 'error', error: <int errcode>, http_status: NNN,
    cli_error?: str}. Errcodes are negative ints; the push loop uses them
    to decide whether to soft-fail (builtin/in-use) or abort."""
    body: dict = {}
    try:
        body = resp.json() or {}
    except Exception:
        pass
    err_val = body.get("error")
    errcode = err_val if isinstance(err_val, int) else 0
    status_str = (body.get("status") or "").lower()
    if errcode < 0 or status_str == "error":
        msg = (body.get("cli_error") or body.get("error_message")
               or (str(err_val) if err_val is not None else "")
               or status_str or "API error")
        # FortiOS HTML-escapes quotes inside cli_error ("before &#39;x&#39;") -
        # unescape once at the source so the error-hint regexes (quote-anchored,
        # e.g. _hint_utm_not_attachable) match and the logged text stays
        # readable. Downstream rendering re-escapes (Jinja autoescape).
        raise _FortiError(errcode or -1, html.unescape(str(msg)), resp.status_code)
    if not resp.ok:
        raise _FortiError(
            0,
            f"HTTP {resp.status_code}: {resp.text[:200]}",
            resp.status_code,
        )
    return body


def _post(base: str, token: str, path: str, vdom: str, body: dict, verify: bool) -> dict:
    url = f"{base}{path}?vdom={vdom}"
    resp = requests.post(url, headers=_api_headers(token),
                         data=json.dumps(body), verify=verify, timeout=(_CONNECT_TIMEOUT, 30))
    return _resp_unwrap(resp)


def _put(base: str, token: str, path: str, vdom: str, body: dict, verify: bool) -> dict:
    url = f"{base}{path}?vdom={vdom}"
    resp = requests.put(url, headers=_api_headers(token),
                        data=json.dumps(body), verify=verify, timeout=(_CONNECT_TIMEOUT, 30))
    return _resp_unwrap(resp)


def _delete(base: str, token: str, path: str, vdom: str, verify: bool) -> dict:
    url = f"{base}{path}?vdom={vdom}"
    resp = requests.delete(url, headers=_api_headers(token),
                           verify=verify, timeout=(_CONNECT_TIMEOUT, 30))
    return _resp_unwrap(resp)


def _list(base: str, token: str, path: str, vdom: str, verify: bool) -> list[dict]:
    url = f"{base}{path}?vdom={vdom}&count=2000"
    resp = requests.get(url, headers=_api_headers(token),
                        verify=verify, timeout=(_CONNECT_TIMEOUT, 30))
    resp.raise_for_status()
    return (resp.json() or {}).get("results") or []


# ── Driver ───────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class _PushStep:
    """One row of the push-steps table.

    deletable_types is the iface-type allow-list for the DELETE phase
    (Interfaces only - Forti refuses to DELETE physical IFs). None means
    delete every entry the GET returns.
    """
    label: str
    cmdb_path: str
    section_key: str
    id_field: str
    strand: str
    deletable_types: frozenset[str] | None


@register_driver
class FortinetDriver(DeployDriver):

    # Must match the fw_devices.platform enum value - the runtime looks up
    # drivers by that key (DEPLOY_DRIVERS[device.platform]).
    platform = "fortigate"

    migration_note = (
        "V1 covers rules, addresses, services, groups, zones, interfaces, "
        "static routes. NAT, IPv6, UTM/security profiles and multi-VDOM are "
        "out of scope. Mgmt interface is excluded from push to preserve "
        "reachability."
    )

    # ── Settings ─────────────────────────────────────────────────

    def default_settings(self) -> list[dict]:
        return [
            {
                "key": "rule_prefix",
                "label": "Rule Name Prefix",
                "type": "text",
                "default": "Gateshift-",
                "placeholder": "e.g. Gateshift-",
            },
            {
                "key": "log_traffic",
                "label": "Log Traffic",
                "type": "select",
                "default": "all",
                "options": ["disable", "utm", "all"],
                "help": (
                    "all = log every session (recommended for Gateshift migrated "
                    "rules without UTM profiles attached). utm = only log "
                    "when a UTM profile matches. disable = no logging."
                ),
            },
            {
                "key": "comment_tag",
                "label": "Comment Tag",
                "type": "text",
                "default": "[Gateshift]",
                "placeholder": "[Gateshift]",
                "help": (
                    "Prefix added to every pushed rule's comments field so "
                    "the Gateshift-managed rules are visually distinguishable on "
                    "the FortiGate UI."
                ),
            },
        ]

    # ── Generate ─────────────────────────────────────────────────

    def generate(
        self,
        *,
        rules: list[dict],
        address_objects: list[dict],
        address_groups: list[dict],
        service_objects: list[dict],
        service_groups: list[dict],
        zones: list[dict],
        interfaces: list[dict],
        routes: list[dict],
        vrfs: list[dict],
        nat_rules: list[dict],
        settings: dict[str, str],
        tp_configs: list[dict] = (),
        nat_vips: list[dict] = (),
        nat_ippools: list[dict] = (),
        tags: list[dict] = (),
        url_categories: list[dict] = (),
        schedules: list[dict] = (),
        pbf_rules: list[dict] = (),
        ssl_rules: list[dict] = (),   # PA/CP rulebase shape - N/A for a Forti target (per-policy attach)
        vpn_tunnels: list[dict] = (),            # IPSec VPN (CE plan P3b)
        ike_crypto_profiles: list[dict] = (),    # inlined into phase1.proposal
        ipsec_crypto_profiles: list[dict] = (),  # inlined into phase2.proposal
        active_routes: list[dict] = (),          # CP-only (route-based VPN domains); ignored here
        nat_mode: str = "central",   # 'central' = central-snat-map; 'policy' = per-policy nat
        routing_mode: str = "legacy",  # PA-only render mode (legacy VR / advanced LR); ignored here
    ) -> tuple[dict[str, str], list[dict]]:
        del active_routes, routing_mode
        # Tags ignored - FortiGate policies have no tag concept; per-rule
        # tag-fields surface as DroppedField in the rules-loop below.
        del vrfs, tp_configs, tags

        sections: dict[str, str] = {}
        dropped: list[DroppedField] = []

        # ── Renames ──
        # Sanitise all object/group/zone names ONCE so lookups + rule refs
        # use the safe form consistently.
        addr_rename:  dict[str, str] = {}
        svc_rename:   dict[str, str] = {}
        grp_addr_rename: dict[str, str] = {}
        grp_svc_rename:  dict[str, str] = {}
        zone_rename:  dict[str, str] = {}

        # Literal → object-name lookup (mirrors panw._build_addr_lookup):
        # log-source rules carry bare IP/CIDR literals ("192.0.2.10"), the
        # auto-generated objects carry names ("h-192.0.2.10[-zone]"). Without
        # this map every such ref missed valid_addrs and fell back to 'all' -
        # 433 of 634 refs on the logs2fgt estate degraded silently
        # (finding 2026-09-01). Keys cover the raw value and, for /32 hosts,
        # the bare IP - same contract as the PA lookup.
        addr_literal: dict[str, str] = {}
        for o in address_objects:
            n = o.get("name") or ""
            # All-addresses objects map to the builtin `all`: the object-render
            # loop then skips it (builtin collision) and group/rule references
            # resolve to `all` instead of an address with start-ip 0 (BUG-021).
            if _forti_is_any_addr(o.get("value") or {}):
                addr_rename[n] = "all"
            else:
                addr_rename[n] = _safe_name(n, _LIM_OBJ)
            _val = o.get("value") or {}
            _v = str(_val.get("value") or "")
            if n and _v:
                addr_literal.setdefault(_v, addr_rename[n])
                if _val.get("type") == "ip-netmask" and _v.endswith("/32"):
                    addr_literal.setdefault(_v[:-3], addr_rename[n])
        for o in address_groups:
            n = o.get("name") or ""
            grp_addr_rename[n] = _safe_name(n, _LIM_OBJ)
        for o in service_objects:
            n = o.get("name") or ""
            svc_rename[n] = _safe_name(n, _LIM_OBJ)
        for o in service_groups:
            n = o.get("name") or ""
            grp_svc_rename[n] = _safe_name(n, _LIM_OBJ)
        for z in zones:
            n = z.get("name") or ""
            zone_rename[n] = _safe_name(n, _LIM_ZONE)

        # An interface that is a member of a zone CANNOT be referenced directly
        # in a policy / central-snat - FortiOS demands the zone
        # (errcode -651 "node_check_object fail! for name <iface>"). Map each
        # zoned interface → its (renamed) zone so srcintf/dstintf resolve to the
        # zone. Built from the same zone data pushed to the target (members are
        # already target-resolved iface names), so it matches the box post
        # network-push.
        # First-seen wins - the same 1:1 dedup the Zones section render applies
        # (an iface in two source zones is emitted only in the first), so this
        # map matches the zone membership actually pushed to the box.
        iface_to_zone: dict[str, str] = {}
        for z in zones:
            zn = zone_rename.get(z.get("name") or "", z.get("name") or "")
            for m in (z.get("interfaces") or []):
                if m and m not in iface_to_zone:
                    iface_to_zone[m] = zn

        # Forti interface-name normalization map (SOURCE name → Forti-safe name),
        # applied wherever an interface is REFERENCED (zone members, route device,
        # policy-route in/out-device) AND at the interface-definition render so
        # both agree. Two transforms:
        #   F8 - VPN tunnel-iface is renamed by render_vpn after the phase1-
        #        interface (tunnel.1 → tun-psk-v1).
        #   F7 - a '.' in a non-VLAN name (loopback.1) breaks Forti's zone/route
        #        datasource lookup → strip it (loopback.1 → loopback1).
        # iface_to_zone stays on the SOURCE name (source rules reference the
        # original → resolve to the zone).
        _iface_map: dict[str, str] = dict(_f.tunnel_iface_names(vpn_tunnels))
        for _i in interfaces:
            _nm = (_i.get("interface_name") or "").strip()
            if _nm and _nm not in _iface_map:
                _safe = _f.forti_safe_iface(_nm, _i.get("iface_type"))
                if _safe != _nm:
                    _iface_map[_nm] = _safe

        def _imap(n):
            return _iface_map.get(n, n)

        # Valid-name sets for rule-time validation (resolve to "any"/"all"/"ALL"
        # fallback if a rule ref doesn't match anything).
        valid_addrs  = set(addr_rename.values()) | set(grp_addr_rename.values()) | _FORTI_BUILTIN_ADDRS
        valid_svcs   = set(svc_rename.values()) | set(grp_svc_rename.values()) | {"ALL"}
        # Zones AND interface names are both valid for srcintf/dstintf.
        iface_names  = {i.get("interface_name") for i in interfaces if i.get("interface_name")}
        valid_ifaces = set(zone_rename.values()) | iface_names | _FORTI_BUILTIN_IFACES

        # ── Address Objects ──
        addr_entries: list[dict] = []
        for o in address_objects:
            name = o.get("name") or ""
            if not name:
                continue
            safe = addr_rename[name]
            if safe.lower() in _FORTI_BUILTIN_ADDRS:
                dropped.append(DroppedField(
                    rule_id=name, field="address",
                    reason="collides with Forti builtin",
                ))
                continue
            v = o.get("value") or {}
            t = (v.get("type") or "").lower()
            entry: dict = {"name": safe}
            if t in ("ip-netmask", "ipmask"):
                subnet = _f.cidr_to_subnet(v.get("value"))
                if not subnet:
                    dropped.append(DroppedField(
                        rule_id=name, field="address",
                        reason=f"unparseable subnet '{v.get('value')}'",
                    ))
                    continue
                entry["type"] = "ipmask"
                entry["subnet"] = subnet
            elif t == "ip-range":
                rng = (v.get("value") or "").strip()
                if "-" not in rng:
                    dropped.append(DroppedField(
                        rule_id=name, field="address",
                        reason=f"unparseable range '{rng}'",
                    ))
                    continue
                start, _, end = rng.partition("-")
                entry["type"] = "iprange"
                entry["start-ip"] = start.strip()
                entry["end-ip"] = end.strip()
            elif t == "fqdn":
                fqdn = (v.get("value") or "").strip()
                if not fqdn:
                    continue
                entry["type"] = "fqdn"
                entry["fqdn"] = fqdn
            else:
                dropped.append(DroppedField(
                    rule_id=name, field="address",
                    reason=f"unsupported type '{t}'",
                ))
                continue
            desc = (v.get("description") or "").strip()
            if desc:
                entry["comment"] = desc[:255]
            addr_entries.append(entry)
        sections["Address Objects"] = json.dumps(addr_entries)

        # ── Address Groups ──
        addrgrp_entries: list[dict] = []
        for g in address_groups:
            name = g.get("name") or ""
            if not name:
                continue
            safe = grp_addr_rename[name]
            v = g.get("value") or {}
            # Dynamic / filter-based groups (PA DAG, tag-filter) have no static
            # members - the membership is evaluated live. Not modeled here, so
            # say so explicitly instead of the misleading "all members
            # unresolved" the empty-members path below would emit. (B-1)
            if v.get("type") == "dynamic" or v.get("filter"):
                dropped.append(DroppedField(
                    rule_id=name, field="address_group",
                    reason="dynamic/filter-based address-group not modeled",
                ))
                continue
            members_raw = v.get("members") or []
            members_resolved: list[str] = []
            for m in members_raw:
                if m in addr_rename:
                    members_resolved.append(addr_rename[m])
                elif m in grp_addr_rename:
                    members_resolved.append(grp_addr_rename[m])
                elif m.lower() in _FORTI_BUILTIN_ADDRS:
                    members_resolved.append(m.lower())
                else:
                    dropped.append(DroppedField(
                        rule_id=name, field="address_group_member",
                        reason=f"unresolved member '{m}'",
                    ))
            if not members_resolved:
                dropped.append(DroppedField(
                    rule_id=name, field="address_group",
                    reason="all members unresolved",
                ))
                continue
            entry = {
                "name": safe,
                "member": [{"name": m} for m in members_resolved],
            }
            desc = (v.get("description") or "").strip()
            if desc:
                entry["comment"] = desc[:255]
            addrgrp_entries.append(entry)
        # Nested groups (group-of-groups) must be pushed member-first (BUG-022).
        sections["Address Groups"] = json.dumps(_toposort_groups(addrgrp_entries))

        # ── Service Objects ──
        # Vendor-shipped (predefined) source services are skipped UNLESS a
        # rule/group/NAT actually references them: same-vendor the target's
        # own catalog resolves the name, but cross-vendor (CP 'domain-udp' on
        # a Forti box, QA finding) the name resolves against NOTHING -
        # materialize-or-map applies to predefined refs too.
        _referenced_svcs: set[str] = set()
        for _r in rules or []:
            _referenced_svcs.update(
                x for x in (_r.get("services") or []) if x and x != "any")
        for _g in service_groups or []:
            _referenced_svcs.update((_g.get("value") or {}).get("members") or [])
        for _n in nat_rules or []:
            _referenced_svcs.update(
                x for x in (_n.get("orig_service") or []) if x and x != "any")
        svc_entries: list[dict] = []
        for o in service_objects:
            name = o.get("name") or ""
            if not name:
                continue
            safe = svc_rename[name]
            v = o.get("value") or {}
            if v.get("predefined") and name not in _referenced_svcs:
                continue  # vendor-shipped + unreferenced, skip
            entry: dict = {"name": safe}

            tcp_pr  = v.get("tcp_portrange")
            udp_pr  = v.get("udp_portrange")
            sctp_pr = v.get("sctp_portrange")
            proto   = (v.get("protocol") or "").lower()
            port    = v.get("port")

            # Forti rejects empty/'any' portrange - normalize to full range.
            # ASA port operators arrive canonically as '<N' / '>N' / '!N';
            # FortiOS knows none of them but takes space-separated multi-
            # ranges, so all three translate (QA finding, ASA legs - the
            # operators previously went out verbatim and 500'd silently).
            def _portrange(p) -> str:
                s = str(p or "").strip().lower()
                if not s or s == "any":
                    return "1-65535"
                if s[0] == "<" and s[1:].strip().isdigit():
                    n = int(s[1:].strip())
                    return f"1-{max(n - 1, 1)}"
                if s[0] == ">" and s[1:].strip().isdigit():
                    n = int(s[1:].strip())
                    return f"{min(n + 1, 65535)}-65535"
                if s[0] == "!" and s[1:].strip().isdigit():
                    n = int(s[1:].strip())
                    parts = []
                    if n > 1:
                        parts.append(f"1-{n - 1}")
                    if n < 65535:
                        parts.append(f"{n + 1}-65535")
                    return " ".join(parts) or "1-65535"
                return str(p)

            if tcp_pr or udp_pr or sctp_pr:
                entry["protocol"] = "TCP/UDP/SCTP"
                if tcp_pr:
                    entry["tcp-portrange"] = _portrange(tcp_pr)
                if udp_pr:
                    entry["udp-portrange"] = _portrange(udp_pr)
                if sctp_pr:
                    entry["sctp-portrange"] = _portrange(sctp_pr)
            elif proto in ("tcp", "udp", "sctp"):
                entry["protocol"] = "TCP/UDP/SCTP"
                entry[f"{proto}-portrange"] = _portrange(port)
            elif proto == "icmp":
                entry["protocol"] = "ICMP"
                if v.get("icmp_type") not in (None, ""):
                    entry["icmptype"] = int(v["icmp_type"])
                if v.get("icmp_code") not in (None, ""):
                    entry["icmpcode"] = int(v["icmp_code"])
            elif proto == "icmpv6":
                entry["protocol"] = "ICMP6"
                if v.get("icmp_type") not in (None, ""):
                    entry["icmptype"] = int(v["icmp_type"])
            elif proto == "ip":
                entry["protocol"] = "IP"
                if v.get("ip_protocol") not in (None, ""):
                    entry["protocol-number"] = int(v["ip_protocol"])
            elif proto in _FORTI_IP_PROTO_NAMES or proto.isdigit():
                entry["protocol"] = "IP"
                entry["protocol-number"] = (int(proto) if proto.isdigit()
                                            else _FORTI_IP_PROTO_NAMES[proto])
            else:
                dropped.append(DroppedField(
                    rule_id=name, field="service",
                    reason=f"unsupported protocol '{proto}'",
                ))
                continue

            desc = (v.get("description") or "").strip()
            if desc:
                entry["comment"] = desc[:255]
            svc_entries.append(entry)
        sections["Service Objects"] = json.dumps(svc_entries)

        # ── Service Groups ──
        svcgrp_entries: list[dict] = []
        for g in service_groups:
            name = g.get("name") or ""
            if not name:
                continue
            safe = grp_svc_rename[name]
            v = g.get("value") or {}
            members_raw = v.get("members") or []
            members_resolved: list[str] = []
            for m in members_raw:
                if m in svc_rename:
                    members_resolved.append(svc_rename[m])
                elif m in grp_svc_rename:
                    members_resolved.append(grp_svc_rename[m])
                elif _integ.looks_like_uid(m):
                    # A raw source UID (CP: member object was deleted/out of
                    # visibility - the importer keeps the UID faithfully).
                    # Never a valid target name → drop the member, keep the
                    # group (QA finding: 'ghost' edge-case group).
                    dropped.append(DroppedField(
                        rule_id=name, field="service_group_member",
                        reason=f"member '{m}' is an unresolved source UID "
                               "(object deleted or not visible at import)",
                    ))
                else:
                    # Could be a Forti builtin service ("HTTP", "DNS", "SSH", ...).
                    # We don't enforce a closed list here; let the push step
                    # surface the failure as errcode if the name is invalid.
                    members_resolved.append(m)
            if not members_resolved:
                dropped.append(DroppedField(
                    rule_id=name, field="service_group",
                    reason="all members unresolved",
                ))
                continue
            entry = {
                "name": safe,
                "member": [{"name": m} for m in members_resolved],
            }
            desc = (v.get("description") or "").strip()
            if desc:
                entry["comment"] = desc[:255]
            svcgrp_entries.append(entry)
        # Nested groups (group-of-groups) must be pushed member-first (BUG-022).
        sections["Service Groups"] = json.dumps(_toposort_groups(svcgrp_entries))

        # ── Schedules (Phase 1b + cross-vendor V1) ──
        # FortiOS has three schedule subtypes: recurring (day list +
        # start/end time), onetime (single start/end datetime), group
        # (list of schedule names). One output section per subtype so the
        # push loop hits the right REST endpoint.
        #
        # Read order: value.forti_* first (lossless same-vendor), fallback
        # value.intervals (universal LCD, dispatch by kind). Built-ins
        # always / default / none exist natively on the target → skip
        # without pushing, rule refs still resolve.
        FORTI_BUILTIN_SCHEDULES = {"always", "default", "none"}
        # Canonical → Forti weekday spelling.
        _FORTI_WEEKDAY_FROM_CANON = {
            "Sun": "sunday", "Mon": "monday", "Tue": "tuesday",
            "Wed": "wednesday", "Thu": "thursday", "Fri": "friday",
            "Sat": "saturday",
        }

        def _iso_to_forti_dt(iso: str) -> str:
            """ISO 'YYYY-MM-DD HH:MM' (or 'T'-separated) → FortiOS onetime
            'HH:MM YYYY/MM/DD'. FortiOS wants the TIME first, then the date -
            sending date-first fails node_check_object (-651)."""
            s = (iso or "").strip().replace("T", " ")
            if not s:
                return ""
            parts = s.split()
            date = parts[0].replace("-", "/")
            time = parts[1][:5] if len(parts) > 1 else "00:00"
            return f"{time} {date}"

        sched_recurring: list[dict] = []
        sched_onetime: list[dict] = []
        sched_group: list[dict] = []
        for s in (schedules or []):
            sname = (s.get("name") or "").strip()
            if not sname:
                continue
            if sname.lower() in FORTI_BUILTIN_SCHEDULES:
                # Built-ins are factory-shipped; pushing them as user objects
                # collides with the predefined entries. Rule-time refs still
                # resolve against the native target object.
                continue
            sval = s.get("value") or {}
            desc = (sval.get("description") or
                    sval.get("forti_description") or "").strip()

            # Same-vendor lossless path - forti_* slots populated by the
            # Forti importer.
            if sval.get("forti_recurring"):
                rec = sval["forti_recurring"]
                e = {"name": sname,
                     "day": " ".join(rec.get("day") or []),
                     "start": (rec.get("start_time") or "").strip(),
                     "end":   (rec.get("end_time")   or "").strip()}
                if desc:
                    e["comment"] = desc[:255]
                sched_recurring.append(e)
                continue
            if sval.get("forti_onetime"):
                ot = sval["forti_onetime"]
                e = {"name": sname,
                     "start": (ot.get("start") or "").strip(),
                     "end":   (ot.get("end")   or "").strip()}
                if desc:
                    e["comment"] = desc[:255]
                sched_onetime.append(e)
                continue
            if sval.get("forti_group"):
                members = sval["forti_group"]
                e = {"name": sname,
                     "member": [{"name": m} for m in members]}
                if desc:
                    e["comment"] = desc[:255]
                sched_group.append(e)
                continue

            # Cross-vendor fallback - derive from universal intervals LCD.
            intervals = sval.get("intervals") or []
            if not intervals:
                dropped.append(DroppedField(
                    rule_id=sname, field="schedule",
                    reason="no forti_* slot AND no intervals - cross-vendor "
                           "import without any schedule mapping",
                    fallback="object skipped at push",
                ))
                continue
            # Merge weekly intervals that share a time window into one: Forti
            # recurring `day` is a multi-day list with a single start/end, so
            # the per-weekday intervals the PA parser emits (Mon–Fri 09:00–17:00
            # = 5 intervals) collapse losslessly to one entry. Distinct windows
            # can't coexist in one recurring object → keep them separate and let
            # the >1 warn below fire. (B-SCHEDWEEK)
            if intervals and all((i.get("kind") or "").lower() == "weekly"
                                 for i in intervals):
                windows: dict[tuple[str, str], list[str]] = {}
                for i in intervals:
                    key = ((i.get("start_time") or "").strip(),
                           (i.get("end_time") or "").strip())
                    bucket = windows.setdefault(key, [])
                    for d in (i.get("weekdays") or []):
                        if d not in bucket:
                            bucket.append(d)
                intervals = [
                    {"kind": "weekly", "weekdays": wkds,
                     "start_time": st, "end_time": en}
                    for (st, en), wkds in windows.items()
                ]
            if len(intervals) > 1:
                dropped.append(DroppedField(
                    rule_id=sname, field="schedule",
                    reason=(f"{len(intervals)} distinct time windows in source - "
                            "Forti recurring holds one start/end per object"),
                    fallback="first window pushed, rest skipped",
                ))
            itv = intervals[0]
            kind = (itv.get("kind") or "").lower()
            if kind == "weekly":
                days = [_FORTI_WEEKDAY_FROM_CANON.get(d, d.lower())
                        for d in (itv.get("weekdays") or [])]
                e = {"name": sname,
                     "day": " ".join(days),
                     "start": (itv.get("start_time") or "").strip(),
                     "end":   (itv.get("end_time")   or "").strip()}
                if desc:
                    e["comment"] = desc[:255]
                sched_recurring.append(e)
            elif kind == "daily":
                # "daily" maps to weekly with all 7 days populated.
                e = {"name": sname,
                     "day": " ".join(_FORTI_WEEKDAY_FROM_CANON.values()),
                     "start": (itv.get("start_time") or "").strip(),
                     "end":   (itv.get("end_time")   or "").strip()}
                if desc:
                    e["comment"] = desc[:255]
                sched_recurring.append(e)
            elif kind == "onetime":
                e = {"name": sname,
                     "start": _iso_to_forti_dt(itv.get("start_datetime") or ""),
                     "end":   _iso_to_forti_dt(itv.get("end_datetime")   or "")}
                if desc:
                    e["comment"] = desc[:255]
                sched_onetime.append(e)
            elif kind == "group":
                members = [m for m in (itv.get("members") or [])
                           if isinstance(m, str) and m]
                if not members:
                    dropped.append(DroppedField(
                        rule_id=sname, field="schedule",
                        reason="group-kind interval with no members",
                        fallback="object skipped at push",
                    ))
                    continue
                e = {"name": sname,
                     "member": [{"name": m} for m in members]}
                if desc:
                    e["comment"] = desc[:255]
                sched_group.append(e)
            elif kind == "monthly":
                dropped.append(DroppedField(
                    rule_id=sname, field="schedule",
                    reason="monthly recurrence (CP-only) - Forti has no "
                           "monthly pattern",
                    fallback="object skipped at push",
                ))
            else:
                dropped.append(DroppedField(
                    rule_id=sname, field="schedule",
                    reason=f"unknown interval kind '{kind}'",
                    fallback="object skipped at push",
                ))
        sections["Schedules Recurring"] = json.dumps(sched_recurring)
        sections["Schedules Onetime"]   = json.dumps(sched_onetime)
        sections["Schedules Group"]     = json.dumps(sched_group)

        # ── Policy Routes (PBF, Phase 3) - router/policy, network strand.
        # Rendered LATER (after _resolve_addr_ref is defined) so srcaddr/dstaddr
        # reuse the security renderer's address-object resolver - router/policy
        # references address objects by name, not inline subnets (schema-probed).

        # ── URL Categories (Phase 1a) ──
        # FortiOS webfilter/urlfilter - a list of URL patterns with type +
        # action. The driver reads the forti_ slot of the value JSON;
        # cross-vendor imports without forti_entries are skipped with a
        # DroppedField warn (per feedback_user_owns_migration_decisions,
        # the user maps manually).
        urlfilter_entries: list[dict] = []
        for c in (url_categories or []):
            name = (c.get("name") or "").strip()
            if not name:
                continue
            val = c.get("value") or {}
            entries_src = val.get("forti_entries") or []
            entries: list[dict] = []
            for ent in entries_src:
                url = (ent.get("url") or "").strip() if isinstance(ent, dict) else ""
                if not url:
                    continue
                entries.append({
                    "url":    url,
                    "type":   (ent.get("type") or "simple"),
                    "action": (ent.get("action") or "block"),
                })
            if not entries:
                dropped.append(DroppedField(
                    rule_id=name, field="url_category",
                    reason="no forti_entries slot - cross-vendor import "
                           "without Forti mapping",
                    fallback="object skipped at push",
                ))
                continue
            entry = {"name": name, "entries": entries}
            desc = (val.get("forti_description") or "").strip()
            if desc:
                entry["comment"] = desc[:255]
            urlfilter_entries.append(entry)
        sections["URL Categories"] = json.dumps(urlfilter_entries)

        # ── Zones ──
        # Forti enforces 1:1 iface→zone. Build a seen-iface set so a member
        # appearing in two source zones is only emitted in the first.
        zone_entries: list[dict] = []
        seen_iface_in_zone: set[str] = set()
        for z in zones:
            zname = z.get("name") or ""
            if not zname:
                continue
            safe = zone_rename[zname]
            members = []
            for m in z.get("interfaces") or []:
                # Normalize to the Forti-safe iface name (F7 dot-strip + F8
                # tunnel rename) so the zone member matches the pushed iface.
                m = _imap(m)
                if not m or m in seen_iface_in_zone:
                    if m in seen_iface_in_zone:
                        dropped.append(DroppedField(
                            rule_id=zname, field="zone_member",
                            reason=f"iface '{m}' already bound to another zone",
                        ))
                    continue
                seen_iface_in_zone.add(m)
                members.append({"interface-name": m})
            if not members:
                dropped.append(DroppedField(
                    rule_id=zname, field="zone",
                    reason="no interface members",
                ))
                continue
            entry = {"name": safe, "interface": members}
            # Vendor-prefixed zone-properties from fw_zones.properties
            # (schema in webui/zone_schemas.py). pa_* slots - if present
            # from a cross-vendor PA→Forti source - are ignored here; the
            # Forti driver only renders its own forti_* slots.
            props = z.get("properties") or {}
            if props.get("forti_intrazone_block"):
                entry["intrazone"] = "deny"
            desc = (props.get("forti_description") or "").strip()
            if desc:
                entry["description"] = desc[:255]
            zone_entries.append(entry)
        sections["Zones"] = json.dumps(zone_entries)

        # ── Interfaces ──
        # Render everything; the push step filters mgmt + physical-DELETE.
        # VRF is an int on the iface (0 = default, else vrf-N → N).
        # Cross-vendor VRs (PA 'gs-vr-guest', CP …) don't follow the Forti
        # 'vrf-N' naming - falling back to 0 would silently COLLAPSE the
        # source's routing separation (two defaults in one table). Allocate
        # a stable id per foreign VR name instead: sorted names take the
        # lowest free ids, skipping ids claimed by native vrf-N names.
        _foreign_vrs = sorted({
            (x.get("vr_name") or "").strip()
            for x in list(interfaces) + list(routes)
            if (x.get("vr_name") or "").strip() not in ("", "default")
            and not re.match(r"^vrf-\d+$", (x.get("vr_name") or "").strip())
        })
        _taken = {int(m.group(1)) for x in list(interfaces) + list(routes)
                  if (m := re.match(r"^vrf-(\d+)$", (x.get("vr_name") or "").strip()))}
        _vr_alloc: dict[str, int] = {}
        _next = 1
        for _vrn in _foreign_vrs:
            while _next in _taken:
                _next += 1
            _vr_alloc[_vrn] = _next
            _taken.add(_next)

        def _vrf_id(vr: str | None) -> int:
            if not vr or vr == "default":
                return 0
            m = re.match(r"^vrf-(\d+)$", vr)
            if m:
                return int(m.group(1))
            return _vr_alloc.get(vr, 0)

        iface_entries: list[dict] = []
        for i in interfaces:
            iname = i.get("interface_name") or ""
            if not iname:
                continue
            itype = (i.get("iface_type") or "").lower()
            if itype == "tunnel":
                # FortiGate names the IPSec tunnel-iface after its phase1-interface
                # and creates it implicitly with the VPN push (CE plan P2/P3) - it
                # is NOT a standalone system/interface, so skip it here.
                dropped.append(DroppedField(
                    rule_id=iname, field="interface",
                    reason="IPSec tunnel iface is implicit (created by the phase1-interface)",
                ))
                continue
            entry: dict = {"name": _imap(iname)}
            if itype == "vlan":
                entry["type"] = "vlan"
                parent = i.get("parent_iface_name") or ""
                if parent:
                    entry["interface"] = _imap(parent)
                vtag = i.get("vlan_tag")
                if vtag:
                    entry["vlanid"] = int(vtag)
            elif itype == "bond":
                entry["type"] = "aggregate"
                members = [
                    {"interface-name": _imap(m)}
                    for m in (i.get("member_iface_names") or [])
                    if m
                ]
                if members:
                    entry["member"] = members
                else:
                    dropped.append(DroppedField(
                        rule_id=iname, field="member_iface_names",
                        reason="bond has no members - empty aggregate would refuse traffic",
                        fallback="skipped - add members in Network > Interfaces",
                    ))
                    continue
            elif itype == "loopback":
                entry["type"] = "loopback"
            # physical: no 'type' field - Forti rejects setting type on a
            # physical iface.
            # DHCP-Client mode wins over static IPs - they're exclusive on
            # FortiOS too. `set mode dhcp` replaces `set ip <addr> <mask>`.
            # Explicit `mode: "static"` on the non-DHCP path so a switch
            # back from a previously DHCP-configured iface lands cleanly:
            # FortiOS rejects `set ip` while mode is still dhcp, leaving the
            # static rewrite silently un-applied. Setting mode unconditionally
            # is a no-op when the target is already static.
            if i.get("dhcp_enabled"):
                entry["mode"] = "dhcp"
            else:
                entry["mode"] = "static"
                ips = i.get("ip_addresses") or []
                if ips:
                    payload = _f.iface_cidr_to_payload(ips[0])
                    if payload:
                        entry["ip"] = payload
                    if len(ips) > 1:
                        dropped.append(DroppedField(
                            rule_id=iname, field="interface_ip",
                            reason=f"{len(ips)-1} secondary IP(s) not rendered (V1)",
                        ))
            vrf = _vrf_id(i.get("vr_name"))
            if vrf:
                entry["vrf"] = vrf
            desc = (i.get("description") or "").strip()
            if desc:
                entry["description"] = desc[:255]
            role_val = (i.get("role") or "").strip().lower()
            if role_val in ("lan", "wan", "dmz", "undefined"):
                entry["role"] = role_val
            # Admin state: omit `status` when up (FortiOS default), emit
            # `down` only on admin-disable. Mirrors how `mode` is left off
            # for static-default cases would be a regression, but here a
            # missing field keeps the iface at its prior status - so we
            # emit `up` explicitly when enabled=True to flip a previously-
            # down iface back on without manual intervention.
            entry["status"] = "down" if not bool(i.get("enabled", True)) else "up"
            iface_entries.append(entry)
        # Push/dependency ordering: an aggregate's physical members and a VLAN's
        # parent (`interface`) must already exist when the dependant is created,
        # or FortiOS rejects it with -3 "entry not found in datasource / value
        # parse error before '<parent>'". Order base ifaces (physical/loopback)
        # → aggregate (rides on physical) → vlan (rides on physical OR aggregate).
        # Stable sort preserves the source order within each tier.
        _iface_push_tier = {"aggregate": 1, "vlan": 2}
        iface_entries.sort(
            key=lambda e: _iface_push_tier.get((e.get("type") or "").lower(), 0)
        )
        sections["Interfaces"] = json.dumps(iface_entries)

        # ── Static Routes ──
        # Skip connected routes - Forti synthesises them from iface IPs.
        # seq-num is renumbered 1..N to avoid collisions on re-push.
        # FortiOS router/static requires `device` (egress interface) on every
        # non-blackhole route - a recursive gateway-only route is rejected with
        # errcode -651 "Attribute 'device' MUST be set". When the source route
        # carries no interface, derive it from the gateway IP: the (already
        # override-resolved) interface whose subnet contains the gateway, by
        # longest-prefix match. interface_name on both `routes` and `interfaces`
        # is target-resolved at generate time, so the derived name lands correct.
        _iface_nets: list[tuple] = []
        for _i in interfaces:
            _nm = (_i.get("interface_name") or "").strip()
            if not _nm:
                continue
            for _ipc in (_i.get("ip_addresses") or []):
                try:
                    _iface_nets.append(
                        (ipaddress.ip_network(_ipc, strict=False), _nm))
                except ValueError:
                    continue

        def _device_for_gw(gw: str) -> str | None:
            try:
                _addr = ipaddress.ip_address((gw or "").strip())
            except ValueError:
                return None
            best = None
            for _net, _nm in _iface_nets:
                if _addr in _net and (best is None
                                      or _net.prefixlen > best[0].prefixlen):
                    best = (_net, _nm)
            return best[1] if best else None

        route_entries: list[dict] = []
        seq = 0
        for r in routes:
            if r.get("is_connected"):
                continue
            prefix = r.get("prefix") or ""
            plen = r.get("prefix_len")
            if not prefix:
                continue
            # fw_routes.prefix stores `a.b.c.d/N` (slash already included);
            # only synth the slash for callers that pass a bare network.
            cidr_str = prefix if "/" in prefix else f"{prefix}/{plen}"
            dst = _f.cidr_to_subnet(cidr_str)
            if not dst:
                continue
            is_bh = (r.get("route_type") or "static") == "blackhole"
            if is_bh:
                # FortiOS discard route - `set blackhole enable` flips the
                # entry to a discard; no gateway/device required.
                seq += 1
                entry: dict = {"seq-num": seq, "dst": dst, "blackhole": "enable"}
            else:
                gw = (r.get("next_hop") or "").strip()
                dev = (r.get("interface_name") or "").strip()
                if not dev and gw:
                    dev = _device_for_gw(gw) or ""      # derive from gateway IP
                if not dev:
                    dropped.append(DroppedField(
                        rule_id=cidr_str, field="route_device",
                        reason=f"no egress interface (gateway '{gw or '-'}' not on "
                               "any interface subnet) - FortiOS router/static "
                               "requires 'device'",
                        fallback="route skipped",
                    ))
                    continue
                seq += 1
                entry = {"seq-num": seq, "dst": dst}
                if gw:
                    entry["gateway"] = gw
                entry["device"] = _imap(dev)   # Forti-safe iface name (F7/F8)
            vrf = _vrf_id(r.get("vr_name"))
            if vrf:
                entry["vrf"] = vrf
            # Admin distance - FortiOS default is 10. Emit only when the
            # user has explicitly overridden so an unchanged-route stays
            # at the factory default.
            metric_val = r.get("metric")
            if metric_val is not None:
                entry["distance"] = int(metric_val)
            route_entries.append(entry)
        sections["Static Routes"] = json.dumps(route_entries)

        # ── NAT objects: VIPs + IP-Pools (Phase B4) ──
        # VIPs come back as obj_type='nat_vip' rows; the source-import side
        # filtered to V1-scope (type=static-nat) already, so we just round-
        # trip the value-fields.
        vip_entries: list[dict] = []
        for v in nat_vips or ():
            val = v.get("value") or {}
            ext_ip = (val.get("ext_ip") or "").strip()
            if not ext_ip:
                dropped.append(DroppedField(
                    rule_id=v.get("name") or "?", field="vip",
                    reason="VIP missing extip - not pushable",
                ))
                continue
            mapped_ips = val.get("mapped_ips") or []
            entry = {
                "name":   v.get("name") or "",
                "type":   "static-nat",
                "extip":  ext_ip,
                "mappedip": [{"range": ip} for ip in mapped_ips if ip],
            }
            if val.get("ext_intf"):
                entry["extintf"] = val["ext_intf"]
            if val.get("portforward"):
                entry["portforward"] = "enable"
                if val.get("protocol"):
                    entry["protocol"] = val["protocol"]
                if val.get("ext_port"):
                    entry["extport"] = val["ext_port"]
                if val.get("mapped_port"):
                    entry["mappedport"] = val["mapped_port"]
            desc = (val.get("description") or "").strip()
            if desc:
                entry["comment"] = desc[:255]
            vip_entries.append(entry)
        # Serialized after the central-snat loop below, which may synthesise
        # VIPs for cross-vendor dest-NAT (B-3).
        vip_names = {e["name"] for e in vip_entries}

        ippool_entries: list[dict] = []
        for p in nat_ippools or ():
            val = p.get("value") or {}
            start_ip = (val.get("start_ip") or "").strip()
            end_ip   = (val.get("end_ip") or "").strip()
            if not start_ip or not end_ip:
                dropped.append(DroppedField(
                    rule_id=p.get("name") or "?", field="ippool",
                    reason="IP-pool missing startip/endip - not pushable",
                ))
                continue
            entry = {
                "name":    p.get("name") or "",
                "type":    "overload",
                "startip": start_ip,
                "endip":   end_ip,
            }
            desc = (val.get("description") or "").strip()
            if desc:
                entry["comments"] = desc[:255]
            ippool_entries.append(entry)
        # Serialized after the central-snat loop below, which may synthesise
        # one-to-one pools for static-ip SNAT (B-F3).
        ippool_names = {e["name"] for e in ippool_entries}

        # ── Central-SNAT-Map + synth-SNAT lookup for policy.nat flag ──
        # nat_rules split: synth-SNAT (properties.synthesized=true,
        # nat_type=snat) flips the policy.nat-flag at rule-render time;
        # synth-DNAT is implicit via VIP-ref in policy.dstaddr (no extra
        # central-snat-map row needed). Anything else is an actual
        # central-snat-map rule.
        synth_snat_by_policy: dict[str, dict] = {}
        csnat_entries: list[dict] = []

        # ── B-3: cross-vendor dest-NAT → Forti VIP (+ dstaddr auto-wire below) ──
        # A non-SNAT NAT-rule with a dest-translation becomes a firewall/vip
        # object; the matching security policy's dstaddr is rewired to the VIP
        # in the rule loop (dnat_index). V1 = trans_dst only (source-static-1:1
        # is V2). See project_forti_dnat_vip_active_plan.
        addr_value_lookup = {o.get("name"): (o.get("value") or {}) for o in address_objects}
        svc_value_lookup  = {o.get("name"): (o.get("value") or {}) for o in service_objects}
        dnat_index: dict[str, list[dict]] = {}   # orig_dst name → [{vip, proto, extport}]
        # policy-NAT mode (B-3 Stufe B): orig_src name → [{pool, src_zones,
        # dst_zones, name}] for wiring nat=enable+poolname onto matching policies.
        snat_policy_index: dict[str, list[dict]] = {}

        def _host_ip(ref: str) -> str | None:
            """orig_dst → a single host IP for the VIP extip. Resolves an
            address object (ip-netmask /32 or /<empty>) or a literal IPv4;
            ranges/subnets/fqdn → None (V2 / drop-warn)."""
            v = addr_value_lookup.get(ref)
            if v is None:
                p = (ref or "").split(".")
                return ref if len(p) == 4 and all(x.isdigit() for x in p) else None
            if (v.get("type") or "").lower() in ("ip-netmask", "ipmask"):
                ip, _, mask = (v.get("value") or "").partition("/")
                return ip.strip() if mask.strip() in ("", "32") else None
            return None

        def _svc_pp(ref: str):
            v = svc_value_lookup.get(ref) or {}
            proto = (v.get("protocol") or "").lower()
            port = str(v.get("port") or "").strip()
            return (proto, port) if proto in ("tcp", "udp") and port else None

        def _synth_vip(n: dict):
            nm = n.get("name") or "?"
            od = [d for d in (n.get("orig_dst") or []) if d and d != "any"]
            if len(od) != 1:                                            # Fund S
                dropped.append(DroppedField(rule_id=nm, field="nat_rule",
                    reason="dest-NAT orig_dst is any/multi - not auto-VIP'd (split manually)"))
                return
            extip = _host_ip(od[0])
            if not extip:                                               # Fund A
                dropped.append(DroppedField(rule_id=nm, field="nat_rule",
                    reason=f"dest-NAT orig_dst '{od[0]}' has no single host IP for VIP extip"))
                return
            # mappedip must be an IP, but trans_dst is often an object name
            # (CP/ASA resolve to object names, not literals) → resolve it too.
            mappedip = _host_ip((n.get("trans_dst") or "").strip())
            if not mappedip:
                dropped.append(DroppedField(rule_id=nm, field="nat_rule",
                    reason=f"dest-NAT trans_dst '{n.get('trans_dst')}' has no single "
                           "host IP for VIP mappedip"))
                return
            # Identity / no-translation NAT (extip == mappedip, e.g. ASA VPN
            # exemptions) → a VIP would be a no-op; skip it. (Phase 0 guard.)
            if extip == mappedip:
                dropped.append(DroppedField(rule_id=nm, field="nat_rule",
                    reason="identity NAT (orig==translated) - no real translation, "
                           "no VIP rendered"))
                return
            vip = {"type": "static-nat", "extip": extip,
                   "mappedip": [{"range": mappedip}]}
            proto = extport = None
            tdport = str(n.get("trans_dst_port") or "").strip()
            if tdport:
                svc = [s for s in (n.get("orig_service") or []) if s and s != "any"]
                pp = _svc_pp(svc[0]) if len(svc) == 1 else None
                if not pp:                                              # Fund Q
                    dropped.append(DroppedField(rule_id=nm, field="nat_rule",
                        reason="dest-NAT with port-translation but service is any/multi/"
                               "unresolved - can't map to a Forti VIP portforward"))
                    return
                proto, extport = pp
                vip.update({"portforward": "enable", "protocol": proto,
                            "extport": extport, "mappedport": tdport})
            base = _safe_name(f"vip-{od[0]}" + (f"-{extport}" if extport else ""), _LIM_OBJ)
            name, k = base, 1                                           # Fund T (uniq)
            while name in vip_names:
                k += 1
                name = _safe_name(f"{base}-{k}", _LIM_OBJ)
            vip["name"] = name
            if (n.get("description") or "").strip():
                vip["comment"] = n["description"][:255]
            vip_names.add(name)
            vip_entries.append(vip)
            dnat_index.setdefault(od[0], []).append(
                {"vip": name, "proto": proto, "extport": extport})

        def _synth_static_vip(n: dict):
            # #1: bidirectional source-static-1:1 → an INBOUND VIP (extip=the
            # MAPPED/public side = trans_src, mappedip=the REAL/internal side =
            # orig_src). Full-IP static-nat (no portforward). Additive: for
            # snat-typed rules the central-snat loop still emits the outbound
            # SNAT (B-F3). Indexed on the MAPPED IP for best-effort auto-wire of
            # an inbound rule (often the public IP isn't an object → un-wired →
            # Fund-K warn = wire the inbound policy manually).
            nm = n.get("name") or "?"
            osrc = [s for s in (n.get("orig_src") or []) if s and s != "any"]
            if len(osrc) != 1:
                dropped.append(DroppedField(rule_id=nm, field="nat_rule",
                    reason="bidir-static orig_src is any/multi - not auto-VIP'd"))
                return
            mapped_pub = (n.get("trans_src") or "").strip()
            extip = _host_ip(mapped_pub)        # MAPPED/public
            mappedip = _host_ip(osrc[0])        # REAL/internal
            if not extip or not mappedip:
                dropped.append(DroppedField(rule_id=nm, field="nat_rule",
                    reason="bidir-static trans_src/orig_src has no single host IP for VIP"))
                return
            if extip == mappedip:
                return                          # identity → no real translation
            base = _safe_name(f"vip-{mapped_pub}", _LIM_OBJ)
            name, k = base, 1
            while name in vip_names:
                k += 1
                name = _safe_name(f"{base}-{k}", _LIM_OBJ)
            vip = {"name": name, "type": "static-nat", "extip": extip,
                   "mappedip": [{"range": mappedip}]}
            if (n.get("description") or "").strip():
                vip["comment"] = n["description"][:255]
            vip_names.add(name)
            vip_entries.append(vip)
            dnat_index.setdefault(mapped_pub, []).append(
                {"vip": name, "proto": None, "extport": None})

        for n in nat_rules or ():
            props = n.get("properties")
            if isinstance(props, str):
                try:
                    props = json.loads(props)
                except Exception:
                    props = {}
            props = props or {}
            if props.get("synthesized"):
                if n.get("nat_type") == "snat":
                    src_name = props.get("source_rule_name")
                    if src_name:
                        synth_snat_by_policy[src_name] = {
                            "ippool_ref": props.get("ippool_ref"),
                            # Pass through the full props dict so Phase-D
                            # vendor-slots (forti_fixedport, forti_natoutbound)
                            # can be applied to the policy push.
                            "properties": props,
                        }
                # synth-dnat falls through (VIP-ref handles it)
                continue

            # #1: bidirectional source-static-1:1 (trans_src + static-ip, no
            # dest-condition, pa_bi_directional or ASA-static) → INBOUND VIP,
            # additive. For snat-typed rules the central-snat loop below still
            # emits the outbound SNAT. Dest-scoped statics fall through to a
            # drop-warn (a VIP can't carry a dest-condition).
            tstype = (n.get("trans_src_type") or "").lower()
            od_concrete = [d for d in (n.get("orig_dst") or []) if d and d != "any"]
            is_bidir_static = (
                bool((n.get("trans_src") or "").strip()) and tstype == "static-ip"
                and not od_concrete
                and (props.get("pa_bi_directional") or n.get("nat_type") == "static"))
            if is_bidir_static and not n.get("disabled"):
                _synth_static_vip(n)

            if n.get("nat_type") != "snat":
                # central-snat-map is SNAT-only. V1 (B-3): a non-SNAT rule with
                # a dest-translation → Forti VIP (auto-wired below).
                if n.get("disabled"):
                    continue                                            # Fund W
                if (n.get("trans_dst") or "").strip():
                    _synth_vip(n)
                elif is_bidir_static:
                    pass            # inbound VIP synth'd above (no central-snat for nat_type=static)
                else:
                    dropped.append(DroppedField(
                        rule_id=n.get("name") or "?", field="nat_rule",
                        reason=f"nat_type={n.get('nat_type')!r} without usable translation "
                               "not pushable to Forti (dest-scoped static / exemption)",
                    ))
                continue
            orig_src = n.get("orig_src") or ["any"]
            orig_dst = n.get("orig_dst") or ["any"]
            src_zones = n.get("src_zones") or ["any"]
            dst_zones = n.get("dst_zones") or ["any"]
            # Source-translation pool - shared by both NAT modes:
            #   interface-address → None (egress IP); static-ip → synth a
            #   one-to-one ippool; dynamic/other → reference verbatim. (B-F2/B-F3)
            tstype = (n.get("trans_src_type") or "").lower()
            tsrc   = (n.get("trans_src") or "").strip()
            pool_name = None
            if tstype == "static-ip" and tsrc:
                # tsrc is a literal IP/range OR an address-OBJECT NAME (CP/ASA
                # sources resolve to names - splitting 'core-h-011' on '-'
                # produced startip='core', QA finding). Resolve the object
                # first; treat as literal only when it parses as IPv4.
                def _lit_ip(x: str) -> bool:
                    p = x.split(".")
                    return len(p) == 4 and all(q.isdigit() and int(q) <= 255 for q in p)
                startip = endip = None
                _v = addr_value_lookup.get(tsrc) or {}
                _vt = (_v.get("type") or "").lower()
                if _vt in ("ip-netmask", "ipmask"):
                    _ip, _, _mask = (_v.get("value") or "").partition("/")
                    if _mask.strip() in ("", "32"):
                        startip = endip = _ip.strip()
                elif _vt == "ip-range":
                    _s, _, _e = (_v.get("value") or "").partition("-")
                    if _s.strip() and _e.strip():
                        startip, endip = _s.strip(), _e.strip()
                elif tsrc not in addr_value_lookup:
                    if "-" in tsrc:
                        _s, _e = tsrc.split("-", 1)
                        if _lit_ip(_s.strip()) and _lit_ip(_e.strip()):
                            startip, endip = _s.strip(), _e.strip()
                    elif _lit_ip(tsrc):
                        startip = endip = tsrc
                if not startip:
                    dropped.append(DroppedField(
                        rule_id=n.get("name") or "?", field="nat_rule",
                        reason=f"static-SNAT trans_src {tsrc!r} doesn't resolve to a "
                               "host IP or range (subnet/fqdn/unknown object) - "
                               "rule skipped"))
                    continue
                pool_name = _safe_name(f"snatpool-{tsrc}", _LIM_OBJ)
                if pool_name not in ippool_names:
                    ippool_entries.append({
                        "name": pool_name, "type": "one-to-one",
                        "startip": startip, "endip": endip,
                    })
                    ippool_names.add(pool_name)
            elif tstype != "interface-address" and tsrc:
                # Dynamic SNAT: tsrc is a REAL ippool only for Forti sources -
                # CP hide-behind / PA dynamic-ip-and-port resolve to an ADDRESS
                # object name, and the policy's poolname datasource requires an
                # ippool → synth an overload pool from the address value
                # (QA finding, 'core-h-025').
                if tsrc in ippool_names:
                    pool_name = tsrc
                else:
                    _v = addr_value_lookup.get(tsrc) or {}
                    _vt = (_v.get("type") or "").lower()
                    startip = endip = None
                    if _vt in ("ip-netmask", "ipmask"):
                        _ip, _, _mask = (_v.get("value") or "").partition("/")
                        if _mask.strip() in ("", "32"):
                            startip = endip = _ip.strip()
                    elif _vt == "ip-range":
                        _s, _, _e = (_v.get("value") or "").partition("-")
                        if _s.strip() and _e.strip():
                            startip, endip = _s.strip(), _e.strip()
                    if startip:
                        pool_name = _safe_name(f"snatpool-{tsrc}", _LIM_OBJ)
                        if pool_name not in ippool_names:
                            ippool_entries.append({
                                "name": pool_name, "type": "overload",
                                "startip": startip, "endip": endip,
                            })
                            ippool_names.add(pool_name)
                    else:
                        dropped.append(DroppedField(
                            rule_id=n.get("name") or "?", field="nat_rule",
                            reason=f"dynamic-SNAT trans_src {tsrc!r} is neither an "
                                   "ippool nor a resolvable host/range address - "
                                   "rule skipped"))
                        continue

            if nat_mode == "policy":
                # policy-NAT: no central-snat-map. Record so the rule loop sets
                # nat=enable (+ poolname) on the matching outbound policy. (B2)
                if not n.get("disabled"):
                    for src in orig_src:
                        snat_policy_index.setdefault(src, []).append({
                            "pool": pool_name, "src_zones": src_zones,
                            "dst_zones": dst_zones, "name": n.get("name") or "?"})
                continue

            # central-snat-map mode. Zoned member-ifaces must surface as their
            # zone (same FortiOS constraint as policy srcintf), deduped.
            def _csnat_intf(zlist):
                seen: set[str] = set()
                out: list[dict] = []
                for z in zlist:
                    nm = iface_to_zone.get(z, z)
                    if nm not in seen:
                        seen.add(nm)
                        out.append({"name": nm})
                return out
            def _csnat_addr(names):
                # FortiOS address wildcard is 'all' - a literal 'any' (or an
                # empty list, e.g. an ASA source-NAT without destination
                # clause) fails the datasource check ("value parse error
                # before 'any'", asa2fgt finding 2026-09-01). Interfaces are
                # different: central-snat srcintf/dstintf DO accept 'any'
                # (live-verified).
                out, seen = [], set()
                for a in names:
                    nm2 = "all" if (not a or a == "any") else a
                    if nm2 not in seen:
                        seen.add(nm2)
                        out.append({"name": nm2})
                return out or [{"name": "all"}]

            entry = {
                "policyid": (n.get("position") or 0) + 1,
                "srcintf":  _csnat_intf(src_zones),
                "dstintf":  _csnat_intf(dst_zones),
                "orig-addr": _csnat_addr(orig_src),
                "dst-addr":  _csnat_addr(orig_dst),
                "nat":      "disable" if n.get("disabled") else "enable",
            }
            if pool_name:
                entry["nat-ippool"] = [{"name": pool_name}]
            # FortiOS central-snat-map schema lists zero negate-fields. Warn per flag.
            for aspect in ("negate_source", "negate_destination", "negate_service"):
                if n.get(aspect):
                    dropped.append(DroppedField(
                        rule_id=n.get("name") or "?", field=aspect,
                        reason="FortiOS central-snat-map does not support negation",
                        fallback="ignored",
                    ))
            comments = (n.get("description") or "").strip()
            if comments:
                entry["comments"] = comments[:1023]
            csnat_entries.append(entry)
        sections["Central SNAT"] = json.dumps(csnat_entries)
        sections["IP Pools"] = json.dumps(ippool_entries)
        # FortiOS firewall/vip requires extintf ("Attribute 'extintf' MUST be
        # set", -56). Default to "any" (match all incoming interfaces) for every
        # VIP - round-tripped + B-3 synthesised - that didn't carry an explicit
        # external interface.
        for _e in vip_entries:
            _e.setdefault("extintf", "any")
        sections["VIPs"] = json.dumps(vip_entries)   # incl. B-3 synthesised VIPs

        # A FortiGate VIP and an address object cannot share a name (errcode
        # -163). When a VIP we create collides with a same-named address - e.g.
        # a round-tripped VIP-external-IP host (Forti VIP → CP host named after
        # it → re-imported as an address → re-derived here as a VIP) - the VIP
        # is the canonical dest object (a policy referencing that name resolves
        # to the VIP on FortiGate), so drop the redundant address.
        _addr_vip_clash = [a for a in addr_entries if a.get("name") in vip_names]
        if _addr_vip_clash:
            for a in _addr_vip_clash:
                dropped.append(DroppedField(
                    rule_id=a.get("name"), field="address",
                    reason="name collides with a same-named VIP (FortiOS forbids "
                           "it); the VIP is the dest object policies resolve to",
                    fallback="redundant address dropped"))
            addr_entries = [a for a in addr_entries if a.get("name") not in vip_names]
            sections["Address Objects"] = json.dumps(addr_entries)

        # ── SSL/SSH Inspection (decryption) ──
        # Forti decryption is a per-policy ssl-ssh-profile ATTACH (UTM Profiles
        # enrichment), NOT a recreatable rulebase - like every other profile type
        # in Gateshift, profiles are referenced by name, never created. So there is
        # no SSL push section for a FortiGate target. (Forti as a SOURCE derives
        # decryption rules from deep-inspection policies - collector side.)

        # ── Rules ──
        prefix = (settings.get("rule_prefix") or "Gateshift-").strip()
        log_traffic = (settings.get("log_traffic") or "all").strip()
        comment_tag = (settings.get("comment_tag") or "[Gateshift]").strip()

        def _resolve_iface_ref(ref: str, rule_id: str) -> str:
            if ref == "any" or not ref:
                return "any"
            renamed = zone_rename.get(ref, ref)
            # A zoned interface must surface as its zone (FortiOS rejects the
            # member iface directly in a policy).
            if renamed in iface_to_zone:
                return iface_to_zone[renamed]
            if renamed in valid_ifaces:
                return renamed
            dropped.append(DroppedField(
                rule_id=rule_id, field="interface_ref",
                reason=f"'{ref}' not in zones/interfaces - falling back to 'any'",
                fallback="any",
            ))
            return "any"

        def _iface_ref_list(zlist, rule_id):
            """Resolve a src/dst zone-or-iface list → deduped Forti intf refs.
            Dedup matters: several zoned member-ifaces (port1, 300) collapse to
            the same zone (trust) and FortiOS rejects a duplicated srcintf."""
            seen: set[str] = set()
            out: list[dict] = []
            for z in (zlist or ["any"]):
                nm = _resolve_iface_ref(z, rule_id)
                if nm not in seen:
                    seen.add(nm)
                    out.append({"name": nm})
            return out or [{"name": "any"}]

        def _resolve_addr_ref(ref: str, rule_id: str) -> str:
            if ref == "any" or not ref:
                return "all"
            renamed = addr_rename.get(ref, grp_addr_rename.get(
                ref, addr_literal.get(ref, ref)))
            if renamed in valid_addrs:
                return renamed
            dropped.append(DroppedField(
                rule_id=rule_id, field="address_ref",
                reason=f"'{ref}' not in addresses/groups - falling back to 'all'",
                fallback="all",
            ))
            return "all"

        # PBF (router/policy) renders src/dst as INLINE subnets, not address-object
        # refs - so it's self-contained and carries NO cross-strand dependency on
        # the policy-strand address objects (which are a separate push). Resolve
        # each agnostic ref to CIDR subnet(s): object → its value; group → member
        # subnets (recursive, cycle-safe); ip-range → CIDR-decomposed; fqdn /
        # missing → drop+warn (a router/policy subnet table can't hold them).
        # CIDR form 'a.b.c.d/N' - NOT cidr_to_subnet's space-mask, which FortiOS
        # rejects on router/policy with -45 (live schema-probed 2026-06-11).
        addr_grp_lookup = {g.get("name"): (g.get("value") or {})
                           for g in address_groups}

        def _value_to_subnets(v: dict, ref: str, rule_id: str) -> list[str]:
            t = (v.get("type") or "").lower()
            raw = (v.get("value") or "").strip()
            if t in ("ip-netmask", "ipmask"):
                try:
                    return [str(ipaddress.ip_network(raw, strict=False))]
                except ValueError:
                    pass
            elif t == "ip-range" and "-" in raw:
                start, _, end = raw.partition("-")
                try:
                    return [str(n) for n in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(start.strip()),
                        ipaddress.IPv4Address(end.strip()))]
                except ValueError:
                    pass
            dropped.append(DroppedField(
                rule_id=rule_id, field="pbf_address",
                reason=f"'{ref}' (type {t or '?'}) can't be a router/policy subnet"))
            return []

        def _resolve_addr_subnets(ref: str, rule_id: str,
                                  _seen: set | None = None) -> list[str]:
            if not ref or ref == "any":
                return []
            if ref in addr_value_lookup:
                return _value_to_subnets(addr_value_lookup[ref], ref, rule_id)
            if ref in addr_grp_lookup:
                _seen = _seen or set()
                if ref in _seen:                     # group cycle → stop
                    return []
                _seen.add(ref)
                out: list[str] = []
                for m in (addr_grp_lookup[ref].get("members") or []):
                    out.extend(_resolve_addr_subnets(m, rule_id, _seen))
                return out
            # Not an object/group → accept a bare IP/CIDR literal, else warn.
            try:
                return [str(ipaddress.ip_network(ref, strict=False))]
            except ValueError:
                dropped.append(DroppedField(
                    rule_id=rule_id, field="pbf_address",
                    reason=f"'{ref}' is not an address object/group or IP literal"))
                return []

        sections["Policy Routes"] = _f.render_policy_routes(
            list(pbf_rules or []), dropped, resolve_subnets=_resolve_addr_subnets,
            iface_map=_iface_map)

        def _resolve_svc_ref(ref: str, rule_id: str) -> str:
            if ref == "any" or not ref:
                return "ALL"
            renamed = svc_rename.get(ref, grp_svc_rename.get(ref, ref))
            # We accept unknown service names (could be Forti builtin like HTTP,
            # DNS, …). Push surfaces invalid names as errcode -3.
            return renamed

        # ── B-3 phase 2: auto-wire a dest-NAT VIP into the matching allow
        # policy's dstaddr. A dst ref that equals a synthesised VIP's orig_dst
        # is rewritten to the VIP name when the rule allows it and the service
        # matches (portforward VIP → same proto/port; full-IP VIP → any). One
        # rule matching multiple VIPs is ambiguous → leave + warn (Fund U).
        wired_vips: set[str] = set()
        snat_wired: set[str] = set()   # B2: SNAT-rule names wired onto a policy

        def _vip_matches_service(c: dict, rule: dict) -> bool:
            if c["extport"] is None:                 # full-IP VIP → any service
                return True
            return ((rule.get("proto") or "").lower() == c["proto"]
                    and str(rule.get("port_from") or "").strip() == c["extport"])

        def _wire_dst(ref: str, rule_id: str, rule: dict) -> str:
            cands = dnat_index.get(ref) or []
            act = (rule.get("action") or "permit").lower()
            if not cands or act not in ("permit", "allow", "accept", "pass"):
                return _resolve_addr_ref(ref, rule_id)          # Fund R: allow-only
            match = [c for c in cands if _vip_matches_service(c, rule)]
            if len(match) == 1:
                wired_vips.add(match[0]["vip"])
                return match[0]["vip"]
            if len(match) > 1:                                  # Fund U: ambiguous
                dropped.append(DroppedField(
                    rule_id=rule_id, field="dstaddr",
                    reason=f"dest '{ref}' matches {len(match)} dest-NAT VIPs - "
                           "ambiguous, not auto-wired (set dstaddr→VIP manually)"))
            return _resolve_addr_ref(ref, rule_id)              # 0 match → leave as-is

        rule_entries: list[dict] = []
        seen_rule_names: dict[str, int] = {}
        for i, rule in enumerate(rules):
            rule_id = str(rule.get("rule_name") or rule.get("id") or f"#{i+1}")

            for fld in _UNSUPPORTED_RULE_FIELDS:
                if rule.get(fld):
                    dropped.append(DroppedField(
                        rule_id=rule_id, field=fld,
                        reason="not rendered by fortinet driver V1",
                    ))

            # Tags (effective from override or source) - Forti policies
            # have no general-purpose tag concept (schema-verified).
            # Drop each tag-bearing field with a warn so user sees the
            # leakage on cross-vendor PA→Forti / CP→Forti pushes.
            for tag_field in ("pa_tags", "cp_tags", "pa_group_tag", "import_tags", "tags"):
                v = rule.get(tag_field)
                if v and v not in ([], "", None, "[]"):
                    dropped.append(DroppedField(
                        rule_id=rule_id, field=tag_field,
                        reason="FortiGate policies have no tag concept",
                        fallback="ignored",
                    ))

            # application-default App-IDs the resolver couldn't map to ports
            # (icmp-only / unmapped) - surfaced so the ALL fallback is visible.
            unresolved_app = rule.get("_appdef_unresolved")
            if unresolved_app:
                dropped.append(DroppedField(
                    rule_id=rule_id, field="service",
                    reason="application-default not resolvable for: "
                           + ", ".join(unresolved_app),
                    fallback="service left as ALL - set manually",
                ))

            base_name = rule.get("rule_name") or f"{prefix}{i+1:03d}"
            rule_name = _safe_name(f"{prefix}{base_name}" if not base_name.startswith(prefix) else base_name, _LIM_POLICY)
            if rule_name in seen_rule_names:
                seen_rule_names[rule_name] += 1
                suffix = f"-{seen_rule_names[rule_name]}"
                rule_name = _safe_name(rule_name[: _LIM_POLICY - len(suffix)] + suffix, _LIM_POLICY)
            else:
                seen_rule_names[rule_name] = 0

            srcintf = _iface_ref_list(rule.get("src_zones"), rule_id)
            dstintf = _iface_ref_list(rule.get("dst_zones"), rule_id)

            def _addr_list(names: list[str]) -> list[dict]:
                # Dedupe (two refs may resolve to the same renamed object) and
                # COLLAPSE on 'all': FortiOS rejects a policy that mixes `all`
                # with other addresses (-7, "'all' cannot be combined with
                # other addresses") - which is exactly what the
                # falling-back-to-'all' path produced on a multi-address rule
                # (logs2fgt finding 2026-09-01). 'all' is the superset anyway.
                out, seen = [], set()
                for nm in names:
                    if nm not in seen:
                        seen.add(nm)
                        out.append({"name": nm})
                if len(out) > 1 and any(e["name"] == "all" for e in out):
                    return [{"name": "all"}]
                return out or [{"name": "all"}]

            srcaddr = _addr_list([_resolve_addr_ref(a, rule_id) for a in (rule.get("sources") or ["any"])])
            dstaddr = _addr_list([_wire_dst(a, rule_id, rule) for a in (rule.get("destinations") or ["any"])])
            service = [{"name": _resolve_svc_ref(s, rule_id)} for s in (rule.get("services") or ["any"])] or [{"name": "ALL"}]

            action_raw = (rule.get("action") or "permit").lower()
            if action_raw in ("permit", "allow", "accept", "pass"):
                action = "accept"
            else:
                action = "deny"

            comments_src = rule.get("description") or rule.get("rule_name") or ""
            comments = f"{comment_tag} {comments_src}".strip()[:1023]

            rule_log_traffic = (rule.get("log_traffic") or log_traffic or "all").strip().lower()
            if rule_log_traffic not in ("all", "utm", "disable"):
                rule_log_traffic = log_traffic

            entry: dict = {
                "policyid":  i + 1,
                "name":      rule_name,
                "srcintf":   srcintf,
                "dstintf":   dstintf,
                "srcaddr":   srcaddr,
                "dstaddr":   dstaddr,
                "service":   service,
                "action":    action,
                # Phase 1b: rule.schedule kommt aus rules_query COALESCE
                # (schovr.schedule_name, r.schedule). NULL = 'always'
                # (Forti default).
                "schedule":  (rule.get("schedule") or "").strip() or "always",
                "logtraffic": rule_log_traffic,
                "nat":       "disable",
                "status":    "disable" if rule.get("disabled") else "enable",
                "comments":  comments,
            }
            # B2: policy-NAT mode - wire SNAT onto this policy when one of its
            # sources matches a source-NAT rule (src-zone overlap). nat=enable
            # (+ poolname for static-ip/pool; interface-address → egress IP).
            # Ambiguous (different pools) → leave + warn.
            _act = (rule.get("action") or "permit").lower()
            if (nat_mode == "policy" and snat_policy_index
                    and _act in ("permit", "allow", "accept", "pass")
                    and not rule.get("negate_source")):
                _rz = set(rule.get("src_zones") or [])
                _dz = set(rule.get("dst_zones") or [])
                def _zov(a, b):
                    return bool(set(a) & b) or "any" in a or "any" in b
                _matches = [c for s in (rule.get("sources") or [])
                            for c in snat_policy_index.get(s, [])
                            if _zov(c["src_zones"], _rz) and _zov(c["dst_zones"], _dz)]
                if _matches:
                    _pools = {c["pool"] for c in _matches}
                    if len(_pools) == 1:
                        entry["nat"] = "enable"
                        _p = next(iter(_pools))
                        if _p:
                            entry["ippool"] = "enable"
                            entry["poolname"] = [{"name": _p}]
                        for c in _matches:
                            snat_wired.add(c["name"])
                    else:
                        dropped.append(DroppedField(
                            rule_id=rule_name, field="nat",
                            reason=f"policy-NAT: {len(_pools)} different SNAT pools match this "
                                   "policy's source - ambiguous, nat not auto-set (set manually)"))
            # Per-rule negate flags - FortiOS expects "enable"/"disable" strings
            # (V0 lab-probe). Default disable; only flip when override-resolved
            # rule.negate_* is truthy.
            if rule.get("negate_source"):
                entry["srcaddr-negate"] = "enable"
            if rule.get("negate_destination"):
                entry["dstaddr-negate"] = "enable"
            if rule.get("negate_service"):
                entry["service-negate"] = "enable"

            # Source-User identity refs (Phase 2 User/Groups, Option C).
            # Forti splits identities into two policy fields - users[] and
            # groups[] - so we route by kind. kind=user → users; group →
            # groups; unknown → groups (AD-refs are almost always groups);
            # keyword (PA known-user/unknown/pre-logon) has no Forti equiv
            # → skipped. Names must exist as user/group objects at the
            # target (User's responsibility - ref-only migration).
            iden_users: list[dict] = []
            iden_groups: list[dict] = []
            for idn in (rule.get("source_identities") or []):
                nm = (idn.get("name") or "").strip()
                if not nm:
                    continue
                kind = (idn.get("kind") or "unknown").lower()
                if kind == "user":
                    iden_users.append({"name": nm})
                elif kind in ("group", "unknown"):
                    iden_groups.append({"name": nm})
                # keyword → no Forti equivalent, skip
            if iden_users:
                entry["users"] = iden_users
            if iden_groups:
                entry["groups"] = iden_groups

            # Phase-B4: a synth-SNAT NAT-rule for this policy flips nat=enable
            # (and optionally ippool/poolname). Looked up by source_rule_name
            # set in main._run_fortigate_import on the synth marker.
            src_rule_name = rule.get("rule_name") or ""
            synth_snat = synth_snat_by_policy.get(src_rule_name)
            if synth_snat:
                entry["nat"] = "enable"
                pool_ref = synth_snat.get("ippool_ref")
                if pool_ref:
                    entry["ippool"] = "enable"
                    entry["poolname"] = [{"name": pool_ref}]
                # Phase-D: nat_schemas forti_* slots on the synth-SNAT row
                # carry over to the policy push. fixedport is the common
                # one ("keep source port unchanged"); natoutbound is the
                # outbound flag, rarely set but supported.
                synth_props = synth_snat.get("properties") or {}
                if synth_props.get("forti_fixedport"):
                    entry["fixedport"] = "enable"
                if synth_props.get("forti_natoutbound"):
                    entry["natoutbound"] = "enable"
            if rule_log_traffic != "disable":
                if rule.get("log_start"):
                    entry["logtraffic-start"] = "enable"
                if rule.get("capture_packet"):
                    entry["capture-packet"] = "enable"

            # UTM profile slots - V2 enrichment. Each slot is independent:
            # column NULL or absent → don't emit (FortiOS default kicks in).
            # If any UTM slot has a value, flip utm-status=enable so the
            # policy actually consults the profile (default is disable).
            utm_fields = [
                ("av_profile",        "av-profile"),
                ("webfilter_profile", "webfilter-profile"),
                ("dnsfilter_profile", "dnsfilter-profile"),
                ("ips_sensor",        "ips-sensor"),
                ("application_list",  "application-list"),
                ("ssl_ssh_profile",   "ssl-ssh-profile"),
            ]
            utm_emitted = False
            for col, api_field in utm_fields:
                val = (rule.get(col) or "").strip()
                if not val:
                    continue
                entry[api_field] = val
                utm_emitted = True
            if utm_emitted:
                entry["utm-status"] = "enable"
            rule_entries.append(entry)
        sections["Rules"] = json.dumps(rule_entries)

        # B-3 (Fund K): a synthesised VIP with no matching allow-policy is inert
        # on Forti (no DNAT happens) - surface it so the user wires it manually.
        for _cands in dnat_index.values():
            for _c in _cands:
                if _c["vip"] not in wired_vips:
                    dropped.append(DroppedField(
                        rule_id=_c["vip"], field="vip",
                        reason="dest-NAT VIP created but no matching allow-policy - "
                               "set a policy dstaddr to this VIP manually",
                    ))

        # B2 policy-NAT: a source-NAT rule with no matching outbound policy isn't
        # applied (nat lives on the policy) - surface it.
        _seen_snat = set()
        for _cands in snat_policy_index.values():
            for _c in _cands:
                if _c["name"] not in snat_wired and _c["name"] not in _seen_snat:
                    _seen_snat.add(_c["name"])
                    dropped.append(DroppedField(
                        rule_id=_c["name"], field="nat_rule",
                        reason="policy-NAT: source-NAT has no matching outbound policy - "
                               "set nat=enable on the relevant policy manually",
                    ))

        # ── IPSec VPN (CE plan P3b) ──────────────────────────────────
        # phase1-interface (gateway + IKE crypto inline) + phase2-interface
        # (IPsec crypto inline). The referenced crypto profiles are looked up by
        # name + inlined into the proposal. The Forti tunnel-iface is implicit
        # (created by phase1) - no separate iface entry.
        ike_by_name = {p.get("name"): (p.get("value") or {})
                       for p in (ike_crypto_profiles or [])}
        ipsec_by_name = {p.get("name"): (p.get("value") or {})
                         for p in (ipsec_crypto_profiles or [])}
        p1_entries, p2_entries = _f.render_vpn(
            list(vpn_tunnels or []), ike_by_name, ipsec_by_name, dropped)
        sections["VPN Phase1"] = json.dumps(p1_entries)
        sections["VPN Phase2"] = json.dumps(p2_entries)

        return sections, [d.to_dict() for d in dropped]

    # ── Push ─────────────────────────────────────────────────────

    # Soft-fail errcodes during DELETE (treat as "couldn't delete, continue"):
    #   -3  : entry not found / read-only
    #   -23 : referenced elsewhere
    #   -37 : system entry - operation prevented (vendor builtins)
    #   -61 : static table entry - cannot delete
    #   -534: read-only system entry
    #   -537: object in use
    #   -651: protected/predefined entry
    _DELETE_SOFT_ERRCODES = (-3, -23, -37, -61, -534, -537, -651)
    # Soft-fail errcodes during PUSH (vendor already provides this name -
    # skip silently). Excludes -3 (referenced object missing) and -23
    # (referenced) since those are hard dependency errors in push context.
    # -5 (already exists) is handled separately via PUT fallback.
    _PUSH_READONLY_ERRCODES = (-37, -61, -534, -537, -651)

    # Delete top-down, push bottom-up (reversed). For Interfaces, only the
    # deletable_types entries get DELETEd; physical IFs are modified via PUT
    # in the push phase. Mgmt iface is excluded from both phases by name.
    _PUSH_STEPS = (
        # Top of the list runs FIRST on DELETE (top-down) and LAST on push
        # (bottom-up reversed). Place NAT-rulebases above Rules so they get
        # deleted first; place NAT-objects below Rules so they're pushed
        # before the policies that reference them (VIP-ref in policy.dstaddr,
        # poolname-ref in policy.poolname).
        _PushStep("Central SNAT",    "/firewall/central-snat-map", "Central SNAT",  "policyid", "policy",  None),
        _PushStep("Rules",           "/firewall/policy",         "Rules",           "policyid", "policy",  None),
        _PushStep("Address Groups",  "/firewall/addrgrp",        "Address Groups",  "name",     "policy",  None),
        _PushStep("Service Groups",  "/firewall.service/group",  "Service Groups",  "name",     "policy",  None),
        _PushStep("VIPs",            "/firewall/vip",            "VIPs",            "name",     "policy",  None),
        _PushStep("IP Pools",        "/firewall/ippool",         "IP Pools",        "name",     "policy",  None),
        _PushStep("Address Objects", "/firewall/address",        "Address Objects", "name",     "policy",  None),
        _PushStep("Service Objects", "/firewall.service/custom", "Service Objects", "name",     "policy",  None),
        # Phase 1a: URL Filter tables - Custom URL Categories.
        # Push-bottom-up: pushed nach Service-Objects, vor anything die
        # sie konsumieren (Webfilter-Profile sind out-of-scope; Catalog
        # liegt als Building-Block am Target).
        # webfilter/urlfilter is keyed by a NUMERIC id, not by name - a
        # delete addressed by name 404s (QA finding, FGCP leg). Pushes still
        # POST with id 0 so FortiOS assigns one.
        _PushStep("URL Categories", "/webfilter/urlfilter",      "URL Categories",   "id",       "policy",  None),
        # Phase 1b: Schedule-Subtypes split auf drei REST-Endpoints.
        # NOTE ON ORDER: the push phase walks this list in REVERSE, so a
        # container must be listed BEFORE the objects it references. The
        # schedule GROUP references recurring/onetime schedules and therefore
        # has to sit above them here - listed after them it was pushed first
        # and FortiOS rejected the member ("entry not found in datasource",
        # QA finding on the FGCP leg). Same reason Groups precede Objects.
        _PushStep("Schedules Group",     "/firewall.schedule/group",     "Schedules Group",     "name", "policy", None),
        _PushStep("Schedules Recurring", "/firewall.schedule/recurring", "Schedules Recurring", "name", "policy", None),
        _PushStep("Schedules Onetime",   "/firewall.schedule/onetime",   "Schedules Onetime",   "name", "policy", None),
        _PushStep("Zones",           "/system/zone",             "Zones",           "name",     "network", None),
        _PushStep("Static Routes",   "/router/static",           "Static Routes",   "seq-num",  "network", None),
        # PBF (policy-routes) → router/policy, network strand (router-config,
        # not firewall-policy). Audit: Forti PBF push-strand is Network.
        _PushStep("Policy Routes",   "/router/policy",           "Policy Routes",   "seq-num",  "network", None),
        # IPSec VPN (CE plan P3b) - phase2 references phase1name → phase2 deleted
        # first (top-down), phase1 pushed first (bottom-up). Both below the routes
        # so a route-via-tunnel finds its phase1-created iface; both above
        # Interfaces so phase1's local-iface (a system iface) exists first.
        _PushStep("VPN Phase2",      "/vpn.ipsec/phase2-interface", "VPN Phase2",   "name",     "network", None),
        _PushStep("VPN Phase1",      "/vpn.ipsec/phase1-interface", "VPN Phase1",   "name",     "network", None),
        _PushStep("Interfaces",      "/system/interface",        "Interfaces",      "name",     "network", frozenset({"vlan", "loopback", "aggregate"})),
    )

    # UI-label → internal section names for per-section push toggles.
    # Forti-specific label shape: `/firewall/policy` is unified
    # Security+NAT (NAT flag per policy entry), hence a single "Rules"
    # label instead of CP/PA's Security/NAT split. Central SNAT is a
    # separate endpoint and gets its own label. NAT objects (VIPs + IP
    # pools) are Forti-exclusive concepts, also their own label.
    # Schedules bundles the three sub-endpoints (recurring/onetime/group)
    # behind one label.
    _SECTION_LABELS: dict[str, list[tuple[str, str, list[str]]]] = {
        "policy": [
            ("address_objects", "Address Objects",
                ["Address Objects", "Address Groups"]),
            ("services",        "Services",
                ["Service Objects", "Service Groups"]),
            ("nat_objects",     "NAT Objects (VIPs + IP Pools)",
                ["VIPs", "IP Pools"]),
            ("url_categories",  "URL Categories",  ["URL Categories"]),
            ("schedules",       "Schedules",
                ["Schedules Recurring", "Schedules Onetime", "Schedules Group"]),
            ("rules",           "Rules (Security + NAT unified)", ["Rules"]),
            ("central_snat",    "Central SNAT",    ["Central SNAT"]),
        ],
        # V1: Network atomic.
        "network": [],
    }

    @classmethod
    def _resolve_skip_internal(cls, strand: str,
                                skip_labels: set[str] | None) -> set[str]:
        if not skip_labels:
            return set()
        out: set[str] = set()
        for key, _ui, internals in cls._SECTION_LABELS.get(strand, []):
            if key in skip_labels:
                out.update(internals)
        return out

    @staticmethod
    def _section_entries(config: dict, key: str) -> list[dict]:
        """Parse a rendered config section (a JSON list of entries)."""
        raw = (config.get(key) or "").strip()
        if not raw:
            return []
        try:
            v = json.loads(raw)
            return v if isinstance(v, list) else []
        except Exception:
            return []

    def _active_steps(self, config: dict, strand: str, skip_sections) -> list:
        """The _PUSH_STEPS (in order) for this strand that carry data + aren't
        skipped. Shared by the direct REST push + the enterprise manager backends."""
        skip_internal = self._resolve_skip_internal(strand, skip_sections)
        return [s for s in self._PUSH_STEPS
                if s.strand == strand and s.section_key not in skip_internal
                and self._section_entries(config, s.section_key)]

    def push(
        self,
        *,
        device: dict,
        config: dict[str, str],
        strand: str = "policy",
        skip_sections: set[str] | None = None,
        mgmt_override: bool = False,   # per-push opt-in (typed confirm), not persisted
        vpn_certs: dict | None = None,  # VPN identity certs - consumed in CR-3
    ) -> Iterator[StepResult]:
        base = _cmdb_base(device)
        token = device.get("api_key") or ""
        if not token:
            yield StepResult(step="auth", success=False, detail="No API key configured")
            return
        vdom = _f.vdom_for(device)
        verify = _verify_tls(device)
        mgmt_iface = _mgmt_iface_name(device)

        active = self._active_steps(config, strand, skip_sections)
        if not active:
            yield StepResult(step="validate", success=False,
                             detail=f"No {strand}-strand sections with data to push")
            return

        # ── FGCP cluster awareness ──
        # Read the HA context once: gate on being the PRIMARY (cmdb writes must
        # land there) and collect the HA-reserved interfaces (heartbeat + ha-mgmt)
        # the network wipe must never touch. Standalone box / any read error →
        # enabled=False → no gate, no extra protection (the plain mgmt_iface
        # exclusion below still applies). Both strands hit the primary.
        ha_ctx = _read_ha_context(device, base, token, vdom, verify)
        ha_reserved: set[str] = ha_ctx["reserved"] if ha_ctx["enabled"] else set()
        if ha_ctx["enabled"] and not ha_ctx["is_primary"]:
            yield StepResult(step="HA primary-check", success=False,
                             detail=ha_ctx["detail"] or "reached node is a cluster subordinate")
            return
        if ha_ctx["enabled"] and ha_ctx.get("dhcp_reserved"):
            yield StepResult(
                step="HA cluster warning", success=True,
                detail=("HA-reserved interface(s) "
                        f"{', '.join(ha_ctx['dhcp_reserved'])} run DHCP (typical "
                        "for cloud clusters). This push does not touch them, but "
                        "the FGCP sync it triggers may copy the primary's "
                        "addressing onto the secondary and split the cluster. "
                        "Verify HA health after the push; pin per-member static "
                        "addresses on those ports if you can."))
        if ha_ctx["enabled"]:
            yield StepResult(
                step="HA primary-check", success=True,
                detail=(f"primary {ha_ctx['hostname']}".rstrip()
                        + (f"; HA-reserved preserved: {', '.join(sorted(ha_reserved))}"
                           if ha_reserved else "")))
        # Interfaces that must survive the network wipe: the mgmt iface (control
        # channel) + the FGCP HA-reserved set. Excluded from both delete and PUT.
        protected_ifaces: set[str] = {mgmt_iface} | ha_reserved

        def _id_path(step: _PushStep, raw_id) -> str:
            return f"{step.cmdb_path}/{urllib.parse.quote(str(raw_id), safe='')}"

        # Capture target's aggregate → members map BEFORE the delete phase
        # so the push phase can fingerprint conflicts. When delete soft-fails
        # on an aggregate (typically -651: referenced by policy), its members
        # remain captive and the source's matching aggregate can't claim them.
        target_aggregate_members: dict[str, list[str]] = {}
        # Track which aggregates we couldn't delete so the push phase knows
        # which physical IFs are still claimed.
        soft_failed_deletes: dict[str, set[str]] = {s.label: set() for s in active}

        # FortiOS auto-creates an interface-subnet address object ("<iface>
        # address") per interface; it holds the interface "in-use" and blocks
        # its DELETE over REST. These are pure interface-coupled derivatives -
        # not user policy - so the interface wipe clears them to complete the
        # clean-slate replace. Source-independent: every FortiGate target grows
        # them for its own interfaces. Cached lazily on first need (keyed by the
        # interface each binds); a derivative that is itself policy-referenced
        # won't delete and is left in place (no cascade into user policy).
        _iface_subnet_addrs: dict[str, list[str]] | None = None

        def _clear_iface_derivatives(iface_name) -> int:
            nonlocal _iface_subnet_addrs
            if _iface_subnet_addrs is None:
                _iface_subnet_addrs = {}
                try:
                    for a in _list(base, token, "/firewall/address", vdom, verify):
                        if ((a.get("type") or "").lower() == "interface-subnet"
                                and a.get("interface") and a.get("name")):
                            _iface_subnet_addrs.setdefault(
                                str(a["interface"]), []).append(str(a["name"]))
                except Exception:
                    pass
            cleared = 0
            for addr in _iface_subnet_addrs.get(str(iface_name), []):
                try:
                    _delete(base, token,
                            f"/firewall/address/{urllib.parse.quote(addr, safe='')}",
                            vdom, verify)
                    cleared += 1
                except Exception:
                    pass  # derivative itself in-use (policy-ref) → leave it,
                    # the iface stays blocked and soft-fails as before
            return cleared

        def _deref_iface_from_zones(iface_name) -> int:
            """Remove iface_name from any system/zone member list (PUT the zone
            sans this member) so a leftover zone membership stops blocking the
            iface DELETE. Zones are wiped in the earlier Zones step, but a
            survivor/recreate can still hold a stale iface. Best-effort."""
            removed = 0
            try:
                zones = _list(base, token, "/system/zone", vdom, verify)
            except Exception:
                return 0
            for z in zones:
                members = [m for m in (z.get("interface") or [])
                           if isinstance(m, dict) and m.get("interface-name")]
                if not any(m["interface-name"] == str(iface_name) for m in members):
                    continue
                kept = [m for m in members if m["interface-name"] != str(iface_name)]
                try:
                    _put(base, token,
                         f"/system/zone/{urllib.parse.quote(str(z['name']), safe='')}",
                         vdom, {"name": z["name"], "interface": kept}, verify)
                    removed += 1
                except Exception:
                    pass
            return removed

        def _unwind_stale_tunnels(iface_name) -> int:
            """Delete phase1-interfaces (phase2s first) whose local-if is the
            blocked iface. A tunnel bound to an interface this wipe removes is
            dead weight from a previous config era; when the SOURCE has VPN
            sections their Delete steps already wiped it - this only catches
            the VPN-less-source case where nobody owns the stale tunnel.
            A POLICY-held tunnel stays (user rules are never auto-removed -
            FortiOS refuses the delete and the iface soft-fails as before;
            the -54 hint then points at the policy-first ordering)."""
            removed = 0
            try:
                p1s = _list(base, token, "/vpn.ipsec/phase1-interface", vdom, verify)
            except Exception:
                return 0
            for p1 in p1s:
                if str(p1.get("interface") or "") != str(iface_name):
                    continue
                name = str(p1.get("name") or "")
                if not name:
                    continue
                try:
                    for p2 in _list(base, token, "/vpn.ipsec/phase2-interface",
                                    vdom, verify):
                        if str(p2.get("phase1name") or "") != name:
                            continue
                        try:
                            _delete(base, token,
                                    "/vpn.ipsec/phase2-interface/"
                                    + urllib.parse.quote(str(p2.get("name")), safe=""),
                                    vdom, verify)
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    _delete(base, token,
                            "/vpn.ipsec/phase1-interface/"
                            + urllib.parse.quote(name, safe=""), vdom, verify)
                    removed += 1
                except Exception:
                    pass
            return removed

        # ── Delete phase (top-down) ──
        for s in active:
            step_name = f"Delete {s.label}"
            try:
                existing = _list(base, token, s.cmdb_path, vdom, verify)
            except Exception as exc:
                yield StepResult(step=step_name, success=False,
                                 detail=f"{exc}{_hint_api_401(exc)}")
                return

            # Snapshot aggregate → members for the conflict-detection below.
            if s.label == "Interfaces":
                for e in existing:
                    if (e.get("type") or "").lower() != "aggregate":
                        continue
                    name = str(e.get("name") or "")
                    members = [m.get("interface-name") for m in (e.get("member") or [])
                               if isinstance(m, dict) and m.get("interface-name")]
                    if name and members:
                        target_aggregate_members[name] = members

            to_delete: list = []
            for e in existing:
                rid = e.get(s.id_field)
                if rid is None or rid == "":
                    continue
                if s.deletable_types is not None:
                    etype = (e.get("type") or "").lower()
                    if etype not in s.deletable_types:
                        continue
                if s.label == "Interfaces" and str(rid) in protected_ifaces:
                    continue
                to_delete.append(rid)

            soft_failed = 0
            detached = 0
            derivative_cleared = 0
            for rid in to_delete:
                try:
                    _delete(base, token, _id_path(s, rid), vdom, verify)
                except _FortiError as exc:
                    if exc.errcode in self._DELETE_SOFT_ERRCODES:
                        # An interface DELETE blocked "in-use" is often just held
                        # by its FortiOS-coupled interface-subnet derivative -
                        # clear that and retry once so the wipe completes and the
                        # source iface re-creates on a free slot. User policy
                        # referrers (VIP, rules) are NOT auto-removed → those stay
                        # the user's push-ordering call.
                        if s.label == "Interfaces":
                            n = _clear_iface_derivatives(rid)
                            if n:
                                try:
                                    _delete(base, token, _id_path(s, rid), vdom, verify)
                                    derivative_cleared += n
                                    continue  # deleted on retry → counts as deleted
                                except Exception:
                                    pass  # still blocked → fall through to soft-fail
                        soft_failed += 1
                        soft_failed_deletes[s.label].add(str(rid))
                        # For aggregates we can't delete (policy-referenced
                        # etc.), still detach their members so the source's
                        # aggregate push can claim them. PUT with empty
                        # member list - leaves an empty aggregate behind,
                        # which is a known cleanup item but unblocks the
                        # whole push pipeline.
                        if (s.label == "Interfaces"
                                and str(rid) in target_aggregate_members):
                            try:
                                _put(base, token, _id_path(s, rid), vdom,
                                     {"name": str(rid), "member": []}, verify)
                                detached += 1
                            except Exception:
                                pass
                        continue
                    yield StepResult(step=step_name, success=False,
                                     detail=f"DELETE {rid}: {exc}")
                    return
                except Exception as exc:
                    yield StepResult(step=step_name, success=False,
                                     detail=f"DELETE {rid}: {exc}")
                    return
            # ── Fixpoint retry sweep (Interfaces) ──
            # A stale aggregate held by its leftover VLAN CHILDREN soft-fails on
            # the first pass when the parent is attempted before its children
            # (API return order). The children are in this same to_delete set,
            # so once they're gone the parent becomes deletable - re-attempt the
            # blocked ifaces (clearing iface-derivatives + dereffing zone
            # memberships each round) until a round recovers nothing. Dissolves
            # the children-before-parent ordering + zone-membership blockers
            # without hardcoding either. Stale TUNNEL bindings bound to a
            # blocked iface are unwound too (p2→p1 delete) - the VPN Delete
            # steps own them when the source HAS VPN sections, but a VPN-less
            # source never runs those steps, orphaning old tunnels forever.
            # Policy-held tunnels survive (user rules are never auto-removed).
            recovered_sweep = 0
            zone_derefs = 0
            tunnel_unwinds = 0
            if s.label == "Interfaces":
                blocked = set(soft_failed_deletes["Interfaces"])
                for _ in range(len(blocked) + 1):
                    if not blocked:
                        break
                    progressed = False
                    for rid in sorted(blocked):
                        _clear_iface_derivatives(rid)
                        zone_derefs += _deref_iface_from_zones(rid)
                        tunnel_unwinds += _unwind_stale_tunnels(rid)
                        try:
                            _delete(base, token, _id_path(s, rid), vdom, verify)
                        except Exception:
                            continue  # still held → try again next round / leave
                        blocked.discard(rid)
                        soft_failed_deletes["Interfaces"].discard(rid)
                        soft_failed -= 1
                        recovered_sweep += 1
                        progressed = True
                    if not progressed:
                        break

            detail = f"deleted {len(to_delete) - soft_failed}/{len(to_delete)}"
            if derivative_cleared:
                detail += f" (cleared {derivative_cleared} coupled addr)"
            if recovered_sweep:
                detail += f"; recovered {recovered_sweep} on retry"
                if zone_derefs or tunnel_unwinds:
                    _parts = []
                    if zone_derefs:
                        _parts.append(f"{zone_derefs} zone-deref")
                    if tunnel_unwinds:
                        _parts.append(f"{tunnel_unwinds} stale-tunnel unwound")
                    detail += f" ({', '.join(_parts)})"
            elif tunnel_unwinds:
                detail += f"; {tunnel_unwinds} stale-tunnel unwound"
            if soft_failed:
                detail += f" ({soft_failed} read-only/in-use, skipped"
                if detached:
                    detail += f"; {detached} member-detached"
                detail += ")"
            yield StepResult(step=step_name, success=True, detail=detail)

        # Physical IFs that are still captured by an aggregate we couldn't
        # delete. The push phase uses this to add a clear hint to the
        # otherwise opaque -651 "value parse error" Forti returns.
        captive_physicals: dict[str, str] = {}
        for agg_name, members in target_aggregate_members.items():
            if agg_name in soft_failed_deletes.get("Interfaces", set()):
                for m in members:
                    if m:
                        captive_physicals[m] = agg_name

        # ── VPN identity-cert import (network strand, before phase1) ──
        # A phase1 with authmethod=signature references a local cert by name;
        # import it first so the reference resolves. Cert/key decrypted server-
        # side (vpn_certs) and base64-imported via the monitor endpoint.
        if strand == "network" and vpn_certs:
            for _vh, cd in vpn_certs.items():
                name = (cd or {}).get("cert_name")
                cpem = (cd or {}).get("cert_pem")
                kpem = (cd or {}).get("key_pem")
                if not (name and cpem and kpem):
                    continue
                try:
                    # FortiOS rejects re-import of an existing name (errcode -23),
                    # so refresh idempotently: best-effort delete first (the
                    # referencing phase1 was already removed in the delete phase),
                    # then import.
                    try:
                        _delete(base, token,
                                f"/vpn.certificate/local/{urllib.parse.quote(name, safe='')}",
                                vdom, verify)
                    except Exception:
                        pass
                    _import_local_cert(device, token, vdom, verify, name, cpem, kpem)
                    yield StepResult(step=f"Import VPN cert {name}", success=True)
                except Exception as e:
                    yield StepResult(step=f"Import VPN cert {name}", success=False,
                                     detail=str(e))
                    return

        # ── Push phase (bottom-up) ──
        # FortiOS ≥7.6 renamed the multi-family service protocol enum to
        # 'TCP/UDP/UDP-Lite/SCTP' (older releases: 'TCP/UDP/SCTP'); pushing
        # the wrong spelling fails with -61. The offline render can't know
        # the target's OS - probe the factory 'ALL' service once and rewrite
        # service entries to the box's own spelling (QA finding, FortiOS 7.6.7).
        _svc_proto_enum: str | None = None
        try:
            # 'HTTPS' is a factory multi-family service on every FortiOS
            # ('ALL' is protocol IP - wrong probe target). Fallback: scan the
            # service table for the first multi-family spelling.
            _probe = _list(base, token, "/firewall.service/custom/HTTPS", vdom, verify)
            _p = str((_probe[0] if _probe else {}).get("protocol") or "")
            if not _p.startswith("TCP/UDP"):
                for _e in _list(base, token, "/firewall.service/custom", vdom, verify):
                    _p2 = str(_e.get("protocol") or "")
                    if _p2.startswith("TCP/UDP"):
                        _p = _p2
                        break
            if _p in ("TCP/UDP/SCTP", "TCP/UDP/UDP-Lite/SCTP"):
                _svc_proto_enum = _p
        except Exception:
            pass

        # Identity refs (Phase 2 Option C, ref-only) name users/groups that
        # must EXIST on the target - FortiOS rejects the whole rule with -3
        # ("entry not found in datasource") otherwise, e.g. an AD principal
        # like 'gateshift\alice' on a box without that directory (QA finding).
        # Prune unknown refs at push time against the target's own catalogs,
        # mirroring CP's Access-Role pushable-gate. Empty result = rule keeps
        # matching all users, which is reported as a skipped-detail below.
        _known_identities: set[str] = set()
        for _p in ("/user/local", "/user/group", "/user/ldap", "/user/radius",
                   "/user/fsso"):
            try:
                for _e in _list(base, token, _p, vdom, verify):
                    _n = str(_e.get("name") or "").strip()
                    if _n:
                        _known_identities.add(_n)
            except Exception:
                pass
        _iden_pruned: list[str] = []

        # UTM/security PROFILE refs are attach-only by design (the profiles
        # themselves are never migrated - see the SSL-decryption scope). A
        # rule naming a profile the target doesn't have fails with -3, so
        # prune unknown refs against the target's catalogs and say so
        # (QA finding, FGCP leg: 'gfgt-deep' ssl-ssh-profile).
        _PROFILE_FIELDS = {
            "ssl-ssh-profile":   "/firewall/ssl-ssh-profile",
            "webfilter-profile": "/webfilter/profile",
            "av-profile":        "/antivirus/profile",
            "ips-sensor":        "/ips/sensor",
            "application-list":  "/application/list",
            "dnsfilter-profile": "/dnsfilter/profile",
        }
        _known_profiles: dict[str, set[str]] = {}
        for _fld, _path in _PROFILE_FIELDS.items():
            try:
                _known_profiles[_fld] = {
                    str(e.get("name") or "") for e in _list(base, token, _path, vdom, verify)}
            except Exception:
                _known_profiles[_fld] = set()
        _prof_pruned: list[str] = []

        for s in reversed(active):
            step_name = f"Push {s.label}"
            entries = self._section_entries(config, s.section_key)
            if s.label == "Rules" and _known_identities is not None:
                _fixed = []
                for e in entries:
                    for _pf, _known in _known_profiles.items():
                        _ref = str(e.get(_pf) or "").strip()
                        if _ref and _known and _ref not in _known:
                            _prof_pruned.append(f"{_pf}={_ref}")
                            e = {k: v for k, v in e.items() if k != _pf}
                    # NOTE: never name a local `_f` in this module - that is
                    # the module-level alias for _forti_common and shadowing it
                    # breaks every `_f.*` call in the enclosing function.
                    for _idf in ("users", "groups"):
                        refs = e.get(_idf)
                        if not isinstance(refs, list):
                            continue
                        keep = [r for r in refs
                                if str(r.get("name") or "") in _known_identities]
                        if len(keep) != len(refs):
                            _iden_pruned.extend(
                                str(r.get("name")) for r in refs if r not in keep)
                            e = {**e, _idf: keep} if keep else {
                                k: v for k, v in e.items() if k != _idf}
                    _fixed.append(e)
                entries = _fixed
            if s.label == "Service Objects" and _svc_proto_enum:
                entries = [
                    {**e, "protocol": _svc_proto_enum}
                    if e.get("protocol") in ("TCP/UDP/SCTP", "TCP/UDP/UDP-Lite/SCTP")
                    else e
                    for e in entries
                ]
            pushed = 0
            skipped = 0
            # Bucket skipped entry-IDs by cause so the step-detail surfaces
            # the cross-vendor naming mismatches (PA "ethernet1/X" vs Forti
            # "portN") instead of just a silent "(N skipped)" count.
            skipped_mgmt: list[str] = []
            skipped_ha: list[str] = []
            skipped_readonly: list[str] = []
            for e in entries:
                entry_id = e.get(s.id_field)
                if entry_id is None:
                    continue
                if s.label == "Interfaces" and str(entry_id) in protected_ifaces:
                    skipped += 1
                    (skipped_mgmt if str(entry_id) == mgmt_iface
                     else skipped_ha).append(str(entry_id))
                    continue

                # Physical IFs (no 'type' field) only support PUT - they
                # already exist on the box and weren't deleted.
                use_put = (s.label == "Interfaces" and not e.get("type"))

                # FortiOS requires `vdom` in the body when CREATING a
                # non-physical iface (vlan / aggregate / loopback) - the
                # URL query-string vdom isn't enough. Inject our push-target
                # vdom; rendered entries don't know which vdom they're
                # destined for.
                if s.label == "Interfaces" and e.get("type") and "vdom" not in e:
                    e = {**e, "vdom": vdom}

                try:
                    if use_put:
                        _put(base, token, _id_path(s, entry_id), vdom, e, verify)
                    else:
                        _post(base, token, s.cmdb_path, vdom, e, verify)
                    pushed += 1
                    continue
                except _FortiError as exc:
                    # -5 on POST is usually "already exists" → PUT to overwrite
                    # (leftover, or a vendor builtin name we render-collided
                    # with). It can ALSO mean a subnet/IP OVERLAP with another
                    # interface - then the PUT below fails too and we surface a
                    # hint (F9: the bare -5 was opaque about overlap).
                    if not use_put and exc.errcode == -5:
                        try:
                            _put(base, token, _id_path(s, entry_id), vdom, e, verify)
                            pushed += 1
                            continue
                        except _FortiError as exc2:
                            if exc2.errcode in self._PUSH_READONLY_ERRCODES:
                                skipped += 1
                                skipped_readonly.append(str(entry_id))
                                continue
                            hint5 = error_hint(_FORTI_ERROR_HINTS, {
                                "phase": "retry", "step": s.label,
                                "errcode": exc2.errcode,
                                "status_code": exc2.status_code,
                                "use_put": use_put, "entry": e,
                                "entry_id": entry_id, "cli_error": exc2.message,
                                "captive_physicals": captive_physicals,
                            })
                            yield StepResult(step=step_name, success=False,
                                             detail=f"PUT {entry_id}: {exc2}{hint5}")
                            return
                        except Exception as exc2:
                            yield StepResult(step=step_name, success=False,
                                             detail=f"PUT {entry_id}: {exc2}")
                            return
                    # -162: the name is already owned by a FortiOS object of a
                    # DIFFERENT type ("<name> is already used as a service name")
                    # - e.g. a round-tripped DCE-RPC service GROUP vs the builtin
                    # DCE-RPC service. It can't be (re)created under that name and
                    # the existing (builtin) object already serves it, so a policy
                    # referencing the name resolves to it → soft-skip instead of
                    # aborting the whole push.
                    if exc.errcode == -162:
                        skipped += 1
                        skipped_readonly.append(str(entry_id))
                        continue
                    # Soft-skip only applies on PUT (vendor-protected entry
                    # we tried to overwrite). On the initial POST any non-(-5)
                    # error is a hard failure - we just deleted everything,
                    # so a missing-dependency or unknown error here is real.
                    if use_put and exc.errcode in self._PUSH_READONLY_ERRCODES:
                        skipped += 1
                        skipped_readonly.append(str(entry_id))
                        continue
                    hint = error_hint(_FORTI_ERROR_HINTS, {
                        "phase": "primary", "step": s.label,
                        "errcode": exc.errcode, "status_code": exc.status_code,
                        "use_put": use_put, "entry": e, "entry_id": entry_id,
                        "cli_error": exc.message,
                        "captive_physicals": captive_physicals,
                    })
                    yield StepResult(step=step_name, success=False,
                                     detail=f"{'PUT' if use_put else 'POST'} {entry_id}: {exc}{hint}")
                    return
                except Exception as exc:
                    yield StepResult(step=step_name, success=False,
                                     detail=f"{'PUT' if use_put else 'POST'} {entry_id}: {exc}")
                    return
            detail = f"pushed {pushed}"
            if skipped:
                # Surface what was skipped + why so a partial cross-vendor
                # push (e.g. PA ethernet1/X names that don't exist on a
                # Forti box's port1/portN hardware) doesn't look like a
                # silent success. Limit to 6 names per bucket to keep the
                # detail line short.
                parts: list[str] = []
                if skipped_mgmt:
                    parts.append(f"mgmt: {', '.join(skipped_mgmt[:6])}")
                if skipped_ha:
                    parts.append(f"HA-reserved: {', '.join(skipped_ha[:6])}")
                if skipped_readonly:
                    head = ", ".join(skipped_readonly[:6])
                    more = f" (+{len(skipped_readonly)-6} more)" if len(skipped_readonly) > 6 else ""
                    parts.append(
                        f"not-on-target / read-only: {head}{more}"
                    )
                detail += f" ({skipped} skipped - " + "; ".join(parts) + ")"
            if s.label == "Rules" and _prof_pruned:
                _up = sorted(set(_prof_pruned))
                detail += ("; security-profile ref(s) not present on target, "
                           f"pruned: {', '.join(_up[:4])}"
                           + (f" (+{len(_up)-4} more)" if len(_up) > 4 else "")
                           + " - profiles are attach-only (never migrated); "
                             "create them on the target and re-push to restore "
                             "the inspection")
            if s.label == "Rules" and _iden_pruned:
                _uniq = sorted(set(_iden_pruned))
                _head = ", ".join(_uniq[:4])
                _more = f" (+{len(_uniq)-4} more)" if len(_uniq) > 4 else ""
                detail += (f"; identity ref(s) not present on target, pruned: "
                           f"{_head}{_more} - create them (LDAP/FSSO/local) and "
                           "re-push to restore the user constraint")
            yield StepResult(step=step_name, success=True, detail=detail)

        # ── Final step: force-reconfigure the mgmt interface (opt-in) ──
        # The normal Interfaces step always SKIPS the mgmt iface (1944) to keep
        # the control channel alive. With the per-push opt-in (a typed "confirm"
        # in the push modal → mgmt_override) we PUT it here, last and in
        # isolation - changing its IP drops our API session, so any earlier step
        # would then fail. A connection error right after this PUT is the
        # EXPECTED outcome (the new IP cut our session), not a failure.
        if mgmt_override and strand == "network":
            iface_step = next((s for s in self._PUSH_STEPS
                               if s.label == "Interfaces"), None)
            mgmt_entry = None
            if iface_step and iface_step.section_key not in skip_internal:
                for e in self._section_entries(config, iface_step.section_key):
                    if str(e.get("name")) == mgmt_iface:
                        mgmt_entry = e
                        break
            if mgmt_entry is not None:
                mstep = "Push Mgmt Interface (force)"
                path = (f"{iface_step.cmdb_path}/"
                        f"{urllib.parse.quote(mgmt_iface, safe='')}")
                try:
                    _put(base, token, path, vdom, mgmt_entry, verify)
                    yield StepResult(
                        step=mstep, success=True,
                        detail=(f"{mgmt_iface} reconfigured (force). Session held - "
                                "verify reachability; if its IP changed, update the "
                                "device's mgmt IP in Gateshift to re-attach."))
                except _FortiError as exc:
                    yield StepResult(step=mstep, success=False,
                                     detail=f"PUT {mgmt_iface}: {exc}")
                except Exception:
                    # Connection dropped immediately after the PUT landed - the
                    # new IP cut our session. This is the success path here.
                    yield StepResult(
                        step=mstep, success=True,
                        detail=(f"{mgmt_iface} reconfigured (force) - API session "
                                "dropped as expected (its IP changed). Gateshift can no "
                                "longer reach the box at the old address; update the "
                                "device's mgmt IP to the new one to re-attach."))

    # ── Target discovery (Discover-as-Verarbeitung) ──────────────

    def list_target_interfaces(self, *, device: dict) -> list[dict]:
        token = device.get("api_key") or ""
        base_url = _f.base_url_for(device)
        vdom = _f.vdom_for(device)
        zone_payload = _f.api_get(base_url, token, "/api/v2/cmdb/system/zone", vdom)
        iface_payload = _f.api_get(base_url, token, "/api/v2/cmdb/system/interface", vdom)
        zone_map = _f.parse_zones_map(zone_payload)
        parsed, _drops = _f.parse_interfaces(iface_payload, zone_map)
        out: list[dict] = []
        for i in parsed:
            row: dict = {
                "name":         i["name"],
                "type":         i["type"],
                "ip_addresses": i.get("ips") or [],
                "zone":         i.get("zone"),
                "description":  i.get("description"),
                "dhcp_enabled": bool(i.get("dhcp_enabled")),
                "enabled":      bool(i.get("enabled", True)),
            }
            # VLAN subs carry parent + vlan_tag; forward them so the
            # discover-save path can persist the same fields the full-
            # collect path writes via _write_collect_result.
            if i.get("parent"):
                row["parent"] = i["parent"]
            if i.get("vlan_tag") is not None:
                row["vlan_tag"] = i["vlan_tag"]
            # Bond members for aggregate-type ifaces.
            if i.get("members"):
                row["members"] = i["members"]
            # role is Forti-only meta; forward so the round-trip stays clean.
            if i.get("role"):
                row["role"] = i["role"]
            out.append(row)
        return out

    def list_target_addresses(self, *, device: dict) -> list[dict]:
        """Read FortiOS address-objects via /firewall/address.

        Returns ``[{"name", "type", "value"}]`` - subtype matches
        the wire (ipmask / iprange / fqdn); value is the canonical
        string. Predefined / vendor-shipped objects are not filtered -
        the UI shows them as choices for cross-vendor mapping.
        """
        token = device.get("api_key") or ""
        base_url = _f.base_url_for(device)
        vdom = _f.vdom_for(device)
        try:
            payload = _f.api_get(base_url, token, "/api/v2/cmdb/firewall/address", vdom)
        except Exception:
            return []
        out: list[dict] = []
        for a in payload.get("results") or []:
            name = a.get("name") or ""
            if not name:
                continue
            atype = (a.get("type") or "ipmask").strip().lower()
            if atype == "ipmask":
                ip = (a.get("subnet") or "").strip()
                value = ip or None
            elif atype == "iprange":
                start = (a.get("start-ip") or "").strip()
                end   = (a.get("end-ip") or "").strip()
                value = f"{start}-{end}" if start and end else None
            elif atype == "fqdn":
                value = (a.get("fqdn") or "").strip() or None
            else:
                value = None
            out.append({"name": name, "type": atype, "value": value})
        return out

    def list_target_services(self, *, device: dict) -> list[dict]:
        """Read FortiOS service-objects via /firewall.service/custom.

        FortiOS returns predefined + custom services from the same
        endpoint - caller can filter on the predefined-name list if
        desired. Returns ``[{"name", "proto", "port"}]`` for the V1
        tcp/udp case; other protocols emit proto=None.
        """
        token = device.get("api_key") or ""
        base_url = _f.base_url_for(device)
        vdom = _f.vdom_for(device)
        try:
            payload = _f.api_get(base_url, token, "/api/v2/cmdb/firewall.service/custom", vdom)
        except Exception:
            return []
        out: list[dict] = []
        for s in payload.get("results") or []:
            name = s.get("name") or ""
            if not name:
                continue
            tcp_p = (s.get("tcp-portrange") or "").strip()
            udp_p = (s.get("udp-portrange") or "").strip()
            if tcp_p:
                out.append({"name": name, "proto": "tcp", "port": tcp_p})
            elif udp_p:
                out.append({"name": name, "proto": "udp", "port": udp_p})
            else:
                out.append({"name": name, "proto": None, "port": None})
        return out

    def list_target_zones(self, *, device: dict) -> list[dict]:
        """Read FortiOS zones via /api/v2/cmdb/system/zone.

        Returns [{"name", "interfaces", "properties": {forti_*}}].
        """
        token = device.get("api_key") or ""
        base_url = _f.base_url_for(device)
        vdom = _f.vdom_for(device)
        payload = _f.api_get(base_url, token, "/api/v2/cmdb/system/zone", vdom)
        out: list[dict] = []
        for z in payload.get("results") or []:
            name = z.get("name") or ""
            if not name:
                continue
            members = [
                m.get("interface-name") or ""
                for m in (z.get("interface") or [])
            ]
            intrazone = (z.get("intrazone") or "").strip().lower()
            out.append({
                "name":       name,
                "interfaces": [m for m in members if m],
                "properties": {
                    "forti_intrazone_block": intrazone == "deny",
                    "forti_description":     (z.get("description") or "").strip() or None,
                },
            })
        return out

    def list_target_routes(self, *, device: dict) -> list[dict]:
        token = device.get("api_key") or ""
        base_url = _f.base_url_for(device)
        vdom = _f.vdom_for(device)
        iface_payload = _f.api_get(base_url, token, "/api/v2/cmdb/system/interface", vdom)
        route_payload = _f.api_get(base_url, token, "/api/v2/cmdb/router/static", vdom)
        zone_map = _f.parse_zones_map({"results": []})
        ifaces, _ = _f.parse_interfaces(iface_payload, zone_map)
        iface_names = {i["name"] for i in ifaces}
        _ivrf = {i["name"]: int(i["vr_name"][4:]) if str(i.get("vr_name") or "").startswith("vrf-") else 0
                 for i in ifaces}
        parsed = _f.parse_routes(route_payload, iface_names, _ivrf)
        out: list[dict] = []
        for r in parsed:
            out.append({
                "prefix":         f"{r['prefix']}/{r['plen']}",
                "interface_name": r.get("iface"),
                "next_hop":       r.get("next_hop"),
                "vr_name":        r.get("vr") or "default",
                "is_connected":   False,  # Forti static routes are never connected
            })
        return out

    def list_utm_profiles(self, *, device: dict) -> dict[str, list[dict]]:
        """Read the target's UTM profile catalog, partial-failure tolerant.

        Returns ``{slot_name: [{"name": str}, ...]}`` where slot_name matches
        the column in fw_rule_security_profile_overrides (av_profile,
        webfilter_profile, dnsfilter_profile, ips_sensor, application_list,
        ssl_ssh_profile). A category absent from the result means the
        endpoint failed (lib not licensed, older FortiOS, auth scope) - UI
        renders the slot as "(no profiles available)".

        Read-only; Gateshift does not manage UTM profile objects.
        """
        token = device.get("api_key") or ""
        if not token:
            raise RuntimeError("No API key configured for target")
        base_url = _f.base_url_for(device)
        vdom = _f.vdom_for(device)

        endpoints = [
            ("av_profile",        "/api/v2/cmdb/antivirus/profile"),
            ("webfilter_profile", "/api/v2/cmdb/webfilter/profile"),
            ("dnsfilter_profile", "/api/v2/cmdb/dnsfilter/profile"),
            ("ips_sensor",        "/api/v2/cmdb/ips/sensor"),
            ("application_list",  "/api/v2/cmdb/application/list"),
            ("ssl_ssh_profile",   "/api/v2/cmdb/firewall/ssl-ssh-profile"),
        ]

        catalog: dict[str, list[dict]] = {}
        for slot, path in endpoints:
            try:
                payload = _f.api_get(base_url, token, path, vdom)
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                # Transport-level failure = device unreachable. Don't probe the
                # remaining blades (each would eat another connect-timeout);
                # surface it so the API returns 502 instead of an empty catalog
                # that looks like "no profiles available".
                raise RuntimeError(f"could not reach target: {exc}") from exc
            except Exception:
                # HTTP-level failure (e.g. blade unlicensed / older FortiOS) -
                # that one slot is unavailable; keep the others.
                continue
            items: list[dict] = []
            for entry in (payload.get("results") or []):
                name = entry.get("name") or ""
                if name:
                    items.append({"name": name})
            catalog[slot] = items
        return catalog

    def list_target_vrfs(self, *, device: dict) -> list[dict]:
        """Forti VRF is an iface-property (0..31). Aggregate distinct
        non-zero VRFs from interfaces; 'default' (vrf=0) is implicit."""
        token = device.get("api_key") or ""
        base_url = _f.base_url_for(device)
        vdom = _f.vdom_for(device)
        iface_payload = _f.api_get(base_url, token, "/api/v2/cmdb/system/interface", vdom)
        zone_map = _f.parse_zones_map({"results": []})
        ifaces, _ = _f.parse_interfaces(iface_payload, zone_map)
        members: dict[str, list[str]] = {}
        for i in ifaces:
            vr = i.get("vr_name") or "default"
            members.setdefault(vr, []).append(i["name"])
        out: list[dict] = []
        for vr, mems in members.items():
            if vr == "default":
                continue
            out.append({
                "name":              vr,
                "interface_members": mems,
                "properties":        None,
            })
        return out
