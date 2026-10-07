# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""OPNsense push driver.

Writes into the MVC firewall model - the ruleset OPNsense surfaces as
"Firewall > Rules" from 26.1 on and as "Firewall > Automation > Filter"
before that. It is the only ruleset with an API; the classic one cannot
be written at all, which is also why a source import reads the
configuration file rather than this API.

Two shapes of this vendor drive the design:

*Interface groups are its zones.* A rule binds to a group exactly as it
binds to an interface, and lands in its own band of the pf evaluation
order (measured: a rule on a group came back with prio_group 300010).
So a zone-native source keeps its zone names here instead of being
flattened into one rule per interface.

*A write is persisted but not active.* add_rule stores into config.xml
immediately; the ruleset only takes effect on apply. That gap is useful
rather than awkward - the operator can read the migrated policy in the
GUI before it goes live - so apply is a separate, explicit step through
commit_session, and discard_session removes what the push wrote.

Sections are JSON arrays, the shape main.py counts natively.
"""

import dataclasses
import json
import re
from typing import Iterator

from deploy import _opnsense_common as _opn
from deploy import integrity as _integ
from deploy.base import (DeployDriver, DroppedField, DropTagger, StepResult,
                         default_rule_disposition, register_driver)

# Gateshift action -> pf action.
_ACTION = {"allow": "pass", "deny": "block", "reject": "reject",
           "drop": "block"}

# OPNsense wants one protocol per rule; these are the ones it names the
# way we do. Anything else is reported rather than guessed at.
_PROTO_OK = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "esp": "ESP",
             "gre": "GRE", "ah": "AH", "sctp": "SCTP", "any": "any"}


@dataclasses.dataclass(frozen=True)
class _Step:
    """One push step: a section, the endpoints that write and clear it."""
    label: str          # section key in the rendered config
    add_path: str       # POST endpoint that creates one entry
    del_path: str       # POST endpoint that deletes one entry by uuid
    search_path: str    # POST endpoint that lists existing entries
    strand: str


_STEPS = (
    _Step("VLANs", "interfaces/vlan_settings/add_item",
          "interfaces/vlan_settings/del_item",
          "interfaces/vlan_settings/search_item", "network"),
    _Step("Static Routes", "routes/routes/addroute",
          "routes/routes/delroute", "routes/routes/searchroute", "network"),
    _Step("Interface Groups", "firewall/group/add_item",
          "firewall/group/del_item", "firewall/group/search_item", "network"),
    _Step("Aliases", "firewall/alias/add_item", "firewall/alias/del_item",
          "firewall/alias/search_item", "policy"),
    _Step("Rules", "firewall/filter/add_rule", "firewall/filter/del_rule",
          "firewall/filter/search_rule", "policy"),
    _Step("Source NAT", "firewall/source_nat/add_rule",
          "firewall/source_nat/del_rule", "firewall/source_nat/search_rule",
          "policy"),
)


# ── Rendering helpers ────────────────────────────────────────────

def _alias_entry(name, atype, content, description=""):
    return {"enabled": "1", "name": name, "type": atype,
            "content": "\n".join(content) if isinstance(content, list)
                       else str(content),
            "description": (description or "")[:255]}


def _one_ref(values, synth, kind, owner):
    """Collapse a Gateshift reference list into one OPNsense value.

    A rule field here takes a single name, so a multi-value side has to
    become an alias. Synthesised aliases are collected in `synth` and
    pushed alongside the ones that came from the source.
    """
    vals = [v for v in (values or []) if v and v != "any"]
    if kind == "svc":
        vals = [_port_token(v) for v in vals]
    if not vals:
        return "any"
    if len(vals) == 1:
        return _opn.safe_name(vals[0]) if not _looks_literal(vals[0]) \
            else vals[0]
    name = _opn.safe_name(f"gs_{kind}_{owner}")
    synth[name] = _alias_entry(
        name, "port" if kind == "svc" else "network", vals,
        f"generated for rule {owner}")
    return name


def _entry_label(entry: dict) -> str:
    """Whatever names this entry - the key differs per section."""
    return (entry.get("description") or entry.get("name")
            or entry.get("ifname") or "entry")


def _looks_literal(value: str) -> bool:
    """True for a raw address/prefix rather than an object name."""
    v = (value or "").strip()
    return bool(v) and (v[0].isdigit() or ":" in v)


# (!) A port RANGE is written with a colon here, not a dash: every other
# vendor we read says 8000-8100 and OPNsense rejects it outright with
# 'Entry "8000-8100" is not a valid port number'. The pattern anchors on a
# pure digits-dash-digits string so an object NAME that happens to contain a
# dash (gs-svc-https) is left alone.
_PORT_RANGE_RE = re.compile(r"^(\d{1,5})\s*-\s*(\d{1,5})$")


def _port_token(value) -> str:
    s = str(value).strip()
    m = _PORT_RANGE_RE.match(s)
    return f"{m.group(1)}:{m.group(2)}" if m else s


_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def _schedule_human(value) -> str:
    """A schedule as one short line, for the note on a degraded rule.

    Reads the vendor-agnostic `intervals` slot (see the cross-vendor schedule
    work), so it does not care which vendor the source was. Consecutive
    weekdays sharing a window collapse - five weekly entries become
    'Mon-Fri 09:00-17:00' rather than a line nobody reads.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return ""
    intervals = (value or {}).get("intervals") or []
    weekly: dict[tuple[str, str], list[str]] = {}
    once: list[str] = []
    for iv in intervals:
        if iv.get("kind") == "weekly":
            span = (iv.get("start_time") or "", iv.get("end_time") or "")
            weekly.setdefault(span, []).extend(iv.get("weekdays") or [])
        elif iv.get("kind") == "onetime":
            start = str(iv.get("start_datetime") or "")
            end = str(iv.get("end_datetime") or "")
            # 2026-09-01 00:00 - 2026-09-01 06:00 -> one date, two times
            if start[:10] and start[:10] == end[:10]:
                once.append(f"{start} - {end[11:] or end}")
            else:
                once.append(f"{start} - {end}")
    parts: list[str] = []
    for (start, end), days in weekly.items():
        idx = sorted({_WEEKDAYS.index(d) for d in days if d in _WEEKDAYS})
        runs, i = [], 0
        while i < len(idx):
            j = i
            while j + 1 < len(idx) and idx[j + 1] == idx[j] + 1:
                j += 1
            runs.append(_WEEKDAYS[idx[i]] if i == j
                        else f"{_WEEKDAYS[idx[i]]}-{_WEEKDAYS[idx[j]]}")
            i = j + 1
        parts.append(f"{','.join(runs)} {start}-{end}".strip())
    return "; ".join(parts + once)


def _off_note(entry: dict, short: str) -> None:
    """Switch a rule off and say why, in the one free-text field it has.

    OPNsense gives a filter rule only `description`, and the rule name already
    lives there - so the note shares the field, after a separator, truncated to
    what the model accepts. Kept separate from its one caller so a second
    reason to switch a rule off cannot word it differently.
    """
    entry["enabled"] = "0"
    if not short:
        return
    note = f" | off: {short}"
    base = entry.get("description") or ""
    entry["description"] = (base[:255 - len(note)] + note)[:255]


def _services_by_proto(services, catalog=None):
    """{'tcp': ['80','443'], ...} for a rule's service references.

    A reference is normally the NAME of a service object, which the
    catalog resolves to its protocol and port. Some sources hand the pair
    over inline as "tcp/80" instead, so that form is still understood.
    """
    catalog = catalog or {}
    out: dict[str, list[str]] = {}
    unknown: list[str] = []
    pending = list(services or [])
    seen: set[str] = set()
    while pending:
        svc = pending.pop()
        if not svc or svc == "any" or svc in seen:
            continue
        seen.add(str(svc))
        entry = catalog.get(str(svc))
        if isinstance(entry, list):          # a service group
            pending.extend(entry)
            continue
        if entry:
            proto, port = entry
        else:
            proto, _, port = str(svc).partition("/")
        proto = (proto or "").lower()
        if proto not in _PROTO_OK:
            unknown.append(svc)
            continue
        out.setdefault(proto, [])
        if port and str(port).lower() != "any":
            out[proto].append(str(port))
    return out, unknown


@register_driver
class OPNsenseDriver(DeployDriver):

    # Must match the fw_devices.platform enum value - the runtime looks up
    # drivers by that key (DEPLOY_DRIVERS[device.platform]).
    platform = "opnsense"

    # ── Settings ─────────────────────────────────────────────────

    def default_settings(self) -> list[dict]:
        return [
            {
                "key": "rule_prefix",
                "label": "Rule Description Prefix",
                "type": "text",
                "default": "Gateshift-",
                "placeholder": "e.g. Gateshift-",
                "help": ("OPNsense rules have no name field: the "
                         "description is what the GUI lists, so the prefix "
                         "is how migrated rules stay recognisable."),
            },
            {
                "key": "log_rules",
                "label": "Log Matching Traffic",
                "type": "select",
                "default": "yes",
                "options": ["yes", "no"],
                "help": ("Enables per-rule logging on every pushed rule. "
                         "Worth leaving on for a migration: without it a "
                         "rule that never matches looks identical to one "
                         "that does."),
            },
            {
                "key": "rule_category",
                "label": "Category",
                "type": "text",
                "default": "gateshift",
                "help": ("Tags every pushed rule with this category, which "
                         "makes them filterable on the firewall."),
            },
        ]

    # ── Push scope ───────────────────────────────────────────────

    _SECTION_LABELS: dict[str, list[tuple[str, str, list[str]]]] = {
        "policy": [
            ("aliases", "Aliases (addresses + ports)", ["Aliases"]),
            ("rules",   "Rules",                       ["Rules"]),
            ("nat",     "Source NAT",                  ["Source NAT"]),
        ],
        # Interface groups are the zone equivalent and rules depend on them,
        # so they are not optional within the network strand.
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
        raw = (config.get(key) or "").strip()
        if not raw:
            return []
        try:
            value = json.loads(raw)
            return value if isinstance(value, list) else []
        except Exception:
            return []

    def _assignment_worklist(self, sess, device, config, strand):
        """What the operator has to assign before this push can work.

        (!) The single biggest obstacle to OPNsense as a target, and it is a
        PREREQUISITE rather than a defect: an interface group may contain, and
        a rule may name, only an ASSIGNED interface. A VLAN this push creates
        is just a device until somebody assigns it under Interfaces >
        Assignments - and that step has no API (probed: no assign controller,
        and neither the device name `vlan010` nor `opt1.100` is accepted).

        It cascades, which is why it has to be caught BEFORE anything is
        written: a zone with one unassigned member cannot become a group, and
        then every rule bound to that zone fails too. A FortiGate source lost
        all 182 of its rules that way while 61 aliases had already landed.

        So instead of writing a partial firewall that looks configured, say
        exactly what to assign. Returns a detail string when the push should
        stop, or None when there is nothing in the way.
        """
        try:
            assignable = _opn.assignable_interfaces(sess, device)
            referenceable = _opn.referenceable_interfaces(sess, device)
        except Exception as exc:
            # Never block a push over a failed probe - say so and go on.
            return config, None, (
                f"could not read which interfaces this firewall accepts "
                f"({exc}): continuing, the firewall will reject anything it "
                f"cannot take")

        # A VLAN is named <parent>.<tag> on the source side; the entries the
        # VLAN step would create carry the same parent and tag, so a blocked
        # member can be named concretely instead of just being rejected.
        vlan_tags = {f"{e.get('_parent')}.{e.get('tag')}": e
                     for e in self._section_entries(config, "VLANs")}

        def describe(member: str) -> str:
            vlan = vlan_tags.get(member)
            if vlan:
                return (f"VLAN tag {vlan.get('tag')} on "
                        f"{vlan.get('_parent')} (as {member})")
            if member.split(".")[0].lower() in ("tunnel", "ipsec", "gre",
                                                "wireguard", "wg", "ovpn"):
                return (f"{member} (a tunnel, on this platform those live "
                        f"under enc0 and are not an assignable interface)")
            if "." in member:
                return f"{member} (subinterface, not assigned here)"
            return (f"{member} (no interface of this name here, not mapped "
                    f"onto a target interface)")

        if strand == "network":
            # (!) Split by whether the operator CAN fix it. A member that is a
            # VLAN this push creates becomes assignable with one GUI action, so
            # stopping and handing over the worklist is right. A member that
            # can never be an assigned interface - a tunnel, an unmapped name -
            # makes its group permanently unbuildable, and treating that as a
            # blocker would gate the network strand FOREVER. (Found exactly so:
            # a PA source's gs_vpn holds tunnel.1/tunnel.2, which on OPNsense
            # live under enc0 and are no assignable slot, so 7 buildable groups
            # could never be written.) Same distinction as elsewhere: fixable
            # on the box -> prerequisite, not fixable -> declared loss.
            groups = self._section_entries(config, "Interface Groups")
            fixable: dict[str, list[str]] = {}
            hopeless: dict[str, list[str]] = {}
            survivors = []
            for grp in groups:
                name = str(grp.get("ifname"))
                members = [m for m in
                           str(grp.get("members") or "").split(",") if m]
                missing = [m for m in members if m not in assignable]
                never = [m for m in missing if m not in vlan_tags]
                later = [m for m in missing if m in vlan_tags]
                if never:
                    hopeless[name] = never
                    members = [m for m in members if m not in never]
                if later:
                    fixable[name] = later
                if members:
                    grp["members"] = ",".join(members)
                    survivors.append(grp)
                elif not later:
                    # Nothing left and nothing to wait for: not a group at all.
                    hopeless.setdefault(name, never or missing)
            if len(survivors) != len(groups):
                config = dict(config,
                              **{"Interface Groups": json.dumps(survivors)})
            note = None
            if hopeless:
                note = (
                    f"{len(hopeless)} interface group(s) can never be created "
                    f"on this firewall and are left out: their members cannot "
                    f"become assigned interfaces: "
                    + "; ".join(f"{g}: {', '.join(describe(m) for m in ms)}"
                               for g, ms in sorted(hopeless.items()))
                    + ". The rules bound to them are rejected by the firewall "
                      "and reported")
            if not fixable:
                return config, None, note
            items = sorted({describe(m) for ms in fixable.values() for m in ms})
            return config, (
                f"{len(fixable)} of {len(groups)} interface groups cannot be "
                f"created YET: their members are not assigned interfaces on "
                f"this firewall. Assign these under Interfaces > Assignments, "
                + "; ".join(items)
                + f". Groups affected: {', '.join(sorted(fixable))}. Then "
                  f"MAP the source interfaces onto the names they were given "
                  f"(Network > Interfaces), because a group member has to be "
                  f"the assigned name, and push again. A group may only "
                  f"contain an assigned interface ("
                + ", ".join(sorted(assignable)) +
                "), and assignment has no API, see KNOWN_LIMITATIONS.md"
            ), note

        # policy strand: a rule may name an assigned interface OR a group, so
        # what is missing here is usually a group the network strand has not
        # created yet - a different instruction from "go and assign".
        missing_ifaces: dict[str, int] = {}
        for rule in self._section_entries(config, "Rules"):
            iface = str(rule.get("interface") or "")
            if iface and iface not in referenceable:
                missing_ifaces[iface] = missing_ifaces.get(iface, 0) + 1
        if not missing_ifaces:
            return config, None, None
        groups = self._section_entries(config, "Interface Groups")
        group_names = {str(g.get("ifname")) for g in groups}

        # (!) Same split as the network branch, one level down. A rule bound to
        # a group that can NEVER exist here - because a member of it cannot
        # become an assigned interface - is unwritable for good, and treating
        # it as a blocker lets ONE such rule gate 181 writable ones. (Found
        # exactly so: a PA source's single gs_vpn rule.) So that rule is
        # dropped and declared, and only the rest stops the push.
        never_groups = {
            str(g.get("ifname")) for g in groups
            if any(m and m not in assignable and m not in vlan_tags
                   for m in str(g.get("members") or "").split(","))}
        hopeless_rules = [r for r in self._section_entries(config, "Rules")
                          if str(r.get("interface") or "") in never_groups]
        note_parts = []
        if hopeless_rules:
            kept = [r for r in self._section_entries(config, "Rules")
                    if str(r.get("interface") or "") not in never_groups]
            config = dict(config, Rules=json.dumps(kept))
            for n in sorted(never_groups):
                missing_ifaces.pop(n, None)
            note_parts.append(
                f"{len(hopeless_rules)} rule(s) are not written: they bind to "
                f"{', '.join(sorted(never_groups))}, which cannot exist on "
                f"this firewall. A member of it can never be an assigned "
                f"interface")
        if not missing_ifaces:
            return config, None, "; ".join(note_parts) or None

        as_groups = sorted(n for n in missing_ifaces if n in group_names)
        as_ifaces = sorted(n for n in missing_ifaces if n not in group_names)
        total = sum(missing_ifaces.values())
        parts = [f"{total} of {len(self._section_entries(config, 'Rules'))} "
                 f"rules name an interface this firewall does not have"]
        if as_groups:
            parts.append("push the NETWORK strand first, these are zones "
                         "that still have to become interface groups: "
                         + ", ".join(as_groups))
        if as_ifaces:
            parts.append("assign these under Interfaces > Assignments: "
                         + "; ".join(describe(n) for n in as_ifaces))
        return config, ". ".join(parts), "; ".join(note_parts) or None

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
        settings: dict[str, str],
        nat_rules: list[dict],
        tp_configs: list[dict] = (),
        imported_tp: list[dict] = (),      # CP-only; ignored here
        nat_vips: list[dict] = (),
        nat_ippools: list[dict] = (),
        tags: list[dict] = (),
        url_categories: list[dict] = (),
        schedules: list[dict] = (),
        pbf_rules: list[dict] = (),
        ssl_rules: list[dict] = (),
        vpn_tunnels: list[dict] = (),
        ike_crypto_profiles: list[dict] = (),
        ipsec_crypto_profiles: list[dict] = (),
        active_routes: list[dict] = (),    # CP-only; ignored here
        nat_mode: str = "central",         # Forti-only; ignored here
        routing_mode: str = "legacy",      # PA-only; ignored here
    ) -> tuple[dict[str, str], list[dict]]:
        del (tp_configs, imported_tp, nat_vips, nat_ippools, tags,
             url_categories, ssl_rules, vpn_tunnels, ike_crypto_profiles,
             ipsec_crypto_profiles, active_routes, nat_mode, routing_mode,
             vrfs)

        prefix = settings.get("rule_prefix", "Gateshift-")
        do_log = settings.get("log_rules", "yes") == "yes"
        category = (settings.get("rule_category") or "").strip()
        dropped: list[DroppedField] = []

        # Shapes differ by direction: main.py hands generate() the source
        # spec (interface_name / zone_name), while list_target_* returns the
        # `name` shape base.py documents for the UI.
        usable = [i for i in interfaces or [] if not i.get("deploy_skip")]
        iface_names = {i["interface_name"] for i in usable}
        group_entries, group_names = self._render_groups(
            zones, usable, iface_names, dropped)

        alias_entries: dict[str, dict] = {}
        self._render_aliases(address_objects, address_groups, service_objects,
                             service_groups, alias_entries, dropped)

        # name -> (proto, port) for objects, name -> [members] for groups
        svc_catalog: dict = {}
        for svc in service_objects or []:
            body = svc.get("value") or {}
            if isinstance(body, dict) and body.get("protocol"):
                svc_catalog[svc["name"]] = (body["protocol"],
                                            body.get("port") or "")
        for grp in service_groups or []:
            body = grp.get("value") or {}
            if isinstance(body, dict) and body.get("members"):
                svc_catalog[grp["name"]] = list(body["members"])

        known_refs = set(alias_entries) | group_names | iface_names
        rule_entries = self._render_rules(
            rules, known_refs, group_names, alias_entries, prefix, do_log,
            category, schedules, pbf_rules, svc_catalog, dropped)
        snat_entries = self._render_snat(
            nat_rules, known_refs, iface_names, group_names, alias_entries,
            dropped)

        config = {
            "VLANs":            json.dumps(
                self._render_vlans(interfaces, dropped), indent=1),
            "Static Routes":    json.dumps(
                self._render_routes(routes, dropped), indent=1),
            "Interface Groups": json.dumps(group_entries, indent=1),
            "Aliases":          json.dumps(list(alias_entries.values()),
                                           indent=1),
            "Rules":            json.dumps(rule_entries, indent=1),
            "Source NAT":       json.dumps(snat_entries, indent=1),
        }
        return config, [d.to_dict() for d in dropped]

    # ── Renderers ────────────────────────────────────────────────

    def _render_groups(self, zones, interfaces, iface_names, dropped):
        """Source zones -> interface groups.

        A group whose members are all unknown on the target would match
        nothing, so it is reported instead of created; the rules that used
        it then fail reference checking and are reported too, which is the
        outcome we want over a silently permissive ruleset.
        """
        entries, names = [], set()
        by_zone: dict[str, list[str]] = {}
        for iface in interfaces or []:
            zname = (iface.get("zone_name") or "").strip()
            if zname:
                by_zone.setdefault(zname, []).append(iface["interface_name"])

        for seq, zone in enumerate(zones or [], start=10):
            zname = (zone.get("name") or "").strip()
            if not zname or zname == "default":
                continue
            members = [m for m in
                       (zone.get("interfaces") or by_zone.get(zname, []))
                       if m in iface_names]
            if not members:
                dropped.append(DroppedField(
                    rule_id=zname, field="zone",
                    reason="no member interface of this zone exists on the "
                           "target, so the group would match nothing"))
                continue
            safe = _opn.safe_name(zname)
            names.add(safe)
            entries.append({"ifname": safe, "members": ",".join(members),
                            "sequence": str(seq), "nogroup": "0",
                            "descr": f"zone {zname}"})
        return entries, names

    def _render_vlans(self, interfaces, dropped):
        """VLAN sub-interfaces.

        The parent is carried as the SOURCE's interface name; OPNsense
        wants the physical device (vtnet0), which only exists on the
        target. generate() is offline, so the push resolves it.
        """
        entries = []
        for iface in interfaces or []:
            if (iface.get("iface_type") or "") != "vlan":
                continue
            parent, tag = iface.get("parent_iface_name"), iface.get("vlan_tag")
            if not parent or not tag:
                dropped.append(DroppedField(
                    rule_id=iface["interface_name"], field="vlan",
                    reason="VLAN without a parent interface or tag: "
                           "OPNsense needs both to create one"))
                continue
            entries.append({"_parent": parent, "tag": str(tag), "proto": "",
                            "descr": (iface.get("description")
                                      or iface["interface_name"])[:255]})
        return entries

    def _render_routes(self, routes, dropped):
        """Static routes.

        The gateway is carried as the next-hop ADDRESS. OPNsense stores a
        gateway NAME instead, and gateways cannot be created through the
        API at all, so the push matches the address against what the
        firewall already has and reports the rest.
        """
        entries = []
        for route in routes or []:
            prefix, nh = route.get("prefix"), route.get("next_hop")
            if not prefix:
                continue
            if not nh:
                dropped.append(DroppedField(
                    rule_id=prefix, field="next_hop",
                    reason="route without a next hop: a connected route "
                           "follows the interface and is not pushed"))
                continue
            entries.append({"network": prefix, "_next_hop": nh,
                            "descr": (route.get("description") or "")[:255],
                            "enabled": "0" if route.get("disabled") else "1"})
        return entries

    def _render_aliases(self, address_objects, address_groups,
                        service_objects, service_groups, out, dropped):
        # `value` is the vendor-agnostic object body, not a string:
        # {"type": "ip-netmask", "value": "10.0.0.0/8", ...} for addresses,
        # {"type": "static", "members": [...]} for groups.
        for obj in address_objects or []:
            name = _opn.safe_name(obj["name"])
            body = obj.get("value") or {}
            if isinstance(body, str):
                body = {"value": body}
            literal = (body.get("value") or body.get("ip-netmask")
                       or body.get("fqdn") or "")
            if not literal:
                dropped.append(DroppedField(
                    rule_id=obj["name"], field="address",
                    reason="object has no address value"))
                continue
            kind = (body.get("type") or "").lower()
            atype = ("network" if kind == "ip-netmask" and "/" in literal
                     else "host")
            out[name] = _alias_entry(name, atype, [literal],
                                     body.get("description") or "")

        for grp in address_groups or []:
            body = grp.get("value") or {}
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except Exception:
                    body = {"members": [body]}
            members = body.get("members") or []
            # Literal members are values, not references - they exist by
            # definition. Only named members can dangle.
            member_strs = [str(m) for m in members]
            available = (set(out) | {m for m in member_strs if _looks_literal(m)}
                         | {_opn.safe_name(m) for m in member_strs})
            kept, gone = _integ.prune_refs(
                [m if _looks_literal(m) else _opn.safe_name(m)
                 for m in member_strs], available)
            if gone:
                dropped.append(DroppedField(
                    rule_id=grp["name"], field="address_group",
                    reason=f"members not on the target: {', '.join(gone)}"))
            if not kept:
                continue
            name = _opn.safe_name(grp["name"])
            out[name] = _alias_entry(name, "network", kept,
                                     body.get("description") or "")

        # Service objects only become aliases where they are a bare port
        # list; a (proto, port) pair belongs on the rule, since OPNsense
        # carries the protocol there and not on the alias.
        #
        # (!) Service GROUPS are deliberately NOT here, although they were.
        # Their `members` are REFERENCE NAMES, and writing those as alias
        # content made OPNsense read them as ports ('Entry "gs-svc-https" is
        # not a valid port number'). Nothing needs such an alias either: a
        # group is resolved through svc_catalog in _render_rules, which splits
        # the rule PER PROTOCOL with concrete ports - the only faithful
        # rendering, since a group mixing tcp/443 and udp/53 cannot be one
        # port alias on a platform that carries the protocol on the rule.
        for svc in (service_objects or []):
            body = svc.get("value") or {}
            if isinstance(body, str):
                continue
            # (!) A service that names its PROTOCOL is not a port list, so it
            # gets no alias - the protocol travels on the rule here, and
            # _render_rules resolves the name through svc_catalog into concrete
            # ports. No rule ever references such an alias by name, so every
            # one of them was dead weight; a Check Point source contributed 499.
            # Worse, they collided with the platform's reserved words: CP ships
            # predefined services called exec, finger, ftp, gopher, http, and
            # OPNsense answers "Reserved protocol or service names may not be
            # used". Not emitting them removes that whole class rather than
            # working around it with a prefix.
            if body.get("protocol"):
                continue
            ports = body.get("port") or ""
            plain = [_port_token(str(p).split("/")[-1]) for p in
                     (ports if isinstance(ports, list) else [ports])
                     if p and str(p) != "any"]
            if plain:
                name = _opn.safe_name(svc["name"])
                out[name] = _alias_entry(name, "port", plain,
                                         body.get("description") or "")

    def _render_rules(self, rules, known_refs, group_names, alias_out,
                      prefix, do_log, category, schedules, pbf_rules,
                      svc_catalog, dropped):
        """Canonical rules -> pf rules.

        One rule can turn into several: OPNsense carries a single protocol
        and a single interface per rule, so a source rule spanning both is
        split rather than approximated.
        """
        # (!) OPNsense 26.7 has NO schedule API - firewall/schedule/* does not
        # exist - but the firewall DOES publish the schedules it already has,
        # as the option list of the rule model's `sched` field. So an operator
        # who creates the schedule by hand gets a faithful migration, and only
        # a missing one costs the time window.
        #
        # Which of the two it is cannot be decided here: generate() is pure and
        # offline. So the NAME is rendered and the push resolves it against the
        # box, exactly as a category or a route's gateway is. The readable
        # window travels along in an underscore key for the note; the push pops
        # it before anything is sent.
        sched_human = {s.get("name"): (_schedule_human(s.get("value"))
                                       or str(s.get("name")))
                       for s in (schedules or []) if s.get("name")}
        # (!) PBF is NOT an attribute of an access rule here, and the lookup
        # that pretended it was did real damage: it keyed on "rule_hash" while
        # the loader supplies "pbf_hash", so the index became {None: <pbf>} and
        # every rule whose content_hash was absent matched it. A PA source came
        # out with gateway 198.51.100.254 on ALL 184 rules - policy-routing the
        # entire ruleset through one next hop. It only ever failed loudly
        # because OPNsense wants a gateway NAME and rejected the IP.
        #
        # The association could not work in principle either: a pbf_hash is
        # computed over PBF fields, so it never equals an access rule's
        # content_hash. A PBF entry carries its own match (ingress, sources,
        # destinations, services) and belongs on the firewall as its own filter
        # rule with route-to - which also needs the next hop resolved to a
        # gateway that already exists on the target, since gateways cannot be
        # created through the API. Until that is built, PBF is declared in the
        # drop channel rather than approximated.
        for _pbf in pbf_rules or []:
            dropped.append(DroppedField(
                rule_id=_pbf.get("name") or "pbf",
                field="pbf",
                reason=("policy-based forwarding is not written to OPNsense "
                        "yet: it needs its own filter rule with route-to and a "
                        "gateway that already exists on the firewall"),
            ))
        entries: list[dict] = []
        seq = 1

        dropped = DropTagger(dropped)  # rule drops carry the rule's hash (Review change log, R2)
        for rule in rules or []:
            name = rule.get("rule_name") or "rule"
            dropped.current = (rule.get("rhash") or "")

            # (!) Default-policy fidelity, and on THIS platform it is a safety
            # gate rather than tidiness. A source's vendor default rule carries
            # no zone, so it renders with no `interface` - and a rule without
            # an interface is a FLOATING rule in pf, evaluated in band 200000,
            # ahead of every interface-group rule at 300000. With quick=1 that
            # makes it the first rule any packet meets. A PA intrazone-default
            # (pass any -> any) therefore became a permissive catch-all in
            # front of the whole migrated policy: everything allowed. The
            # classification for opnsense already existed in base.py - this
            # driver simply never asked for it, unlike the other three.
            _disp, _dnote = default_rule_disposition(rule, "opnsense")
            if _disp in ("skip", "drop"):
                dropped.append(DroppedField(
                    rule_id=name, field="default_rule", reason=_dnote,
                    fallback=("not pushed" if _disp == "skip" else "dropped")))
                continue

            # (!) The key is `application`, singular - what the loader sets
            # (main.py) and what base.py, panw.py and checkpoint.py all read.
            # This asked for `applications`, which nothing ever sets, so the
            # loss of an application match was reported NOWHERE. And "any" is
            # not a constraint, so it must not be reported either; base.py
            # makes the same test the same way.
            if (rule.get("application") or "").strip().lower() not in (
                    "", "any", "application-default"):
                dropped.append(DroppedField(
                    rule_id=name, field="application",
                    reason="this platform has no application awareness",
                    fallback="rule written with its ports, which is wider"))
            if rule.get("source_identities"):
                dropped.append(DroppedField(
                    rule_id=name, field="source_identities",
                    reason="rules cannot match users on this platform"))

            # A zone reference is either a group we are about to create or
            # an interface on the target. It is NOT checked against the
            # source's pushable interface list: main.py filters that down to
            # interfaces carrying an address, because an address-less one
            # cannot be configured - but rules and NAT still bind to it
            # perfectly well, and dropping them here would lose policy for a
            # reason that belongs to the network strand. An unknown name is
            # rejected by the firewall at push time, with a hint that says so.
            zones_in = [z for z in (rule.get("src_zones") or [])
                        if z and z != "any"]
            ifaces = [_opn.safe_name(z) for z in zones_in]

            src = _one_ref(rule.get("sources"), alias_out, "src", name)
            dst = _one_ref(rule.get("destinations"), alias_out, "dst", name)
            by_proto, unknown = _services_by_proto(rule.get("services"),
                                                   svc_catalog)
            if unknown:
                dropped.append(DroppedField(
                    rule_id=name, field="services",
                    reason=f"protocol not expressible here: "
                           f"{', '.join(unknown)}"))
            sched = rule.get("schedule")

            base = {
                "enabled": "0" if rule.get("disabled") else "1",
                "action": _ACTION.get((rule.get("action") or "").lower(),
                                      "block"),
                "quick": "1",
                "direction": "in",
                "ipprotocol": "inet",
                "source_net": src,
                "source_not": "1" if rule.get("negate_source") else "0",
                "destination_net": dst,
                "destination_not": ("1" if rule.get("negate_destination")
                                    else "0"),
                "description": f"{prefix}{name}"[:255],
                "log": "1" if do_log else "0",
            }
            if category:
                base["categories"] = category
            if sched:
                base["sched"] = _opn.safe_name(sched)
                base["_sched_human"] = sched_human.get(sched) or str(sched)
                base["_sched_source"] = str(sched)

            # (!) A rule with no zone must NEVER be written without an
            # interface. pf then treats it as a FLOATING rule - band 200000,
            # ahead of every interface-group rule at 300000 - and with quick=1
            # it becomes the first rule any packet meets. The Check Point
            # estate carries 17 such rules: 7 are `block any -> any` over all
            # protocols, which would take the firewall down, and 2 are
            # `pass any -> any`, which would bypass the entire migrated policy.
            #
            # They are zoneless for a structural reason, not a data gap: zone
            # derivation is ROUTE-based and an any->any rule has no endpoint to
            # derive from, so for a zoneless source (Check Point) this is
            # systematic. Such a rule applies EVERYWHERE on the source, and
            # "everywhere" on this platform is one rule per interface group -
            # which is faithful AND lands in the normal evaluation bands.
            # (!) A rule with no source zone is NOT written. This took three
            # attempts to get right, so the reasoning is here in full.
            #
            # It must not go out without an interface: pf then treats it as a
            # FLOATING rule - band 200000, ahead of every interface-group rule
            # at 300000 - and with quick=1 it is the first rule any packet
            # meets. The Check Point estate has 17 of them, 7 being
            # `block any -> any`, which would take the firewall down.
            #
            # Nor can the interface be guessed. Two guesses were tried and
            # both widen:
            #  - "everywhere" (a copy per interface): on that estate these are
            #    the LAST rule of each zone-named section (gs-trust-in_291/292
            #    close rules 0-292, gs-dmz-in_091 closes 293-384). Their scope
            #    is the section; flattened into one linear ruleset, a copy on
            #    every interface puts a block-all in the MIDDLE of the policy
            #    and cuts everything after it.
            #  - "every ingress" for a rule whose source is `any` but whose
            #    destination is concrete: `any` means every source ADDRESS,
            #    not every ingress interface. `pass any -> gs_h_pub_web
            #    tcp/443` is an inbound web permit; copying it onto every
            #    internal interface opens it far wider than the source did.
            #
            # So the zone is genuinely unavailable - derivation is route-based
            # and an `any` endpoint gives it nothing to look up - and the
            # honest move is to declare it. A DENY costs nothing in practice:
            # pf denies whatever no rule passed, which is the same argument
            # base.py already makes for deny-defaults on this platform. An
            # ALLOW is lost rather than widened: fail closed.
            if not ifaces:
                denyish = (rule.get("action") or "").lower() in (
                    "deny", "drop", "reject")
                dropped.append(DroppedField(
                    rule_id=name, field="src_zones",
                    reason=("no source zone, and none can be derived (a rule "
                            "with an `any` endpoint gives route-based "
                            "derivation nothing to look up). A rule without an "
                            "interface would be a pf floating rule, evaluated "
                            "ahead of the whole policy, so it is not written"),
                    fallback=("the firewall's own default-deny expresses this"
                              if denyish else
                              "NOT pushed: give the rule a zone, or "
                              "re-create it on the firewall deliberately")))
                continue

            variants = list(by_proto.items()) or [("any", [])]
            for iface in ifaces:
                for proto, ports in variants:
                    entry = dict(base, sequence=str(seq),
                                 protocol=_PROTO_OK.get(proto, "any"))
                    if iface:
                        entry["interface"] = iface
                    if ports:
                        entry["destination_port"] = _one_ref(
                            ports, alias_out, "svc",
                            f"{name}_{proto}") if len(ports) > 1 else ports[0]
                    entries.append(entry)
                    seq += 1
        return entries

    def _render_snat(self, nat_rules, known_refs, iface_names, group_names,
                     alias_out, dropped):
        entries: list[dict] = []
        seq = 1
        for nat in nat_rules or []:
            name = nat.get("name") or "nat"
            kind = (nat.get("nat_type") or "").lower()
            if kind != "snat":
                dropped.append(DroppedField(
                    rule_id=name, field="nat_type",
                    reason=f"{kind or 'this'} NAT has no API on OPNsense: "
                           "port forwards and one-to-one must be set up on "
                           "the firewall"))
                continue
            # Same reasoning as the rule renderer: the egress names a
            # target interface, not something from the source's pushable set.
            egress = [e for e in (nat.get("dst_zones") or []) if e and e != "any"]
            if not egress:
                dropped.append(DroppedField(
                    rule_id=name, field="dst_zones",
                    reason="source NAT without an egress interface: "
                           "OPNsense binds every NAT rule to one"))
                continue
            target = nat.get("trans_src") or ""
            entries.append({
                "enabled": "0" if nat.get("disabled") else "1",
                "sequence": str(seq),
                "interface": _opn.safe_name(egress[0]),
                "ipprotocol": "inet",
                "protocol": "any",
                "source_net": _one_ref(nat.get("orig_src"), alias_out,
                                       "src", name),
                "destination_net": _one_ref(nat.get("orig_dst"), alias_out,
                                            "dst", name),
                "target": _opn.safe_name(target) if target else "",
                "description": (nat.get("description") or name)[:255],
            })
            seq += 1
        return entries

    # ── Push ─────────────────────────────────────────────────────

    def push(
        self,
        *,
        device: dict,
        config: dict[str, str],
        strand: str = "policy",
        skip_sections: set[str] | None = None,
        mgmt_override: bool = False,
        vpn_certs: dict | None = None,
    ) -> Iterator[StepResult]:
        del mgmt_override, vpn_certs

        if not (device.get("api_key") and _opn.api_key_id(device)):
            yield StepResult(step="auth", success=False,
                             detail="no API key and secret configured")
            return

        sess = _opn.session_for(device)
        try:
            version = _opn.product_version(sess, device)
        except _opn.OPNsenseError as exc:
            yield StepResult(step="auth", success=False, detail=str(exc))
            return
        if _opn.version_tuple(version) < (26, 1):
            yield StepResult(
                step="version", success=False,
                detail=(f"OPNsense {version} is too old to be a target: the "
                        "API-managed ruleset only became a first-class "
                        "section in 26.1, so pushed rules would sit in a "
                        "place the operator is unlikely to look"))
            return

        skip = self._resolve_skip_internal(strand, skip_sections)
        steps = [s for s in _STEPS
                 if s.strand == strand and s.label not in skip]
        if not steps:
            yield StepResult(step="validate", success=False,
                             detail=f"no {strand}-strand sections to push")
            return

        # The POLICY strand is gated before anything is written: a rule naming
        # a group that does not exist cannot be fixed by writing the rest
        # first. The NETWORK strand is gated later, just before the Interface
        # Groups step, so its VLANs are created and can be assigned - see
        # _assignment_worklist.
        if strand == "policy":
            config, stop, note = self._assignment_worklist(
                sess, device, config, strand)
            if note:
                yield StepResult(step="preflight", success=True, detail=note)
            if stop:
                yield StepResult(step="preflight", success=False, detail=stop)
                return

        # Legacy rules and the API-managed ones coexist with no documented
        # precedence, so a target that still carries classic rules would
        # give an order we cannot predict. Say so instead of pushing into it.
        if strand == "policy":
            try:
                rows = _opn.search_all(sess, device,
                                       "firewall/filter/search_rule")
                legacy = [r for r in rows
                          if r.get("legacy") and not r.get("is_automatic")]
                if legacy:
                    yield StepResult(
                        step="preflight", success=False,
                        detail=(f"{len(legacy)} rules still live in the "
                                "classic ruleset. How those interleave with "
                                "the API-managed ones is undocumented, so "
                                "the result would be unpredictable: migrate "
                                "them first (Firewall > Rules > Migration "
                                "assistant) or remove them"))
                    return
            except _opn.OPNsenseError as exc:
                yield StepResult(step="preflight", success=True,
                                 detail=f"legacy-rule check skipped: {exc}")

            # Outbound-NAT mode. With it on "automatic" OPNsense generates
            # its own source NAT and IGNORES manual rules - they are still
            # stored, but invisible in the GUI and to the API's own search,
            # which then also blocks deleting the aliases they hold. There
            # is no API for the setting on 26.7, and flipping a device-wide
            # NAT mode is the operator's call in any case, so say what is
            # wrong rather than push rules that will not take effect.
            #
            # (!) Reading the mode needs the whole configuration, which is the
            # ONE large response this platform mishandles (KNOWN_LIMITATIONS.md)
            # and the only place a push depends on one. A failure here must
            # therefore SAY SO rather than fall through as "not automatic":
            # treating an unreadable config as a pass is how the push would go
            # on to write NAT rules the firewall then ignores, which is the one
            # outcome this check exists to prevent. Non-fatal on purpose - the
            # mode is usually fine, and the operator can see the note and the
            # empty NAT tab on the box afterwards.
            if ("Source NAT" not in skip
                    and self._section_entries(config, "Source NAT")):
                # (!) Read from the READABLE PREFIX of the configuration, not
                # from a parsed whole document. Insisting on the whole file
                # left this check permanently blind on every box with a real
                # configuration, because OPNsense truncates an HTTP/1.1
                # response at 65528 bytes - so the one preflight that guards
                # against silently ineffective NAT never actually ran.
                mode, unreadable = _opn.outbound_nat_mode(sess, device)
                if mode is None:
                    yield StepResult(
                        step="preflight", success=True,
                        detail=("could not verify the outbound-NAT mode "
                                f"({unreadable}). If Firewall > NAT > Outbound "
                                "is set to automatic, OPNsense ignores the "
                                "source NAT written below. Check that setting "
                                "on the box"))
                elif mode == "automatic":
                    yield StepResult(
                        step="preflight", success=False,
                        detail=("outbound NAT is set to automatic, where "
                                "OPNsense generates its own source NAT and "
                                "ignores manual rules: switch Firewall > "
                                "NAT > Outbound to Hybrid or Manual first "
                                "(there is no API for that setting)"))
                    return

        # Delete before create, and across the whole strand rather than per
        # section: OPNsense refuses to remove an alias or a group that a
        # rule still binds to, so clearing rules first is what makes the
        # rest removable at all. Same shape as the other drivers - the
        # delete phase walks dependents first, the create phase reverses it.
        # `categories` on a rule is a relation to a Category object, not a
        # free-text tag: the model rejects a plain name with "Related
        # category not found". generate() cannot know the uuid (it is pure
        # and offline), so the name it rendered is resolved here.
        cat_uuid = None
        rule_entries = self._section_entries(config, "Rules")
        cat_name = next((e.get("categories") for e in rule_entries
                         if e.get("categories")), None)
        if cat_name:
            cat_uuid, cat_err = self._ensure_category(sess, device, cat_name)
            if cat_err:
                yield StepResult(step="category", success=True,
                                 detail=f"{cat_err}, rules pushed untagged")
            for entry in rule_entries:
                if cat_uuid:
                    entry["categories"] = cat_uuid
                else:
                    entry.pop("categories", None)
            config = dict(config, Rules=json.dumps(rule_entries))

        # The network strand needs two more names the source cannot know.
        # A VLAN's parent is a physical device on the target, and a route's
        # gateway is a NAMED object there - one that cannot even be created
        # through the API, so an unmatched next hop is a dead end rather
        # than something to work around.
        if strand == "network":
            config, net_msgs = self._resolve_network_names(sess, device,
                                                           config)
            for msg in net_msgs:
                yield StepResult(step="resolve", success=True, detail=msg)
        else:
            config, pol_msgs = self._resolve_policy_names(sess, device, config)
            for msg in pol_msgs:
                yield StepResult(step="resolve", success=True, detail=msg)

        created: dict[str, list[str]] = {}
        ok = True
        for step in reversed([s for s in steps
                              if s.label not in ("Interface Groups",
                                                 "Aliases", "VLANs")]):
            if not self._section_entries(config, step.label):
                continue
            removed, err = self._wipe(sess, device, step)
            if err:
                yield StepResult(step=f"Delete {step.label}", success=False,
                                 detail=err)
                return
            yield StepResult(step=f"Delete {step.label}", success=True,
                             detail=f"{removed} removed")

        for step in steps:
            entries = self._section_entries(config, step.label)
            if not entries:
                continue

            # (!) The assignment gate sits HERE, not in the preflight above,
            # and the ordering is the whole point: the VLANs step runs first
            # so the devices the operator has to assign actually EXIST on the
            # firewall by the time we hand over the worklist. Stopping before
            # them would name VLANs that are not there to assign.
            if step.label == "Interface Groups":
                config, stop, note = self._assignment_worklist(
                    sess, device, config, strand)
                if note:
                    yield StepResult(step="preflight", success=True,
                                     detail=note)
                if stop:
                    yield StepResult(step="preflight", success=False,
                                     detail=stop)
                    return
                # (!) Re-read. The gate REMOVES a group that can never be
                # created (one whose member is a tunnel), and `entries` above
                # was taken before that - so without this the push went on to
                # write exactly the group the gate had just declared as
                # impossible, and failed on it.
                entries = self._section_entries(config, step.label)
                if not entries:
                    continue

            # Interface groups are reconciled by name rather than wiped and
            # rebuilt. They cannot be deleted while a rule still binds to
            # one, and rules are pushed in the other strand - so a
            # delete-first step would fail on exactly the groups that are
            # doing their job. Reconciling also makes a repeated push a
            # no-op instead of an error.
            if step.label in ("Interface Groups", "Aliases", "VLANs"):
                key_fn, sysu, after = {
                    "Interface Groups": (lambda r: r.get("ifname"),
                                         ("enc0", "openvpn", "wireguard"),
                                         "firewall/group/reconfigure"),
                    "Aliases": (lambda r: r.get("name"),
                                ("bogons", "bogonsv6", "sshlockout",
                                 "virusprot"), None),
                    # A VLAN has no name of its own - parent plus tag is what
                    # identifies it, on both sides.
                    "VLANs": (lambda r: f"{r.get('if')}.{r.get('tag')}", (),
                              "interfaces/vlan_settings/reconfigure"),
                }[step.label]
                made, msgs, failed = self._reconcile(
                    sess, device, step, entries, key_fn, sysu)
                created[step.label] = made
                if after and not failed:
                    try:
                        _opn.api_post(sess, device, after)
                    except _opn.OPNsenseError as exc:
                        msgs.append(f"reconfigure failed: {exc}")
                        failed = True
                yield StepResult(step=f"Sync {step.label}",
                                 success=not failed,
                                 detail="; ".join(msgs)[:400])
                if failed:
                    ok = False
                    break
                continue

            made, failures = [], []
            for entry in entries:
                try:
                    body = _opn.api_post(sess, device, step.add_path,
                                         self._wrap(step, entry))
                except _opn.OPNsenseError as exc:
                    failures.append(f"{_entry_label(entry)}: {exc}")
                    continue
                if body.get("result") == "saved" and body.get("uuid"):
                    made.append(body["uuid"])
                else:
                    failures.append(
                        f"{_entry_label(entry)}: "
                        f"{json.dumps(body.get('validations') or body)[:200]}")
            created[step.label] = made

            # An interface group is not referenceable until it is applied -
            # a rule naming one otherwise fails validation with a message
            # that reads as though the group does not exist.
            if step.label == "Static Routes":
                try:
                    _opn.api_post(sess, device, "routes/routes/reconfigure")
                except _opn.OPNsenseError:
                    pass

            yield StepResult(
                step=f"Push {step.label}", success=not failures,
                detail=(f"{len(made)} created"
                        + (f", {len(failures)} failed: "
                           + "; ".join(failures[:5]) if failures else "")))
            if failures:
                ok = False
                break

        if not ok:
            yield StepResult(
                step="summary", success=False,
                detail="push stopped. What was written is on the firewall but "
                       "not active: discard it or finish by hand")
            return

        # Only the policy strand stages. Interface groups, VLANs and routes
        # take effect on their own reconfigure calls, which already ran -
        # offering a Publish button for them would be theatre.
        if strand != "policy":
            yield StepResult(
                step="summary", success=True,
                detail="network configuration applied")
            return

        yield StepResult(
            step="staged", success=True,
            detail=("written to the firewall but NOT active yet: review it "
                    "there, then Publish to apply"),
            data={"session_handle": {"created": created,
                                     "strand": strand}})

    def _resolve_network_names(self, sess, device, config):
        """Turn source-side names into the ones the target actually uses."""
        msgs: list[str] = []
        vlans = self._section_entries(config, "VLANs")
        routes = self._section_entries(config, "Static Routes")
        if not vlans and not routes:
            return config, msgs

        try:
            rows = _opn.api_post(sess, device, "interfaces/overview/export")
            by_name = {r.get("identifier"): r.get("device")
                       for r in rows if r.get("identifier")}
            by_name.update({r.get("device"): r.get("device")
                            for r in rows if r.get("device")})
        except _opn.OPNsenseError as exc:
            msgs.append(f"could not read the target's interfaces: {exc}")
            by_name = {}

        kept_vlans = []
        for entry in vlans:
            parent = entry.pop("_parent", "")
            device_name = by_name.get(parent)
            if not device_name:
                msgs.append(f"VLAN {entry.get('tag')}: no interface named "
                            f"{parent!r} on the target, skipped")
                continue
            entry["if"] = device_name
            kept_vlans.append(entry)

        try:
            gw_rows = _opn.api_post(sess, device,
                                    "routes/gateway/status").get("items") or []
            by_addr = {g.get("address"): g.get("name") for g in gw_rows}
        except _opn.OPNsenseError as exc:
            msgs.append(f"could not read the target's gateways: {exc}")
            by_addr = {}

        kept_routes = []
        for entry in routes:
            nh = entry.pop("_next_hop", "")
            name = by_addr.get(nh)
            if not name:
                msgs.append(
                    f"route {entry.get('network')}: no gateway for next hop "
                    f"{nh} on the target. Gateways cannot be created through "
                    "the API, so add it on the firewall first")
                continue
            entry["gateway"] = name
            kept_routes.append(entry)

        return dict(config,
                    **{"VLANs": json.dumps(kept_vlans),
                       "Static Routes": json.dumps(kept_routes)}), msgs

    def _resolve_policy_names(self, sess, device, config):
        """Resolve the one policy-strand name the source cannot know.

        A rule's `sched` has to name a schedule that exists ON THE FIREWALL.
        There is no API to create one, but the rule model publishes the ones
        that are there as its option list - so an operator who created the
        schedule by hand gets the time window migrated faithfully, and only a
        missing one costs it.

        A rule whose schedule is missing is pushed DISABLED with a note naming
        the window, rather than silently running around the clock.
        Returns (config, messages).
        """
        entries = self._section_entries(config, "Rules")
        if not any(e.get("sched") for e in entries):
            return config, []

        try:
            body = _opn.api_post(sess, device, "firewall/filter/get_rule", {})
            options = ((body.get("rule") or body) or {}).get("sched") or {}
            have = {k for k in options if k} if isinstance(options, dict) else set()
        except Exception as exc:
            have = set()
            msgs = [f"could not read the firewall's schedules ({exc}): "
                    f"rules carrying one are pushed disabled"]
        else:
            msgs = []

        missing: dict[str, str] = {}
        for entry in entries:
            want = entry.pop("_sched_human", "")
            src = entry.pop("_sched_source", "")
            name = entry.get("sched")
            if not name:
                continue
            if name in have:
                continue
            entry.pop("sched", None)
            missing[name] = want or src or name
            _off_note(entry, f"schedule {want}" if want else "schedule")

        if missing:
            msgs.append(
                f"{len(missing)} schedule(s) do not exist on this firewall, so "
                f"the rules using them are pushed DISABLED: create them under "
                f"Firewall > Settings > Schedules and push again: "
                + "; ".join(f"{n} = {w}" for n, w in sorted(missing.items()))
                + ". OPNsense has no API to create a schedule, which is why "
                  "this is a manual step")
        return dict(config, Rules=json.dumps(entries)), msgs

    def _ensure_category(self, sess, device, name):
        """Category uuid for `name`, creating it if the target lacks it."""
        try:
            rows = _opn.search_all(sess, device,
                                   "firewall/category/search_item")
            for row in rows:
                if row.get("name") == name:
                    return row.get("uuid"), None
            body = _opn.api_post(sess, device,
                                 "firewall/category/add_item",
                                 {"category": {"name": name, "auto": "0"}})
            if body.get("uuid"):
                return body["uuid"], None
            return None, f"could not create category {name!r}"
        except _opn.OPNsenseError as exc:
            return None, f"category {name!r} unavailable: {exc}"

    def _reconcile(self, sess, device, step: _Step, entries, key_fn,
                   system_uuids=()):
        """Bring a named collection in line with `entries`.

        Used for the two sections whose entries have a natural key -
        interface groups and aliases. Both refuse deletion while a rule
        binds to them, so wiping and rebuilding would fail on exactly the
        entries that are doing their job. Reconciling also makes a
        repeated push a no-op instead of an error.

        Entries that vanished from the source but are still referenced are
        reported and left in place: the next policy push clears the
        reference, and the one after that can remove them.
        """
        made, msgs, failed = [], [], False
        set_path = step.add_path.replace("add_", "set_")
        try:
            existing = {key_fn(r): r["uuid"] for r in
                        _opn.search_all(sess, device, step.search_path)
                        if key_fn(r)}
        except _opn.OPNsenseError as exc:
            return [], [f"could not list {step.label.lower()}: {exc}"], True

        wanted = {key_fn(e): e for e in entries}
        for name, entry in wanted.items():
            try:
                if name in existing:
                    _opn.api_post(sess, device,
                                  f"{set_path}/{existing[name]}",
                                  self._wrap(step, entry))
                else:
                    body = _opn.api_post(sess, device, step.add_path,
                                         self._wrap(step, entry))
                    if body.get("uuid"):
                        made.append(body["uuid"])
                    elif body.get("validations"):
                        raise _opn.OPNsenseError(
                            json.dumps(body["validations"])[:160])
            except _opn.OPNsenseError as exc:
                msgs.append(f"{name}: {exc}")
                failed = True

        stale = []
        for name, uuid in existing.items():
            if (name in wanted or uuid in system_uuids
                    or str(name).startswith("__")):
                continue
            try:
                _opn.api_post(sess, device, f"{step.del_path}/{uuid}")
            except _opn.OPNsenseError:
                stale.append(name)
        if stale:
            msgs.append("still referenced elsewhere, left in place: "
                        + ", ".join(stale[:6]))
        msgs.insert(0, f"{len(wanted)} in place ({len(made)} new)")
        return made, msgs, failed

    def _wrap(self, step: _Step, entry: dict) -> dict:
        key = {"Interface Groups": "group", "Aliases": "alias",
               "VLANs": "vlan", "Static Routes": "route"}.get(
            step.label, "rule")
        return {key: entry}

    def _wipe(self, sess, device, step: _Step) -> tuple[int, str | None]:
        """Clear the entries this step owns. Returns (removed, error)."""
        try:
            rows = _opn.search_all(sess, device, step.search_path)
        except _opn.OPNsenseError as exc:
            return 0, f"could not list existing entries: {exc}"

        removed = 0
        for row in rows:
            uuid = row.get("uuid")
            if not uuid:
                continue
            # System-generated entries are not ours to remove, and the
            # classic ruleset cannot be touched through this API at all.
            if row.get("is_automatic") or row.get("legacy"):
                continue
            if step.label == "Interface Groups" and uuid in (
                    "enc0", "openvpn", "wireguard"):
                continue
            try:
                _opn.api_post(sess, device, f"{step.del_path}/{uuid}")
                removed += 1
            except _opn.OPNsenseError:
                # Built-in aliases refuse deletion; that is expected and
                # not a reason to abandon the push.
                continue
        return removed, None

    # ── Activate / discard ───────────────────────────────────────

    def commit_session(self, *, device: dict,
                       handle: dict) -> Iterator[StepResult]:
        """Apply what the push wrote."""
        sess = _opn.session_for(device)
        if handle.get("created", {}).get("Interface Groups"):
            try:
                _opn.api_post(sess, device, "firewall/group/reconfigure")
            except _opn.OPNsenseError as exc:
                yield StepResult(step="reconfigure groups", success=False,
                                 detail=str(exc))
                return
        try:
            body = _opn.api_post(sess, device, "firewall/filter/apply")
        except _opn.OPNsenseError as exc:
            yield StepResult(step="apply", success=False, detail=str(exc))
            return
        yield StepResult(step="apply", success=True,
                         detail=f"ruleset reloaded ({body.get('status', 'ok')})")

    def discard_session(self, *, device: dict,
                        handle: dict) -> Iterator[StepResult]:
        """Remove what the push wrote, leaving the active ruleset alone.

        Deletion runs in reverse dependency order - rules and NAT before
        the groups they bind to - because a group that is still referenced
        cannot be removed.
        """
        sess = _opn.session_for(device)
        by_label = {s.label: s for s in _STEPS}
        created = handle.get("created") or {}
        total, failed = 0, 0
        for label in ("Source NAT", "Rules", "Aliases", "Interface Groups"):
            for uuid in created.get(label, []):
                try:
                    _opn.api_post(sess, device,
                                  f"{by_label[label].del_path}/{uuid}")
                    total += 1
                except _opn.OPNsenseError:
                    failed += 1
        try:
            _opn.api_post(sess, device, "firewall/filter/apply")
        except _opn.OPNsenseError:
            pass
        yield StepResult(step="discard", success=failed == 0,
                         detail=f"{total} entries removed"
                                + (f", {failed} could not be" if failed else ""))

    # ── Target reads ─────────────────────────────────────────────

    def list_target_interfaces(self, *, device: dict) -> list[dict]:
        sess = _opn.session_for(device)
        body = _opn.api_get(sess, device, "interfaces/overview/export")
        rows = body if isinstance(body, list) else body.get("rows") or []
        out = []
        for row in rows:
            # Only an ASSIGNED interface has an identifier (lan / wan / optN),
            # and only an assigned one can carry a rule - so a row without one
            # (enc0, pflog0) is a pseudo device, not a rename target.
            name = row.get("identifier")
            if not name or name == "lo0":
                continue
            # (!) This endpoint reports an address TWICE, in two shapes: `ipv4`
            # as [{"ipaddr": "192.0.2.70/24"}] and `addr4` as the bare string
            # "192.0.2.70/24". Reading addr4 in the ipv4 shape iterated the
            # string CHARACTER BY CHARACTER ('str' has no attribute 'get') -
            # and only on an interface that actually has an address, which is
            # why an all-unaddressed lab box never showed it.
            addrs = [a.get("ipaddr") for a in (row.get("ipv4") or [])
                     if isinstance(a, dict) and a.get("ipaddr")]
            if not addrs and isinstance(row.get("addr4"), str) and row["addr4"]:
                addrs = [row["addr4"]]
            out.append({
                "name": name,
                "type": "ethernet",
                "ip_addresses": addrs,
                "zone": None,
                "description": row.get("description") or None,
                "enabled": bool(row.get("enabled", True)),
            })
        return out

    def list_target_zones(self, *, device: dict) -> list[dict]:
        """Interface groups - this platform's zones."""
        sess = _opn.session_for(device)
        rows = _opn.search_all(sess, device, "firewall/group/search_item")
        return [{"name": r.get("ifname"),
                 "description": r.get("descr") or None,
                 "interface_members": [m for m in
                                       (r.get("members") or "").split(",") if m]}
                for r in rows if r.get("ifname")]

    def list_target_vrfs(self, *, device: dict) -> list[dict]:
        # No VRF concept; the sentinel keeps the UI's refresh quiet.
        return [{"name": "default", "interface_members": []}]

    def list_target_routes(self, *, device: dict) -> list[dict]:
        sess = _opn.session_for(device)
        rows = _opn.search_all(sess, device, "routes/routes/searchroute")
        out = []
        for row in rows:
            net = row.get("network")
            if not net:
                continue
            out.append({"prefix": net, "next_hop": row.get("gateway"),
                        "iface": None, "vr": "default",
                        "description": row.get("descr") or None})
        return out
