# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""OPNsense config.xml parser.

The config.xml is the only complete source for an OPNsense box. Its REST
API deliberately exposes a *separate* filter ruleset - the vendor's own
documentation says of it: "There's no relation to any of the rules being
managed via the core system", and "Rules not visible in the web interface
(Firewall > Automation) will not be returned by the API either". A box
that still holds classic rules would therefore import as half empty over
the API. The XML holds both rulesets, so that is what we read.

How the XML is laid out (verified against a live 26.7 box):

    opnsense/
      system/hostname
      interfaces/<logical>        # tag IS the name: wan, lan, opt1, lo0
        if, ipaddr, subnet, descr, enable, gateway
      ifgroups/ifgroupentry       # ifname, members (comma list), sequence
      staticroutes/route          # network, gateway, descr, disabled
      vlans/vlan                  # if, tag, vlanif, descr
      filter/rule                 # LEGACY rules (empty on a modern box)
      nat/outbound/mode           # LEGACY outbound-NAT mode
      nat/rule                    # LEGACY port forwards
      OPNsense/Firewall/Alias/aliases/alias
      OPNsense/Firewall/Filter/rules/rule        # the MVC ruleset
      OPNsense/Firewall/Filter/snatrules/rule    # source NAT lives HERE,
                                                 # not in a NAT branch

Entry points mirror webui/parsers/asa.py - the other file-sourced vendor:
``pre_parse`` for the upload wizard, one slice per object kind, and
``parse_full`` for the import/collect handlers. On top of those there is
``sanitize``, which MUST run before the XML is persisted anywhere.

Not to be confused with ``pyapp/gateshift/modules/parsers/opnsense.py`` -
that one reads pf *traffic logs* for the evidence pipeline. Same vendor,
unrelated job.
"""

import ipaddress
import re
import xml.etree.ElementTree as ET


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

# Nodes removed before the XML is stored. Paths are EXPLICIT on purpose: a
# name-pattern sweep over a live box matched `unboundplus/advanced/
# prefetchkey` and an IPsec syslog level named `tls`, neither of which is a
# secret - dropping them would silently change configuration semantics. So
# the list is curated and every addition is a deliberate decision.
#
# Paths are relative to the document root and may end in a wildcard segment
# to mean "every child at that level".
_SECRET_PATHS = (
    "system/user/password",          # bcrypt hashes
    "system/user/apikeys",           # API key/secret pairs
    "system/user/otp_seed",
    "system/group/password",
    "revision/user_apitoken",
    "cert/prv",                      # certificate private keys
    "ca/prv",
    "openvpn/openvpn-server/shared_key",
    "openvpn/openvpn-server/tls",
    "openvpn/openvpn-client/shared_key",
    "openvpn/openvpn-client/tls",
    "ipsec/phase1/pre-shared-key",
    "OPNsense/IPsec/preSharedKeys/preSharedKey/keyValue",
    "OPNsense/wireguard/server/servers/server/privkey",
    "OPNsense/wireguard/client/clients/client/psk",
    "snmpd/rocommunity",
    "snmpd/rwcommunity",
    "dhcpd/*/ddnsdomainkey",
    "OPNsense/Firewall/Alias/aliases/alias/password",   # URL-table auth
    "OPNsense/Firewall/Alias/aliases/alias/username",
)

# Anything whose tag matches this is reported by audit_secrets() even when
# it is not in _SECRET_PATHS - a tripwire for the next OPNsense version
# introducing a secret we do not know about yet. It never deletes.
_SECRET_TAG_HINT = re.compile(
    r"(passwo?rd|secret|privkey|^prv$|psk|pre.?shared|apikey|apitoken"
    r"|bindpw|community|sharedkey|otp_seed)", re.I)


def _iter_paths(root):
    """Yield (path, parent, element) for every element below root."""
    stack = [("", root)]
    while stack:
        prefix, el = stack.pop()
        for ch in el:
            path = f"{prefix}/{ch.tag}" if prefix else ch.tag
            yield path, el, ch
            stack.append((path, ch))


def _path_matches(path: str, pattern: str) -> bool:
    pp, tt = pattern.split("/"), path.split("/")
    if len(pp) != len(tt):
        return False
    return all(p == "*" or p == t for p, t in zip(pp, tt))


def sanitize(text: str) -> tuple[str, dict]:
    """Strip every secret-bearing node from an OPNsense config.xml.

    Returns the cleaned XML and a report ``{"removed": {path: count},
    "unknown": [path, ...]}``. ``unknown`` lists nodes that look secret by
    name but are not on the curated list - they are NOT removed, they are
    reported, so a new vendor release cannot quietly smuggle a secret past
    us without somebody noticing.

    Must run before the XML is persisted: an OPNsense config carries
    WireGuard private keys, IPsec PSKs, certificate private keys and
    password hashes, and Gateshift promises never to store those
    (SECURITY.md).
    """
    root = ET.fromstring(text)
    removed: dict[str, int] = {}
    unknown: list[str] = []

    for path, parent, el in list(_iter_paths(root)):
        if any(_path_matches(path, p) for p in _SECRET_PATHS):
            # Blank the whole node, not just its text: OPNsense stores some
            # secrets as a subtree (system/user/apikeys holds one <item>
            # per key/secret pair), so clearing the text alone would leave
            # the values sitting in the children.
            el.text = ""
            for child in list(el):
                el.remove(child)
            el.set("gs-redacted", "1")
            removed[path] = removed.get(path, 0) + 1
        elif _SECRET_TAG_HINT.search(el.tag) and (el.text or "").strip():
            unknown.append(path)

    return ET.tostring(root, encoding="unicode"), {
        "removed": removed, "unknown": sorted(set(unknown))}


def audit_secrets(text: str) -> list[str]:
    """Paths that still hold a value and look like a secret. Test hook."""
    root = ET.fromstring(text)
    return sorted({p for p, _, el in _iter_paths(root)
                   if _SECRET_TAG_HINT.search(el.tag)
                   and (el.text or "").strip()})


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

def pre_parse(text: str) -> dict:
    """Identity bootstrap for the upload wizard - cheap, no full parse."""
    warnings: list[str] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return {"hostname": None, "is_opnsense": False, "version": None,
                "warnings": [f"not valid XML: {exc}"]}

    if root.tag != "opnsense":
        return {"hostname": None, "is_opnsense": False, "version": None,
                "warnings": [f"root element is <{root.tag}>, expected "
                             "<opnsense>: this is not an OPNsense "
                             "config.xml"]}

    host = _text(root, "system/hostname")
    domain = _text(root, "system/domain")
    if not host:
        warnings.append("no <system><hostname> in the config")
    if root.find("OPNsense/Firewall/Filter") is None:
        warnings.append(
            "no OPNsense/Firewall/Filter section: this config predates the "
            "MVC firewall. Only classic rules will be imported")

    return {
        "hostname": f"{host}.{domain}" if host and domain else host,
        "is_opnsense": True,
        # The config carries no product version - only who last changed it
        # and why. The version comes from /api/core/firmware/status when we
        # have a live box; an uploaded config simply has none.
        "version": None,
        "revision": _text(root, "revision/time") or None,
        "warnings": warnings,
    }


def _text(el, path, default=""):
    if el is None:
        return default
    found = el.find(path)
    return (found.text or "").strip() if found is not None and found.text \
        else default


def _flag(el, path) -> bool:
    return _text(el, path) in ("1", "yes", "true", "on")


# --------------------------------------------------------------------------
# Objects (aliases)
# --------------------------------------------------------------------------

# Alias types we can represent. Everything else goes to the drop channel
# with its name, per the vendor guide ("never silently dropped").
_ADDRESS_ALIAS_TYPES = {"host", "network", "networkgroup"}
_PORT_ALIAS_TYPES = {"port"}


def _literal_name(value: str) -> str:
    """A stable object name for a raw address, so a group can reference it."""
    return "h-" + value.replace("/", "-").replace(".", "_").replace(":", "_")


def _addr_kind(value: str) -> str:
    """Classify an alias entry the way the shared object model names it."""
    v = (value or "").strip()
    if "-" in v and not v.startswith("-"):
        return "ip-range"
    if "/" in v or v.replace(".", "").isdigit():
        return "ip-netmask"
    return "fqdn"


def parse_objects(root) -> dict:
    """Aliases -> address / address_group objects.

    An OPNsense alias is a named list, so it maps onto Gateshift's group
    notion rather than onto a single object: a one-entry alias becomes an
    ``address``, a multi-entry alias an ``address_group`` holding the
    literals. Literal members are fine here - the reference model already
    tolerates raw IP literals for this vendor (webui/refmodel.py).

    Port aliases are NOT emitted as objects. OPNsense port aliases carry
    no protocol; the protocol lives on the referencing rule. They are
    returned in ``port_aliases`` so parse_rules can expand them into real
    (proto, port) services.
    """
    objects: list[dict] = []
    port_aliases: dict[str, list[str]] = {}
    drops: dict[str, list[str]] = {}
    synth: dict[str, dict] = {}
    seen_names = {(_text(a, "name") or "")
                  for a in root.findall(
                      "OPNsense/Firewall/Alias/aliases/alias")}

    for al in root.findall("OPNsense/Firewall/Alias/aliases/alias"):
        name = _text(al, "name")
        if not name:
            continue
        atype = _text(al, "type")
        entries = [e.strip() for e in (_text(al, "content") or "").split("\n")
                   if e.strip()]
        descr = _text(al, "description")

        if not _flag(al, "enabled"):
            drops.setdefault("alias_disabled", []).append(name)
            continue
        if atype in _PORT_ALIAS_TYPES:
            port_aliases[name] = entries
            continue
        if atype not in _ADDRESS_ALIAS_TYPES:
            drops.setdefault(f"alias_type_{atype or 'unknown'}", []).append(name)
            continue
        if not entries:
            drops.setdefault("alias_empty", []).append(name)
            continue

        # The value is the vendor-agnostic object BODY, the same shape the
        # other parsers emit - a plain string here would reach the drivers
        # as one and break rendering.
        if len(entries) == 1:
            objects.append({
                "obj_type": "address", "name": name,
                "value": {"type": _addr_kind(entries[0]),
                          "value": entries[0], "description": descr},
                "source_vendor_id": al.get("uuid") or name})
        else:
            # A multi-entry alias is a group, and its entries may be raw
            # addresses. Gateshift's own reference model tolerates those
            # for this vendor, but a target does not: FortiGate rejects a
            # group member that is not a named object, and it is not the
            # only one. So each literal becomes an address object and the
            # group references it by name - the same thing the ASA parser
            # does for its inline literals.
            members = []
            for entry in entries:
                if entry in seen_names:
                    members.append(entry)
                    continue
                member = _literal_name(entry)
                synth.setdefault(member, {
                    "obj_type": "address", "name": member,
                    "value": {"type": _addr_kind(entry), "value": entry,
                              "description": f"member of {name}"}})
                members.append(member)
            objects.append({
                "obj_type": "address_group", "name": name,
                "value": {"type": "static", "members": members,
                          "description": descr},
                "source_vendor_id": al.get("uuid") or name})

    return {"objects": objects + list(synth.values()),
            "port_aliases": port_aliases, "drops": drops}


# --------------------------------------------------------------------------
# Interfaces, zones, routes
# --------------------------------------------------------------------------

def parse_interfaces(root) -> dict:
    """Interfaces and interface groups.

    Two things come out of here. The interfaces themselves (the tag name
    is the logical name rules bind to - `lan`, `opt1` - while `<if>` is
    the physical device), and the interface GROUPS, which are OPNsense's
    zone equivalent: rules bind to a group exactly as they bind to an
    interface, and the group lands in its own band of the pf evaluation
    order. We surface them as zones.
    """
    interfaces: list[dict] = []
    zones: list[dict] = []
    drops: dict[str, list[str]] = {}

    # OPNsense mirrors each interface group into <interfaces> as a virtual
    # entry. Skipping those is not a loss - they come back below as zones -
    # so they must not be reported as dropped interfaces.
    group_names = {_text(g, "ifname")
                   for g in root.findall("ifgroups/ifgroupentry")}

    ifs = root.find("interfaces")
    for el in (list(ifs) if ifs is not None else []):
        name = el.tag
        if name in group_names:
            continue
        if _flag(el, "virtual") or _flag(el, "internal_dynamic"):
            drops.setdefault("virtual_interface", []).append(name)
            continue

        ips: list[str] = []
        addr, plen = _text(el, "ipaddr"), _text(el, "subnet")
        dhcp = addr.lower() in ("dhcp", "dhcp6")
        if addr and not dhcp and plen:
            try:
                ips.append(str(ipaddress.ip_interface(f"{addr}/{plen}")))
            except ValueError:
                drops.setdefault("unparsable_address", []).append(
                    f"{name}={addr}/{plen}")
        v6, v6len = _text(el, "ipaddrv6"), _text(el, "subnetv6")
        if v6 and v6.lower() not in ("dhcp6", "track6", "slaac") and v6len:
            drops.setdefault("ipv6_address", []).append(f"{name}={v6}/{v6len}")

        interfaces.append({
            "name":         name,
            "type":         "physical",
            "zone":         None,
            "description":  _text(el, "descr") or None,
            "ips":          ips,
            "shutdown":     not _flag(el, "enable"),
            "enabled":      _flag(el, "enable"),
            "dhcp_enabled": dhcp,
            "raw_extras":   {"opn_device": _text(el, "if") or None,
                             "opn_gateway": _text(el, "gateway") or None},
        })

    # VLANs are their own section and reference the parent by device name;
    # map them back to the logical interface that carries the device.
    dev_to_logical = {(i["raw_extras"] or {}).get("opn_device"): i["name"]
                      for i in interfaces}
    for vl in root.findall("vlans/vlan"):
        vlanif, parent_dev, tag = (_text(vl, "vlanif"), _text(vl, "if"),
                                   _text(vl, "tag"))
        if not vlanif:
            continue
        logical = dev_to_logical.get(vlanif)
        for i in interfaces:
            if i["name"] == logical:
                i["type"] = "vlan"
                i["raw_extras"]["opn_vlan_tag"] = tag
                i["raw_extras"]["opn_vlan_parent"] = parent_dev
                break
        else:
            drops.setdefault("vlan_unassigned", []).append(
                f"{vlanif} (tag {tag}), not assigned to an interface")

    known = {i["name"] for i in interfaces}
    for gr in root.findall("ifgroups/ifgroupentry"):
        gname = _text(gr, "ifname")
        if not gname:
            continue
        members = [m.strip() for m in (_text(gr, "members") or "").split(",")
                   if m.strip()]
        missing = [m for m in members if m not in known]
        if missing:
            drops.setdefault("group_member_unknown", []).append(
                f"{gname}: {', '.join(missing)}")
        zones.append({
            "name":              gname,
            "description":       _text(gr, "descr") or None,
            "interface_members": [m for m in members if m in known],
            "raw_extras":        {"opn_group_sequence": _text(gr, "sequence")},
        })
        for i in interfaces:
            if i["name"] in members and not i["zone"]:
                i["zone"] = gname

    return {"interfaces": interfaces, "zones": zones, "drops": drops}


def parse_routes(root) -> dict:
    """Static routes. OPNsense names a gateway; the next hop is resolved
    from the gateway definition, falling back to the gateway name so the
    reference survives even when the gateway block is missing."""
    routes: list[dict] = []
    drops: dict[str, list[str]] = {}

    gateways = {}
    for gw in root.findall("gateways/gateway_item"):
        gname = _text(gw, "name")
        if gname:
            gateways[gname] = {"ip": _text(gw, "gateway"),
                               "iface": _text(gw, "interface")}

    for rt in root.findall("staticroutes/route"):
        net = _text(rt, "network")
        gwname = _text(rt, "gateway")
        if not net:
            continue
        if rt.find("disabled") is not None:
            drops.setdefault("route_disabled", []).append(net)
            continue
        try:
            prefix = ipaddress.ip_network(net, strict=False)
        except ValueError:
            drops.setdefault("unparsable_route", []).append(net)
            continue
        if prefix.version == 6:
            drops.setdefault("ipv6_route", []).append(net)
            continue
        gw = gateways.get(gwname, {})
        routes.append({
            "prefix":   str(prefix),
            "plen":     prefix.prefixlen,
            "ip_from":  int(prefix.network_address),
            "ip_to":    int(prefix.broadcast_address),
            "iface":    gw.get("iface") or None,
            "next_hop": gw.get("ip") or gwname or None,
            "vr":       "default",
        })

    return {"routes": routes, "drops": drops}


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

# pf evaluates in bands; a rule's band decides its place regardless of its
# own sequence number. Confirmed on a live box: a rule bound to the group
# `gstrust` (group sequence 10) came back with prio_group 300010 and
# sort_order "300010.0000001" for sequence 1.
_BAND_FLOATING = 200000
_BAND_GROUP = 300000
_BAND_INTERFACE = 400000

_ACTION_MAP = {"pass": "allow", "block": "deny", "reject": "reject"}


def parse_rules(root, port_aliases: dict | None = None,
                iface_networks: dict | None = None) -> dict:
    """Filter rules from both rulesets, in pf's effective order.

    Both the MVC ruleset (OPNsense/Firewall/Filter) and the classic one
    (filter/rule) are read; on a box that has been migrated the latter is
    empty. Ordering is the part that matters: a rule's position is its
    band plus its own sequence, not the document order. We reproduce the
    band arithmetic here because the XML has no sort key - when Gateshift
    talks to a live box, the API hands `sort_order` over directly and
    that is authoritative.
    """
    port_aliases = port_aliases or {}
    iface_networks = iface_networks or {}
    rules: list[dict] = []
    drops: dict[str, list[str]] = {}
    # A pf rule carries its protocol and port inline, with no named object
    # behind them. Targets that expect a service OBJECT (PAN-OS rejects a
    # bare "tcp/80" reference outright) need one, so the pairs a rule uses
    # are collected here and emitted alongside the aliases - the same thing
    # the ASA parser does for its ACE literals.
    services_seen: dict[str, dict] = {}

    group_seq = {_text(g, "ifname"): _text(g, "sequence") or "0"
                 for g in root.findall("ifgroups/ifgroupentry")}

    def band_of(iface: str) -> int:
        if not iface:
            return _BAND_FLOATING
        if "," in iface:
            return _BAND_FLOATING          # multi-interface = floating
        if iface in group_seq:
            return _BAND_GROUP + int(group_seq[iface] or 0)
        return _BAND_INTERFACE

    collected = [(el, False) for el
                 in root.findall("OPNsense/Firewall/Filter/rules/rule")]
    collected += [(el, True) for el in root.findall("filter/rule")]

    for el, is_legacy in collected:
        name = _text(el, "description") or el.get("uuid") or "rule"
        action = _text(el, "action") or "pass"
        iface = _text(el, "interface")

        if action == "match":
            # pf's `match` marks traffic without deciding it - there is no
            # equivalent on any target we push to.
            drops.setdefault("action_match", []).append(name)
            continue
        if _text(el, "ipprotocol") == "inet6":
            drops.setdefault("ipv6_rule", []).append(name)
            continue
        if is_legacy and not _flag(el, "quick"):
            # Without `quick` pf keeps looking and the LAST match wins.
            # Every target we push to is first-match, so re-ordering these
            # would change their meaning. Surface them instead.
            drops.setdefault("legacy_last_match_rule", []).append(name)
            continue

        proto = _text(el, "protocol")
        sources, s_drop = _endpoint(el, "source", port_aliases, proto,
                                    iface_networks)
        dests, d_drop = _endpoint(el, "destination", port_aliases, proto,
                                  iface_networks)
        services = []
        for proto, port in (s_drop.pop("services", [])
                            + d_drop.pop("services", [])):
            svc_name = f"svc-{proto}-{port}"
            services_seen.setdefault(svc_name, {
                "obj_type": "service", "name": svc_name,
                "value": {"protocol": proto, "port": port,
                          "description": "from an OPNsense rule"}})
            services.append(svc_name)
        for k, v in list(s_drop.items()) + list(d_drop.items()):
            drops.setdefault(k, []).extend(v)

        band = band_of(iface)
        try:
            seq = int(_text(el, "sequence") or "0")
        except ValueError:
            seq = 0

        ifaces = [i for i in iface.split(",") if i] if iface else []
        direction = _text(el, "direction") or "in"
        src_zones = ifaces if direction in ("in", "any") else []
        dst_zones = ifaces if direction == "out" else []

        rules.append({
            "rule_name":      name,
            "seq_num":        band * 1000 + seq,
            "action":         _ACTION_MAP.get(action, "deny"),
            "src_zones":      src_zones,
            "dst_zones":      dst_zones,
            "sources":        sources,
            "destinations":   dests,
            "services":       services,
            "applications":   [],
            "description":    _text(el, "description") or None,
            "disabled":       not _flag(el, "enabled"),
            "tags":           [c for c in
                               (_text(el, "categories") or "").split(",") if c],
            "negate_source":      _flag(el, "source_not"),
            "negate_destination": _flag(el, "destination_not"),
            "schedule":       _text(el, "sched") or None,
            "raw_extras":     {
                "opn_direction":  direction,
                "opn_interface":  iface or None,
                "opn_quick":      _flag(el, "quick"),
                "opn_gateway":    _text(el, "gateway") or None,
                "opn_statetype":  _text(el, "statetype") or None,
                "opn_legacy":     is_legacy,
                "log_setting":    "log" if _flag(el, "log") else None,
            },
            "source_vendor_id": el.get("uuid") or name,
            "dropped_inputs":   [],
        })

    rules.sort(key=lambda r: r["seq_num"])
    for i, r in enumerate(rules, 1):
        r["seq_num"] = i
    return {"rules": rules, "drops": drops,
            "service_objects": list(services_seen.values())}


def _endpoint(el, side: str, port_aliases: dict, proto: str,
              iface_networks: dict | None = None):
    """One side of a rule -> (address refs, {drop_key: [...], services: [...]}).

    `any` collapses to an empty list (Gateshift's own 'any'). A port that
    names an alias is expanded here, because the protocol that turns a
    bare port into a service only exists on the rule.

    OPNsense also accepts interface shorthands where an address is
    expected: a bare interface name means "the network behind it" and
    `<iface>ip` means the interface's own address. Those are resolved to
    real prefixes - left alone they would import as references to
    something that does not exist.
    """
    iface_networks = iface_networks or {}
    drops: dict[str, list] = {"services": []}
    net = _text(el, f"{side}_net")
    if net in ("", "any"):
        addrs = []
    elif net in iface_networks or net[:-2] in iface_networks:
        want_ip = net.endswith("ip") and net not in iface_networks
        key = net[:-2] if want_ip else net
        val = iface_networks[key].get("ip" if want_ip else "net")
        if val:
            addrs = [val]
        else:
            addrs = [net]
            drops.setdefault("interface_shorthand_unresolved", []).append(
                f"{_text(el, 'description') or '?'}:{net}")
    else:
        addrs = [net]

    port = _text(el, f"{side}_port")
    if port:
        protos = ([] if proto.lower() in ("any", "")
                  else [proto.lower()] if proto.lower() != "tcp/udp"
                  else ["tcp", "udp"])
        ports = port_aliases.get(port, [port])
        if not protos:
            drops.setdefault("port_without_protocol", []).append(
                f"{_text(el, 'description') or '?'}:{port}")
        for pr in protos:
            for pt in ports:
                drops["services"].append((pr, pt.replace(":", "-")))
    return addrs, drops


# --------------------------------------------------------------------------
# NAT
# --------------------------------------------------------------------------

def parse_nat(root) -> dict:
    """Source NAT (MVC) and classic port forwards.

    Source NAT lives under Filter/snatrules - not in a NAT branch of its
    own. Port forwards are the other way round: they are still the
    classic nat/rule tree, and on 26.7 they have no API at all, which is
    why they can be read but not pushed.

    Two keys here are writer contract rather than vendor detail, and both
    cost a failed import to discover: device_import_run indexes
    ``position`` directly, so a rule without one raises KeyError instead
    of defaulting, and it reads vendor extras from ``properties`` - a
    ``raw_extras`` dict (which rules do use) is silently ignored here.
    """
    nat_rules: list[dict] = []
    drops: dict[str, list[str]] = {}

    mode = _text(root, "nat/outbound/mode")
    for el in root.findall("OPNsense/Firewall/Filter/snatrules/rule"):
        name = _text(el, "description") or el.get("uuid") or "snat"
        if _flag(el, "nonat"):
            drops.setdefault("nat_exclusion_rule", []).append(name)
            continue
        src, dst = _text(el, "source_net"), _text(el, "destination_net")
        egress = [i for i in (_text(el, "interface") or "").split(",") if i]
        target = _text(el, "target")
        nat_rules.append({
            "position":      len(nat_rules),
            "name":          name,
            "nat_type":      "snat",
            "src_zones":     [],
            "dst_zones":     egress,
            "orig_src":      [] if src in ("", "any") else [src],
            "orig_dst":      [] if dst in ("", "any") else [dst],
            "orig_service":  [],
            "trans_src":     target or None,
            # An OPNsense SNAT target is usually the egress interface itself
            # ("hide behind wan"); only an explicit address is a static IP.
            "trans_src_type": ("interface-address" if target in egress
                               else "static-ip" if target else "none"),
            "trans_dst":     None,
            "disabled":      not _flag(el, "enabled"),
            "description":   _text(el, "description") or None,
            "properties":    {"opn_staticnatport": _flag(el, "staticnatport"),
                              "opn_outbound_mode": mode or None},
            "source_vendor_id": el.get("uuid") or name,
        })

    for el in root.findall("nat/rule"):
        name = _text(el, "descr") or "portforward"
        tgt = _text(el, "target")
        nat_rules.append({
            "position":      len(nat_rules),
            "name":          name,
            "nat_type":      "dnat",
            "src_zones":     [i for i in (_text(el, "interface") or "").split(",") if i],
            "dst_zones":     [],
            "orig_src":      [],
            "orig_dst":      [d for d in [_text(el, "destination/address")] if d],
            "orig_service":  [p for p in [_text(el, "destination/port")] if p],
            "trans_src":     None,
            "trans_src_type": "none",
            "trans_dst":     tgt or None,
            "trans_dst_port": _text(el, "local-port") or None,
            "disabled":      el.find("disabled") is not None,
            "description":   _text(el, "descr") or None,
            "properties":    {"opn_legacy_nat": True},
            "source_vendor_id": name,
        })

    return {"nat_rules": nat_rules, "drops": drops}


# --------------------------------------------------------------------------
# Combined entry point
# --------------------------------------------------------------------------

def parse_full(text: str) -> dict:
    """Everything, in the shape device_import_run expects.

    Returns objects, rules, interfaces, zones, routes, vrfs, nat_rules and
    drops. OPNsense has no VRF concept, so the network strand carries the
    same single 'default' sentinel that PA/CP/ASA use.
    """
    root = ET.fromstring(text)

    obj = parse_objects(root)
    ifc = parse_interfaces(root)
    # Rules need the interfaces first: OPNsense writes shorthands like
    # `lan` / `lanip` where an address belongs, and those only resolve
    # once we know what each interface is addressed with.
    iface_networks = {}
    for i in ifc["interfaces"]:
        cidr = (i["ips"] or [None])[0]
        if cidr:
            net = ipaddress.ip_interface(cidr)
            iface_networks[i["name"]] = {"net": str(net.network),
                                         "ip": str(net.ip)}
        else:
            iface_networks[i["name"]] = {"net": None, "ip": None}
    rul = parse_rules(root, obj["port_aliases"], iface_networks)
    rts = parse_routes(root)
    nat = parse_nat(root)

    merged: dict[str, list[str]] = {}
    for part in (obj["drops"], rul["drops"], ifc["drops"], rts["drops"],
                 nat["drops"]):
        for key, names in part.items():
            merged.setdefault(key, []).extend(names)

    return {
        "objects":    obj["objects"] + rul["service_objects"],
        "rules":      rul["rules"],
        "interfaces": ifc["interfaces"],
        "zones":      ifc["zones"],
        "routes":     rts["routes"],
        "vrfs":       [{"name": "default", "interface_members": []}],
        "nat_rules":  nat["nat_rules"],
        "drops":      merged,
    }
