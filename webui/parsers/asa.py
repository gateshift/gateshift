# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Cisco ASA running-config parser.

Slice 1: pre_parse() only - identity bootstrap for the upload wizard.
Later slices add the full token-engine for objects / ACLs / interfaces /
NAT under additional entry points.
"""

import ipaddress
import re


_HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)\s*$")

# Header markers that strongly indicate a Cisco ASA `show running-config`
# dump. We do NOT require any of these - some configs land without the
# ": Saved" preamble (e.g. captured via SSH paging) - but we surface a
# warning when none are present so the user can confirm vendor before
# proceeding.
_ASA_HEADER_MARKERS = (
    re.compile(r"^ASA Version\b"),
    re.compile(r"^:\s*Saved\b"),
    re.compile(r"^:\s*Hardware:"),
    re.compile(r"^:\s*Serial Number:"),
    re.compile(r"^PIX Version\b"),
)


def pre_parse(text: str) -> dict:
    """Identity bootstrap pass for the ASA upload wizard.

    Scans only enough lines to extract the hostname and confirm the
    vendor. Cheap - no tokenisation, no block parsing.

    Returns
    -------
    dict with keys:
      hostname:  str | None  - value of `hostname X` line, or None
      header_ok: bool        - at least one ASA-style header marker seen
      errors:    list[str]   - blocker conditions (caller must reject)
      warnings:  list[str]   - non-blocking notices for the UI
    """
    hostname: str | None = None
    header_ok = False
    errors: list[str] = []
    warnings: list[str] = []

    if not text:
        errors.append("Empty config - upload an ASA `show running-config` dump.")
        return {"hostname": None, "header_ok": False,
                "errors": errors, "warnings": warnings}

    for raw in text.splitlines():
        # Strip CR (Windows-saved configs) and trailing whitespace only.
        # Leading whitespace matters for block-detection in later slices,
        # but pre_parse cares about top-level lines only - `hostname` and
        # header markers always sit at column 0.
        line = raw.rstrip()
        if not line or line.startswith(" ") or line.startswith("\t"):
            continue

        if not header_ok:
            for pat in _ASA_HEADER_MARKERS:
                if pat.match(line):
                    header_ok = True
                    break

        if hostname is None:
            m = _HOSTNAME_RE.match(line)
            if m:
                hostname = m.group(1)

        # Done as soon as both signals are settled - no point reading
        # 50k more lines just to confirm what we already know.
        if hostname is not None and header_ok:
            break

    if hostname is None:
        errors.append("ASA config must contain a `hostname` line. "
                      "Add `hostname <name>` at column 0 and re-upload.")

    if not header_ok:
        warnings.append("No ASA header marker found "
                        "(expected one of: `ASA Version`, `: Saved`, "
                        "`: Hardware:`). Vendor sanity check failed - "
                        "proceed only if you are sure this is an ASA config.")

    return {
        "hostname": hostname,
        "header_ok": header_ok,
        "errors": errors,
        "warnings": warnings,
    }


# ── Slice 2: Objects + Object-Groups ─────────────────────────────────
#
# Token-engine basics. Top-level blocks open on a column-0 line and
# contain indented child lines until the next column-0 line or a
# comment/banner line (`!` or `:`). Lines outside any block are
# single-line blocks with no children.
#
# Object-Group members can be inline IP literals (`network-object
# 10.30.0.0 255.255.0.0`) - these are synthesized into deterministic
# address/service objects so the downstream group member list is always
# a list of names (PA convention; the V1 optimizer relies on it).


def _iter_blocks(text: str):
    """Yield (header_line, [child_lines]) tuples from an ASA config.

    Header = column-0 non-blank, non-comment line. Children = subsequent
    indented lines. A `!` or `:` at column 0 terminates the current block.
    Blank lines are ignored (don't terminate, don't add to children).
    """
    cur_header: str | None = None
    cur_children: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r\n").rstrip()
        if not line:
            continue
        if line[0] in ("!", ":"):
            if cur_header is not None:
                yield cur_header, cur_children
                cur_header = None
                cur_children = []
            continue
        if line[0] in (" ", "\t"):
            if cur_header is not None:
                cur_children.append(line.strip())
            continue
        if cur_header is not None:
            yield cur_header, cur_children
        cur_header = line
        cur_children = []
    if cur_header is not None:
        yield cur_header, cur_children


def _mask_to_prefix(mask: str) -> int | None:
    """Convert a dotted-decimal netmask to a CIDR prefix length.

    Returns None for non-contiguous masks (e.g. 255.0.0.255) so the
    caller can drop them rather than silently emitting bogus CIDRs.
    """
    parts = mask.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    m = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    inverted = (~m) & 0xFFFFFFFF
    if (inverted & (inverted + 1)) != 0:
        return None
    prefix = 0
    while m & 0x80000000:
        prefix += 1
        m = (m << 1) & 0xFFFFFFFF
    return prefix


def _inline_host_name(ip: str) -> str:
    return f"_inline_H_{ip}"


def _inline_net_name(ip: str, prefix: int) -> str:
    return f"_inline_N_{ip}_{prefix}"


def _inline_range_name(lo: str, hi: str) -> str:
    return f"_inline_R_{lo}-{hi}"


def _inline_service_name(proto: str, port: str) -> str:
    return f"_inline_S_{proto}_{port}"


# ASA named-port aliases. Operator commands such as `eq https` /
# `range 135 netbios-ssn` are valid; downstream resolution requires
# numeric ports, so we resolve at parse time. List covers the common
# IANA names ASA accepts for tcp/udp.
_ASA_PORT_ALIASES: dict[str, str] = {
    # tcp/udp shared
    "domain":         "53",
    "echo":           "7",
    "discard":        "9",
    "sunrpc":         "111",
    "tacacs":         "49",
    "talk":           "517",
    "kerberos":       "750",
    "sip":            "5060",
    "pim-auto-rp":    "496",
    "nfs":            "2049",
    "cifs":           "3020",
    # tcp
    "ftp-data":       "20",
    "ftp":            "21",
    "ssh":            "22",
    "telnet":         "23",
    "smtp":           "25",
    "whois":          "43",
    "www":            "80",
    "http":           "80",
    "pop2":           "109",
    "pop3":           "110",
    "ident":          "113",
    "nntp":           "119",
    "msrpc":          "135",
    "netbios-ssn":    "139",
    "imap4":          "143",
    "ldap":           "389",
    "https":          "443",
    "exec":           "512",
    "login":          "513",
    "cmd":            "514",
    "lpd":            "515",
    "klogin":         "543",
    "kshell":         "544",
    "rtsp":           "554",
    "ldaps":          "636",
    "lotusnotes":     "1352",
    "citrix-ica":     "1494",
    "h323":           "1720",
    "pptp":           "1723",
    "sqlnet":         "1521",
    "pcanywhere-data": "5631",
    "ctiqbe":         "2748",
    "irc":            "194",
    "finger":         "79",
    "hostname":       "101",
    "uucp":           "540",
    "rsh":            "514",
    "daytime":        "13",
    "chargen":        "19",
    "gopher":         "70",
    "bgp":            "179",
    "aol":            "5190",
    # udp
    "bootps":         "67",
    "bootpc":         "68",
    "tftp":           "69",
    "ntp":            "123",
    "netbios-ns":     "137",
    "netbios-dgm":    "138",
    "snmp":           "161",
    "snmptrap":       "162",
    "xdmcp":          "177",
    "isakmp":         "500",
    "syslog":         "514",
    "rip":            "520",
    "biff":           "512",
    "who":            "513",
    "time":           "37",
    "nameserver":     "42",
    "radius":         "1812",
    "radius-acct":    "1813",
    "mobile-ip":      "434",
    "secureid-udp":   "5510",
    "pcanywhere-status": "5632",
    "dnsix":          "195",
    "tftp-data":      "69",
}


def _resolve_port_alias(tok: str) -> str:
    """Resolve a single ASA port token to its numeric form.

    Accepts an optional operator prefix (`<` / `>` / `!`). Aliases that
    contain `-` themselves (`netbios-ssn`, `echo-reply`, …) are looked
    up as a single token; range strings (`lo-hi`) must be assembled by
    the caller AFTER resolving each side, since `LO`/`HI` cannot be
    disambiguated from a hyphenated alias once joined.
    """
    if not tok:
        return tok
    op_prefix = ""
    if tok[0] in ("<", ">", "!"):
        op_prefix, tok = tok[0], tok[1:]
    if tok.isdigit():
        return f"{op_prefix}{tok}"
    return f"{op_prefix}{_ASA_PORT_ALIASES.get(tok, tok)}"


def _add_inline(inlines: dict, obj: dict) -> str:
    """Register a synthesized inline object (idempotent by name)."""
    inlines.setdefault(obj["name"], obj)
    return obj["name"]


def _parse_network_object(children: list[str], name: str,
                          drops: dict) -> dict | None:
    description = ""
    value: dict | None = None
    for c in children:
        toks = c.split()
        if not toks:
            continue
        kw = toks[0]
        if kw == "description":
            description = c[len("description"):].strip()
        elif kw == "host" and len(toks) >= 2:
            value = {"type": "ip-netmask", "value": f"{toks[1]}/32"}
        elif kw == "subnet" and len(toks) >= 3:
            prefix = _mask_to_prefix(toks[2])
            if prefix is None:
                drops.setdefault("invalid_netmask", []).append(name)
                return None
            value = {"type": "ip-netmask", "value": f"{toks[1]}/{prefix}"}
        elif kw == "range" and len(toks) >= 3:
            value = {"type": "ip-range", "value": f"{toks[1]}-{toks[2]}"}
        elif kw == "fqdn":
            drops.setdefault("fqdn_address_object", []).append(name)
            return None
        # Other keywords (nat - handled in Slice 5) are ignored here.
    if value is None:
        return None
    value["description"] = description
    return {"obj_type": "address", "name": name, "value": value}


_PROTO_NUM_TO_NAME = {"6": "tcp", "17": "udp"}


def _is_tcp_or_udp(proto: str) -> bool:
    return proto in ("tcp", "udp") or proto in _PROTO_NUM_TO_NAME


def _normalize_proto(proto: str) -> str:
    return _PROTO_NUM_TO_NAME.get(proto, proto)


def _parse_service_object(children: list[str], name: str,
                          drops: dict) -> dict | None:
    description = ""
    value: dict | None = None
    for c in children:
        toks = c.split()
        if not toks:
            continue
        if toks[0] == "description":
            description = c[len("description"):].strip()
            continue
        if toks[0] != "service" or len(toks) < 2:
            continue
        proto = toks[1]
        if not _is_tcp_or_udp(proto):
            drops.setdefault("icmp_service_object"
                             if proto == "icmp"
                             else "unsupported_service_proto",
                             []).append(name)
            return None
        proto = _normalize_proto(proto)

        # Walk remaining tokens: optional `source <PORT_SPEC>` and/or
        # `destination <PORT_SPEC>`. ASA permits source-only, dest-only,
        # or both.
        port_dst: str | None = None
        port_src: str | None = None
        i = 2
        while i < len(toks):
            t = toks[i]
            if t in ("source", "destination"):
                if i + 2 >= len(toks):
                    break
                op = toks[i + 1]
                if op in ("eq", "lt", "gt"):
                    p = toks[i + 2]
                    if op == "lt":
                        p = f"<{p}"
                    elif op == "gt":
                        p = f">{p}"
                    if t == "source":
                        port_src = p
                    else:
                        port_dst = p
                    i += 3
                elif op == "range" and i + 3 < len(toks):
                    p = f"{toks[i + 2]}-{toks[i + 3]}"
                    if t == "source":
                        port_src = p
                    else:
                        port_dst = p
                    i += 4
                else:
                    i += 1
            else:
                i += 1
        if port_dst is None and port_src is None:
            # `service tcp` with no qualifier means all ports - model as
            # port "any" so downstream can treat as proto-only.
            port_dst = "any"
        value = {"protocol": proto,
                 "port": _resolve_port_alias(port_dst or "any")}
        if port_src:
            value["source_port"] = _resolve_port_alias(port_src)
        break

    if value is None:
        return None
    value["description"] = description
    return {"obj_type": "service", "name": name, "value": value}


def _parse_network_group(children: list[str], name: str,
                         inlines: dict, drops: dict) -> dict:
    description = ""
    members: list[str] = []
    for c in children:
        toks = c.split()
        if not toks:
            continue
        kw = toks[0]
        if kw == "description":
            description = c[len("description"):].strip()
        elif kw == "network-object" and len(toks) >= 2:
            sub = toks[1]
            if sub == "host" and len(toks) >= 3:
                mname = _inline_host_name(toks[2])
                _add_inline(inlines, {
                    "obj_type": "address", "name": mname,
                    "value": {"type": "ip-netmask",
                              "value": f"{toks[2]}/32",
                              "description": ""}})
                members.append(mname)
            elif sub == "object" and len(toks) >= 3:
                members.append(toks[2])
            elif len(toks) >= 3:
                # `network-object A.B.C.D MASK` (literal subnet)
                prefix = _mask_to_prefix(toks[2])
                if prefix is None:
                    drops.setdefault("invalid_netmask", []).append(name)
                    continue
                mname = _inline_net_name(toks[1], prefix)
                _add_inline(inlines, {
                    "obj_type": "address", "name": mname,
                    "value": {"type": "ip-netmask",
                              "value": f"{toks[1]}/{prefix}",
                              "description": ""}})
                members.append(mname)
        elif kw == "group-object" and len(toks) >= 2:
            members.append(toks[1])
    return {"obj_type": "address_group", "name": name,
            "value": {"type": "static", "members": members,
                      "description": description}}


def _service_member_from_port(proto: str, op_toks: list[str],
                              inlines: dict) -> str | None:
    """Build a synthesized service object from a `port-object` /
    inline-port tail and return its synthesized name.
    """
    if not op_toks:
        return None
    op = op_toks[0]
    if op == "eq" and len(op_toks) >= 2:
        port = op_toks[1]
    elif op == "range" and len(op_toks) >= 3:
        port = (f"{_resolve_port_alias(op_toks[1])}-"
                f"{_resolve_port_alias(op_toks[2])}")
    elif op == "lt" and len(op_toks) >= 2:
        port = f"<{op_toks[1]}"
    elif op == "gt" and len(op_toks) >= 2:
        port = f">{op_toks[1]}"
    else:
        return None
    return _inline_proto_port(proto, port, inlines)


def _parse_service_group(children: list[str], name: str,
                         proto_suffix: str | None,
                         inlines: dict, drops: dict) -> dict:
    description = ""
    members: list[str] = []

    # Expand tcp-udp into both protos for inline port-objects.
    if proto_suffix == "tcp-udp":
        expand_protos = ("tcp", "udp")
    elif proto_suffix in ("tcp", "udp"):
        expand_protos = (proto_suffix,)
    else:
        expand_protos = ()  # No proto in header → service-object children carry proto.

    for c in children:
        toks = c.split()
        if not toks:
            continue
        kw = toks[0]
        if kw == "description":
            description = c[len("description"):].strip()
        elif kw == "port-object" and expand_protos and len(toks) >= 2:
            for proto in expand_protos:
                mname = _service_member_from_port(proto, toks[1:], inlines)
                if mname:
                    members.append(mname)
        elif kw == "service-object" and len(toks) >= 2:
            sub = toks[1]
            if sub == "object" and len(toks) >= 3:
                members.append(toks[2])
                continue
            # `tcp-udp` shorthand - emit one service per proto so the
            # downstream resolver (which only knows tcp/udp) sees both.
            if sub == "tcp-udp":
                protos_iter: tuple[str, ...] = ("tcp", "udp")
            elif _is_tcp_or_udp(sub):
                protos_iter = (_normalize_proto(sub),)
            else:
                drops.setdefault(
                    "icmp_service_object" if sub == "icmp"
                    else "unsupported_service_proto",
                    []).append(name)
                continue
            # Find `destination` qualifier; ASA also allows `service-object
            # tcp` (proto-only, all ports) - synthesize a port-"any" svc.
            tail_idx = None
            for i in range(2, len(toks)):
                if toks[i] == "destination":
                    tail_idx = i + 1
                    break
            for proto in protos_iter:
                if tail_idx is None:
                    mname = _inline_service_name(proto, "any")
                    _add_inline(inlines, {
                        "obj_type": "service", "name": mname,
                        "value": {"protocol": proto, "port": "any",
                                  "description": ""}})
                    members.append(mname)
                else:
                    mname = _service_member_from_port(
                        proto, toks[tail_idx:], inlines)
                    if mname:
                        members.append(mname)
        elif kw == "group-object" and len(toks) >= 2:
            members.append(toks[1])

    value: dict = {"members": members, "description": description}
    if proto_suffix:
        value["proto_header"] = proto_suffix
    return {"obj_type": "service_group", "name": name, "value": value}


def parse_objects(text: str) -> dict:
    """Parse ASA object / object-group blocks.

    Returns
    -------
    dict with keys:
      objects: list of {obj_type, name, value} dicts (address, service,
               address_group, service_group). Includes synthesized
               inline objects emitted from group literals; their names
               are prefixed `_inline_` for traceability.
      drops:   dict {drop_category: [sample_names]} for V1 out-of-scope
               constructs (fqdn, icmp service, protocol group, …).
    """
    inlines: dict[str, dict] = {}
    named: list[dict] = []
    drops: dict[str, list[str]] = {}
    protocol_groups: dict[str, list[str]] = {}

    for header, children in _iter_blocks(text):
        toks = header.split()
        if not toks:
            continue
        if toks[0] == "object" and len(toks) >= 3:
            kind, name = toks[1], toks[2]
            if kind == "network":
                obj = _parse_network_object(children, name, drops)
                if obj:
                    named.append(obj)
            elif kind == "service":
                obj = _parse_service_object(children, name, drops)
                if obj:
                    named.append(obj)
        elif toks[0] == "object-group" and len(toks) >= 3:
            kind, name = toks[1], toks[2]
            if kind == "network":
                named.append(
                    _parse_network_group(children, name, inlines, drops))
            elif kind == "service":
                proto_suffix = (toks[3] if len(toks) >= 4
                                and toks[3] in ("tcp", "udp", "tcp-udp")
                                else None)
                named.append(
                    _parse_service_group(children, name, proto_suffix,
                                         inlines, drops))
            elif kind == "protocol":
                # Track for ACE proto-position lookups (e.g. `permit
                # object-group TCPUDP …`). Stored separately so we still
                # surface the V1-out-of-scope flag for groups with
                # protocols we can't translate (esp, gre, …).
                pgroup_protos: list[str] = []
                for child in children:
                    cts = child.split()
                    if len(cts) >= 2 and cts[0] == "protocol-object":
                        pgroup_protos.append(cts[1])
                protocol_groups[name] = pgroup_protos
                # Only flag groups containing non-tcp/udp protos - pure
                # TCP/UDP/tcp-udp groups are fully handled at ACE-parse time.
                if any(p not in ("tcp", "udp", "tcp-udp")
                       for p in pgroup_protos):
                    drops.setdefault("protocol_object_group", []).append(name)
            # Other group kinds (icmp-type, security, user) ignored in V1.
        elif toks[0] == "name" and len(toks) >= 3:
            # Legacy host alias: `name 10.0.0.1 ALIAS [description …]` -
            # surface as a regular host address-object so downstream
            # resolution treats it like a modern `object network ALIAS`.
            ip = toks[1]
            alias = toks[2]
            description = ""
            if "description" in toks:
                di = toks.index("description")
                description = " ".join(toks[di + 1:])
            named.append({
                "obj_type": "address", "name": alias,
                "value": {"type": "ip-netmask", "value": f"{ip}/32",
                          "description": description}})

    objects = list(inlines.values()) + named
    return {"objects": objects,
            "protocol_groups": protocol_groups,
            "drops": drops}


# ── Slice 3: ACEs + access-group → rules ─────────────────────────────
#
# Three passes over the config text:
#   1. Collect ACEs per ACL in declaration order (`access-list ACL …`).
#      `remark` lines accumulate into the description of the next ACE.
#   2. Walk `access-group` bindings - promote bound ACLs to rules and
#      set `src_zones = [nameif]`. ASA ACLs are ingress-only; egress and
#      global bindings land in drops.
#   3. ACLs without an `in` binding land in drops (unbound_acl).
#
# Token-eating disambiguation: after SRC, `eq|lt|gt|range PORT` is
# always a source-port-spec. `object-group NAME` is a source-port-spec
# iff the named group is a service_group (looked up via name_to_type);
# otherwise it's the DST. Single `object NAME` is always DST (ASA
# syntax: port refs via object always use the `object-group` form or
# the bare port-spec keywords).


_IP_OCTET_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _looks_like_ip(tok: str) -> bool:
    return bool(_IP_OCTET_RE.match(tok))


def _inline_proto_any(proto: str, inlines: dict) -> str:
    mname = _inline_service_name(proto, "any")
    _add_inline(inlines, {
        "obj_type": "service", "name": mname,
        "value": {"protocol": proto, "port": "any", "description": ""}})
    return mname


def _read_addr_spec(toks: list[str], pos: int, name_to_type: dict,
                    inlines: dict, drops: dict, acl_name: str
                    ) -> tuple[list[str], int, list[str]]:
    """Consume a source-or-destination address spec.

    Returns (members, new_pos, ace_dropped_tags).
    """
    if pos >= len(toks):
        return [], pos, []
    t = toks[pos]
    if t in ("any", "any4", "any6"):
        return ["any"], pos + 1, []
    if t == "host" and pos + 1 < len(toks):
        ip_or_name = toks[pos + 1]
        # Pre-8.3 dialect: `host <NAME>` accepts a `name`-alias as the
        # host. If the token isn't an IP literal but matches a known
        # address object, pass it through by name; downstream resolves.
        if not _looks_like_ip(ip_or_name) \
                and name_to_type.get(ip_or_name) == "address":
            return [ip_or_name], pos + 2, []
        mname = _inline_host_name(ip_or_name)
        _add_inline(inlines, {
            "obj_type": "address", "name": mname,
            "value": {"type": "ip-netmask", "value": f"{ip_or_name}/32",
                      "description": ""}})
        return [mname], pos + 2, []
    if t == "object" and pos + 1 < len(toks):
        return [toks[pos + 1]], pos + 2, []
    if t == "object-group" and pos + 1 < len(toks):
        return [toks[pos + 1]], pos + 2, []
    if t == "interface" and pos + 1 < len(toks):
        return [f"iface:{toks[pos + 1]}"], pos + 2, ["iface_address_ref"]
    if (pos + 1 < len(toks)
            and _looks_like_ip(t) and _looks_like_ip(toks[pos + 1])):
        prefix = _mask_to_prefix(toks[pos + 1])
        if prefix is None:
            drops.setdefault("invalid_netmask", []).append(acl_name)
            return [], pos + 2, []
        mname = _inline_net_name(t, prefix)
        _add_inline(inlines, {
            "obj_type": "address", "name": mname,
            "value": {"type": "ip-netmask", "value": f"{t}/{prefix}",
                      "description": ""}})
        return [mname], pos + 2, []
    return [], pos, []


def _read_port_spec(toks: list[str], pos: int, proto: str,
                    name_to_type: dict, inlines: dict
                    ) -> tuple[list[str] | None, int, list[str]]:
    """Consume an optional port-spec at toks[pos].

    Returns (members_or_None, new_pos, dropped_tags). None signals no
    port-spec consumed (next token belongs to DST).
    """
    if pos >= len(toks):
        return None, pos, []
    t = toks[pos]
    if t == "eq" and pos + 1 < len(toks):
        port = toks[pos + 1]
        return [_inline_proto_port(proto, port, inlines)], pos + 2, []
    if t == "lt" and pos + 1 < len(toks):
        return [_inline_proto_port(proto, f"<{toks[pos + 1]}", inlines)], pos + 2, []
    if t == "gt" and pos + 1 < len(toks):
        return [_inline_proto_port(proto, f">{toks[pos + 1]}", inlines)], pos + 2, []
    if t == "neq" and pos + 1 < len(toks):
        return [_inline_proto_port(proto, f"!{toks[pos + 1]}", inlines)], pos + 2, ["neq_port"]
    if t == "range" and pos + 2 < len(toks):
        lo = _resolve_port_alias(toks[pos + 1]) if proto in ("tcp", "udp") else toks[pos + 1]
        hi = _resolve_port_alias(toks[pos + 2]) if proto in ("tcp", "udp") else toks[pos + 2]
        return [_inline_proto_port(proto, f"{lo}-{hi}", inlines)], pos + 3, []
    if t == "object-group" and pos + 1 < len(toks):
        gname = toks[pos + 1]
        if name_to_type.get(gname) == "service_group":
            return [gname], pos + 2, []
    return None, pos, []


def _inline_proto_port(proto: str, port: str, inlines: dict) -> str:
    # Port aliases are tcp/udp-only - ICMP type tokens (`echo`,
    # `echo-reply`, …) must stay verbatim.
    if proto in ("tcp", "udp"):
        port = _resolve_port_alias(port)
    mname = _inline_service_name(proto, port)
    _add_inline(inlines, {
        "obj_type": "service", "name": mname,
        "value": {"protocol": proto, "port": port, "description": ""}})
    return mname


_ICMP_TYPE_TOKENS = {
    "echo", "echo-reply", "unreachable", "time-exceeded", "redirect",
    "source-quench", "router-advertisement", "router-solicitation",
    "timestamp-reply", "timestamp-request", "information-reply",
    "information-request", "mask-reply", "mask-request", "traceroute",
    "conversion-error", "mobile-redirect", "parameter-problem",
    "alternate-address", "neighbor-advertisement", "neighbor-solicitation",
    "packet-too-big",
}


def _parse_ace_tokens(toks: list[str], acl_name: str, seq: int,
                      name_to_type: dict, protocol_groups: dict,
                      inlines: dict, drops: dict
                      ) -> dict | None:
    """Parse the tokens after `access-list ACL_NAME [line N]` into a rule.

    Returns None for non-extended (standard / legacy) forms which the
    caller already classifies.
    """
    if not toks or toks[0] != "extended":
        return None
    pos = 1
    if pos >= len(toks):
        return None
    action_tok = toks[pos]; pos += 1
    if action_tok not in ("permit", "deny"):
        return None
    action = "allow" if action_tok == "permit" else "deny"
    if pos >= len(toks):
        return None

    proto_tok = toks[pos]; pos += 1
    # `permit object-group X …` carries three distinct meanings depending
    # on what X is:
    #   service_group  → X drives the services slot, no proto/port read
    #   protocol_group → effective proto = "tcp-udp" if X⊆{tcp,udp,tcp-udp};
    #                    else opaque drop
    #   network_group  → only legal post-src/dst, treated as an address
    proto: str
    proto_group_name: str | None = None
    if proto_tok in ("object", "object-group") and pos < len(toks):
        gname = toks[pos]; pos += 1
        gtype = name_to_type.get(gname)
        if gtype == "service":
            # Singular `object <svc>` in proto slot - same shape as
            # service_group (services come from the object, no port-spec).
            proto = "service-group"
            proto_group_name = gname
        elif gtype == "service_group":
            proto = "service-group"
            proto_group_name = gname
        elif gname in protocol_groups:
            protos = protocol_groups[gname]
            if protos and all(p in ("tcp", "udp", "tcp-udp")
                              for p in protos):
                proto = "tcp-udp"  # both protos, port-spec applies to both
            else:
                proto = f"{proto_tok}:{gname}"
        else:
            proto = f"{proto_tok}:{gname}"
    else:
        proto = proto_tok

    dropped_inputs: list[str] = []

    sources, pos, sd = _read_addr_spec(
        toks, pos, name_to_type, inlines, drops, acl_name)
    dropped_inputs.extend(sd)

    src_port: list[str] | None = None
    if proto in ("tcp", "udp", "tcp-udp"):
        src_port, pos, pd = _read_port_spec(
            toks, pos, proto, name_to_type, inlines)
        dropped_inputs.extend(pd)

    destinations, pos, dd = _read_addr_spec(
        toks, pos, name_to_type, inlines, drops, acl_name)
    dropped_inputs.extend(dd)

    services: list[str] = []
    if proto == "ip":
        services = ["any"]
    elif proto in ("tcp", "udp"):
        dst_port, pos, pd = _read_port_spec(
            toks, pos, proto, name_to_type, inlines)
        dropped_inputs.extend(pd)
        services = dst_port if dst_port else [_inline_proto_any(proto, inlines)]
    elif proto == "tcp-udp":
        # `object-group <PROTO_GROUP>` with protos ⊆ {tcp, udp, tcp-udp}:
        # the trailing port-spec (eq 3389 / object-group X) applies to
        # both. Emit one service per proto so downstream resolves both.
        dst_port, pos, pd = _read_port_spec(
            toks, pos, "tcp", name_to_type, inlines)
        dropped_inputs.extend(pd)
        if dst_port:
            # Either inline port (e.g. `eq 3389`) - synthesize tcp + udp -
            # or a service_group reference, which carries its own protos.
            if pos > 0 and dst_port[0].startswith("_inline_"):
                port_repr = dst_port[0].rsplit("_", 1)[-1]
                services = [
                    _inline_proto_port("tcp", port_repr, inlines),
                    _inline_proto_port("udp", port_repr, inlines),
                ]
            else:
                services = dst_port
        else:
            services = [_inline_proto_any("tcp", inlines),
                        _inline_proto_any("udp", inlines)]
    elif proto == "service-group":
        services = [proto_group_name] if proto_group_name else []
    elif proto.startswith("object:") or proto.startswith("object-group:"):
        # Protocol object/group with non-tcp/udp content - opaque to V1
        services = [proto.split(":", 1)[1]]
        dropped_inputs.append("protocol_object_in_ace")
    elif proto in ("icmp", "icmp6", "icmpv6"):
        # Optional trailing ICMP type (echo, echo-reply, unreachable, …)
        icmp_type = "any"
        if pos < len(toks) and toks[pos] in _ICMP_TYPE_TOKENS:
            icmp_type = toks[pos]
            pos += 1
        services = [_inline_proto_port(proto, icmp_type, inlines)
                    if icmp_type != "any"
                    else _inline_proto_any(proto, inlines)]
        dropped_inputs.append(f"non_tcp_udp_proto:{proto}")
    else:
        # esp, gre, ah, numeric protocol, …
        services = [_inline_proto_any(proto, inlines)]
        dropped_inputs.append(f"non_tcp_udp_proto:{proto}")

    description = ""
    disabled = 0
    raw_extras: dict = {}
    while pos < len(toks):
        t = toks[pos]
        if t == "log":
            pos += 1
            raw_extras["log"] = True
            # Optional log level + optional `interval N`
            if pos < len(toks) and toks[pos] not in (
                    "time-range", "inactive", "disable", "log", "interval"):
                raw_extras["log_level"] = toks[pos]
                pos += 1
            if pos + 1 < len(toks) and toks[pos] == "interval":
                raw_extras["log_interval"] = toks[pos + 1]
                pos += 2
        elif t == "time-range" and pos + 1 < len(toks):
            raw_extras["time_range"] = toks[pos + 1]
            dropped_inputs.append("time_range_ace")
            pos += 2
        elif t in ("inactive", "disable"):
            disabled = 1
            pos += 1
        else:
            dropped_inputs.append(f"unknown_trailing:{t}")
            pos += 1

    if src_port:
        raw_extras["source_port"] = src_port

    return {
        "rule_name":      f"{acl_name}_{seq:03d}",
        "seq_num":        seq,
        "action":         action,
        "src_zones":      [],
        "dst_zones":      [],
        "sources":        sources,
        "destinations":   destinations,
        "services":       services,
        "applications":   [],
        "description":    description,
        "disabled":       disabled,
        "tags":           [],
        "raw_extras":     raw_extras or None,
        "dropped_inputs": dropped_inputs,
    }


def parse_rules(text: str, name_to_type: dict,
                protocol_groups: dict | None = None) -> dict:
    """Parse ACEs and bind them to interfaces via access-group.

    Args:
      text:             the full running-config text
      name_to_type:     {object_name: "address"|"service"|"address_group"|"service_group"}
                        used to disambiguate `object-group NAME` after SRC
                        between source-port-spec and DST.
      protocol_groups:  {group_name: [protocol_token, …]} from parse_objects;
                        lets the ACE parser recognize `permit object-group
                        TCPUDP …` as a tcp+udp multi-proto rule.

    Returns dict with:
      rules:           bound rules in global parse-order with src_zones set
      inline_objects:  synthesized address/service objects emitted by ACE
                       literals (`host X`, `eq 443`, …)
      drops:           {drop_category: [sample_names]}
    """
    protocol_groups = protocol_groups or {}
    inlines: dict[str, dict] = {}
    drops: dict[str, list[str]] = {}
    acls: dict[str, list[dict]] = {}
    pending_remarks: dict[str, list[str]] = {}

    # Pass 1: collect ACEs per ACL
    for header, _children in _iter_blocks(text):
        toks = header.split()
        if not toks or toks[0] != "access-list" or len(toks) < 3:
            continue
        acl_name = toks[1]
        rest = toks[2:]

        # Strip optional `line N`
        if rest[0] == "line" and len(rest) >= 2:
            try:
                int(rest[1])
                rest = rest[2:]
            except ValueError:
                pass
        if not rest:
            continue

        if rest[0] == "remark":
            pending_remarks.setdefault(acl_name, []).append(
                " ".join(rest[1:]))
            continue

        existing = acls.setdefault(acl_name, [])
        seq = len(existing)

        if rest[0] == "standard":
            drops.setdefault("standard_acl", []).append(acl_name)
            continue
        if rest[0] != "extended":
            drops.setdefault("legacy_dialect", []).append(
                f"{acl_name}:{rest[0]}")
            continue

        rule = _parse_ace_tokens(rest, acl_name, seq, name_to_type,
                                 protocol_groups, inlines, drops)
        if rule is None:
            continue
        pending = pending_remarks.pop(acl_name, [])
        if pending:
            rule["description"] = "\n".join(pending)
        existing.append(rule)

    # Pass 2: access-group bindings
    rules: list[dict] = []
    bound_acls: set[str] = set()
    global_seq = 0
    for header, _children in _iter_blocks(text):
        toks = header.split()
        if not toks or toks[0] != "access-group" or len(toks) < 3:
            continue
        acl_name = toks[1]
        if toks[2] == "global":
            drops.setdefault("global_acl", []).append(acl_name)
            bound_acls.add(acl_name)
            continue
        if toks[2] == "out" and len(toks) >= 5 and toks[3] == "interface":
            drops.setdefault("egress_acl", []).append(acl_name)
            bound_acls.add(acl_name)
            continue
        if (toks[2] != "in" or len(toks) < 5
                or toks[3] != "interface"):
            continue
        iface = toks[4]
        bound_acls.add(acl_name)
        for r in acls.get(acl_name, []):
            promoted = dict(r)
            promoted["src_zones"] = [iface]
            promoted["seq_num"] = global_seq
            global_seq += 1
            rules.append(promoted)

    # Pass 3: ACLs declared but never bound `in`
    for acl_name, acl_rules in acls.items():
        if acl_name not in bound_acls and acl_rules:
            drops.setdefault("unbound_acl", []).append(acl_name)

    return {
        "rules":          rules,
        "inline_objects": list(inlines.values()),
        "drops":          drops,
    }


# ── Slice 4: Interfaces + Routes (network strand) ────────────────────


def _classify_asa_iface(name: str) -> str:
    """Map an ASA interface-name to one of the canonical iface_type
    values the writer expects. The shared `parse_iface_name` covers
    PA/CP conventions but doesn't know ASA's `Port-channelN` or
    `GigabitEthernet*` prefixes - this fills that gap.
    """
    lo = name.lower()
    if lo.startswith("port-channel"):
        return "bond"
    if lo.startswith("loopback") or re.match(r"^lo[0-9]", lo):
        return "loopback"
    if lo.startswith("tunnel"):
        return "tunnel"
    if lo.startswith("bvi"):
        return "bridge"
    if lo.startswith("vlan") and "/" not in name:
        return "vlan"
    if "." in name:
        head, _, tail = name.rpartition(".")
        if head and tail.isdigit():
            return "vlan"
    return "physical"


def parse_interfaces(text: str) -> dict:
    """Parse `interface X` blocks into agnostic interface dicts.

    Shape per interface:
      {name, type, zone, description, ips: [cidr, …], shutdown}

    `zone` is the `nameif` value (ASA's notion of a zone, 1:1 with the
    interface). Shutdown interfaces are still persisted but added to
    `drops.inactive_interface` for UI surfacing.
    """
    interfaces: list[dict] = []
    drops: dict[str, list[str]] = {}
    parent_of: dict[str, str] = {}

    for header, children in _iter_blocks(text):
        toks = header.split()
        if len(toks) < 2 or toks[0] != "interface":
            continue
        ifname = toks[1]

        nameif: str | None = None
        description = ""
        ips: list[str] = []
        shutdown = False
        dhcp_enabled = False

        for c in children:
            ctoks = c.split()
            if not ctoks:
                continue
            k = ctoks[0]
            if k == "nameif" and len(ctoks) >= 2:
                nameif = ctoks[1]
            elif k == "description":
                description = c[len("description"):].strip()
            elif k == "shutdown":
                shutdown = True
            elif k == "no" and len(ctoks) >= 2 and ctoks[1] == "shutdown":
                shutdown = False
            elif (k == "ip" and len(ctoks) >= 3
                    and ctoks[1] == "address"
                    and ctoks[2] == "dhcp"):
                # ASA `ip address dhcp [setroute]` - DHCP-client mode.
                # Static IP and DHCP are mutually exclusive on the same
                # iface, so we don't combine them.
                dhcp_enabled = True
            elif (k == "ip" and len(ctoks) >= 4
                    and ctoks[1] == "address"
                    and ctoks[2] != "dhcp"):
                ip = ctoks[2]
                mask = ctoks[3]
                if _looks_like_ip(ip) and _looks_like_ip(mask):
                    prefix = _mask_to_prefix(mask)
                    if prefix is not None:
                        ips.append(f"{ip}/{prefix}")

        iface_type = _classify_asa_iface(ifname)
        if iface_type == "vlan" and "." in ifname:
            parent_of[ifname] = ifname.rsplit(".", 1)[0]

        if shutdown:
            drops.setdefault("inactive_interface", []).append(ifname)

        interfaces.append({
            "name":         ifname,
            "type":         iface_type,
            "zone":         nameif,
            "description":  description,
            "ips":          ips,
            "shutdown":     shutdown,
            "enabled":      not shutdown,
            "dhcp_enabled": dhcp_enabled,
        })

    return {"interfaces": interfaces, "drops": drops}


def parse_routes(text: str) -> dict:
    """Parse `route <iface> <dst> <mask> <next_hop> [metric] …` lines.

    Returns prefix-ready route dicts compatible with `_write_collect_result`.
    Routing-protocol statements (`router ospf …`, `router bgp …`) land in
    `drops.routing_protocol`.

    ASA allows multiple static routes for the same prefix with different
    next-hops/metrics (admin-distance picks the winner at runtime). The
    Gateshift schema enforces UNIQUE(device_id, prefix, vr_name) - so the parser
    keeps the first occurrence per (prefix, vr) and surfaces additional
    entries under `drops.duplicate_route`.
    """
    routes: list[dict] = []
    drops: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()

    for header, _children in _iter_blocks(text):
        toks = header.split()
        if not toks:
            continue
        if toks[0] == "route" and len(toks) >= 5:
            iface, dst, mask, next_hop = toks[1], toks[2], toks[3], toks[4]
            prefix = _mask_to_prefix(mask)
            if prefix is None or not _looks_like_ip(dst):
                drops.setdefault("invalid_route_mask", []).append(
                    f"{dst} {mask}")
                continue
            try:
                net = ipaddress.ip_network(f"{dst}/{prefix}", strict=False)
            except ValueError:
                continue
            key = (str(net), "default")
            if key in seen:
                drops.setdefault("duplicate_route", []).append(
                    f"{net} via {next_hop} on {iface}")
                continue
            seen.add(key)
            routes.append({
                "prefix":   str(net),
                "plen":     net.prefixlen,
                "ip_from":  int(net.network_address),
                "ip_to":    int(net.broadcast_address),
                "iface":    iface,
                "next_hop": next_hop,
                "vr":       "default",
            })
        elif toks[0] == "router" and len(toks) >= 2:
            drops.setdefault("routing_protocol", []).append(
                " ".join(toks[:2]))

    return {"routes": routes, "drops": drops}


# ── Slice 5: NAT (twice-NAT + object-NAT) → fw_nat_rules ─────────────
#
# Two grammars to handle:
#
#   1. Twice-NAT (unified, manual):
#        nat (REAL_IF,MAPPED_IF) [N] source {static|dynamic} ORIG_SRC MAPPED_SRC \
#            [destination static ORIG_DST MAPPED_DST] \
#            [service ORIG_SVC MAPPED_SVC] \
#            [unidirectional|inactive|description …|dns|no-proxy-arp|route-lookup]
#
#   2. Object-NAT (auto, within `object network NAME` block):
#        object network NAME
#         nat (REAL_IF,MAPPED_IF) {static <MAPPED>|dynamic {<MAPPED>|interface}}
#
# Mapping decision (per plan §349-388):
#   - source dynamic …                              → snat
#   - source static A B + no destination + no svc   → static (1:1)
#   - source static A B + destination static C D    → static if A==B (pure
#     dnat with src-match), else dnat (NAT44 with src-rewrite)
#   - Object-NAT static MAPPED                      → dnat
#   - Object-NAT dynamic …|interface                → snat
#
# Position-ordering is parse-order, twice-NAT first, then object-NAT
# (matches ASA's manual > auto runtime priority).


_NAT_FLAG_TOKENS = {
    "unidirectional", "inactive", "dns", "no-proxy-arp",
    "route-lookup", "net-to-net", "extended",
}


def _parse_twice_nat_line(toks: list[str], drops: dict) -> dict | None:
    """Parse a single `nat (IN,OUT) source …` line into a NAT-rule dict.

    Returns None for legacy / unparseable forms (those land in drops).
    """
    # toks[0]=='nat', toks[1] == '(IN,OUT)'
    if len(toks) < 6:
        return None
    zone_tok = toks[1]
    if not (zone_tok.startswith("(") and zone_tok.endswith(")")
            and "," in zone_tok):
        drops.setdefault("legacy_dialect", []).append(" ".join(toks[:3]))
        return None
    src_zone, dst_zone = zone_tok[1:-1].split(",", 1)

    # Optional explicit position after the zone-pair: `nat (in,out) 1 source …`
    i = 2
    if toks[i].isdigit():
        i += 1

    # The plan's grammar requires `source`. If something else, treat as
    # unknown/legacy.
    if i >= len(toks) or toks[i] != "source":
        drops.setdefault("legacy_dialect", []).append(" ".join(toks[:4]))
        return None
    i += 1
    if i + 2 >= len(toks):
        return None
    src_mode = toks[i]
    i += 1
    if src_mode not in ("static", "dynamic"):
        drops.setdefault("nat_unknown_source_mode", []).append(src_mode)
        return None
    orig_src = toks[i]
    i += 1
    trans_src = toks[i]
    i += 1

    orig_dst = None
    trans_dst = None
    orig_svc = None
    trans_svc = None
    flags: list[str] = []
    description = ""

    while i < len(toks):
        t = toks[i]
        if t == "destination" and i + 3 < len(toks) and toks[i + 1] == "static":
            orig_dst = toks[i + 2]
            trans_dst = toks[i + 3]
            i += 4
        elif t == "service" and i + 2 < len(toks):
            orig_svc = toks[i + 1]
            trans_svc = toks[i + 2]
            i += 3
        elif t == "description":
            description = " ".join(toks[i + 1:])
            break
        elif t in _NAT_FLAG_TOKENS:
            flags.append(t)
            i += 1
        else:
            # Unknown token - capture as a soft drop tag and continue.
            drops.setdefault("nat_unknown_token", []).append(t)
            i += 1

    # nat_type mapping
    if src_mode == "dynamic":
        nat_type = "snat"
    elif orig_dst is None and orig_svc is None:
        nat_type = "static"
    elif orig_src == trans_src:
        # Source unchanged, only destination/service rewritten → pure DNAT.
        nat_type = "dnat"
    else:
        # Both source and destination rewritten - closest agnostic match
        # is `static` (1:1 NAT44 with explicit src+dst pairing). Tag for
        # later visibility.
        nat_type = "static"
        flags.append("twice_nat_src_and_dst")

    if src_mode == "dynamic":
        trans_src_type = ("interface-address" if trans_src == "interface"
                          else "dynamic-ip-and-port")
    else:
        trans_src_type = ("interface-address" if trans_src == "interface"
                          else "static-ip")

    dropped: list[str] = []
    if "unidirectional" in flags:
        dropped.append("nat_unidirectional")
    if "dns" in flags:
        dropped.append("nat_dns_rewrite")
    for d in dropped:
        drops.setdefault(d, []).append(" ".join(toks[:6]))

    return {
        "nat_type":       nat_type,
        "disabled":       1 if "inactive" in flags else 0,
        "src_zones":      [src_zone],
        "dst_zones":      [dst_zone],
        "orig_src":       [orig_src],
        "orig_dst":       [orig_dst] if orig_dst else [],
        "orig_service":   [orig_svc] if orig_svc else [],
        "trans_src":      trans_src,
        "trans_src_type": trans_src_type,
        "trans_dst":      trans_dst,
        "trans_dst_port": None,
        "description":    description,
        "properties":     {"flags": flags} if flags else None,
        "dropped_inputs": dropped,
    }


def _parse_object_nat_child(child: str, drops: dict) -> dict | None:
    """Parse the `nat (IN,OUT) {static|dynamic} …` child line of an
    `object network NAME` block. Returns the NAT-rule dict or None.
    """
    toks = child.split()
    if len(toks) < 4 or toks[0] != "nat":
        return None
    zone_tok = toks[1]
    if not (zone_tok.startswith("(") and zone_tok.endswith(")")
            and "," in zone_tok):
        return None
    src_zone, dst_zone = zone_tok[1:-1].split(",", 1)

    mode = toks[2]
    if mode == "static":
        mapped = toks[3]
        nat_type = "dnat"
        trans_src_type = ("interface-address" if mapped == "interface"
                          else "static-ip")
    elif mode == "dynamic":
        mapped = toks[3]
        nat_type = "snat"
        trans_src_type = ("interface-address" if mapped == "interface"
                          else "dynamic-ip-and-port")
    else:
        drops.setdefault("nat_unknown_source_mode", []).append(mode)
        return None

    return {
        "nat_type":       nat_type,
        "disabled":       0,
        "src_zones":      [src_zone],
        "dst_zones":      [dst_zone],
        "orig_src":       [],   # filled in by caller (= the object's name)
        "orig_dst":       [],
        "orig_service":   [],
        "trans_src":      mapped,
        "trans_src_type": trans_src_type,
        "trans_dst":      None,
        "trans_dst_port": None,
        "description":    "",
        "properties":     None,
        "dropped_inputs": [],
    }


def parse_nat(text: str) -> dict:
    """Parse Twice-NAT + Object-NAT into agnostic NAT-rule dicts.

    Returns
    -------
    dict with keys:
      nat_rules: list of rule dicts (position-ordered, twice-NAT first,
                 then object-NAT; matches ASA manual > auto runtime
                 priority). Each rule has the shape that maps directly
                 to fw_nat_rules columns.
      drops:    dict {drop_category: [samples]} for legacy / unsupported
                constructs.
    """
    twice: list[dict] = []
    auto: list[dict] = []
    drops: dict[str, list[str]] = {}

    for header, children in _iter_blocks(text):
        toks = header.split()
        if not toks:
            continue
        if toks[0] == "nat":
            r = _parse_twice_nat_line(toks, drops)
            if r:
                twice.append(r)
        elif (toks[0] == "object" and len(toks) >= 3
              and toks[1] == "network"):
            obj_name = toks[2]
            for c in children:
                if not c.startswith("nat "):
                    continue
                r = _parse_object_nat_child(c, drops)
                if r:
                    r["orig_src"] = [obj_name]
                    auto.append(r)
        elif toks[0] == "global" or (toks[0] == "static" and len(toks) >= 3
                                     and toks[1].startswith("(")):
            # Pre-8.3 legacy NAT.
            drops.setdefault("legacy_dialect", []).append(
                " ".join(toks[:3]))

    rules: list[dict] = []
    for pos, r in enumerate(twice + auto):
        rules.append({**r, "position": pos})

    return {"nat_rules": rules, "drops": drops}


def parse_full(text: str) -> dict:
    """Combined entrypoint for the ASA import + collector handlers.

    Returns dict with: objects, rules, interfaces, routes, vrfs, drops,
    nat_rules. Network strand always includes a single 'default' VRF
    (ASA single-context configs have no native VRF concept; we use the
    same sentinel as PA/CP).
    """
    obj_result = parse_objects(text)
    name_to_type = {o["name"]: o["obj_type"] for o in obj_result["objects"]}
    protocol_groups = obj_result.get("protocol_groups") or {}

    rule_result = parse_rules(text, name_to_type, protocol_groups)
    iface_result = parse_interfaces(text)
    route_result = parse_routes(text)
    nat_result = parse_nat(text)

    obj_by_name = {o["name"]: o for o in obj_result["objects"]}
    for o in rule_result["inline_objects"]:
        obj_by_name.setdefault(o["name"], o)

    # Egress-interface PAT resolution (`nat ... dynamic <grp> interface`):
    # the parse stages left the literal 'interface' keyword in trans_src,
    # which zone-mode targets rendered verbatim and rejected ("'interface'
    # is not a valid reference" - the former KNOWN_LIMITATIONS entry).
    # With interfaces AND NAT parsed we can resolve it here: the egress
    # side is the MAPPED_IF nameif (dst_zones[0]); store the interface's
    # canonical name (+ '|ip' composite when known, so CP can materialize
    # a host object and PA takes the name via its split). Renames cascade
    # - trans_src is interface-typed in the reference model. An
    # unresolvable egress (e.g. 'any') keeps the literal + a drop note.
    _iface_by_nameif = {i["zone"]: i for i in iface_result["interfaces"]
                        if i.get("zone")}
    for _nr in nat_result["nat_rules"]:
        if (_nr.get("trans_src") == "interface"
                and _nr.get("trans_src_type") == "interface-address"):
            _egress = (_nr.get("dst_zones") or [""])[0] or ""
            _eif = _iface_by_nameif.get(_egress)
            if _eif:
                _ip = ((_eif.get("ips") or [""])[0] or "").split("/")[0]
                _nr["trans_src"] = (f"{_eif['name']}|{_ip}" if _ip
                                    else _eif["name"])
            else:
                nat_result["drops"].setdefault(
                    "nat_interface_pat_unresolved", []).append(
                    f"({_nr.get('src_zones', ['?'])[0]},{_egress or '?'})")

    merged_drops: dict[str, list[str]] = {}
    for src in (obj_result["drops"], rule_result["drops"],
                iface_result["drops"], route_result["drops"],
                nat_result["drops"]):
        for k, names in src.items():
            merged_drops.setdefault(k, []).extend(names)

    return {
        "objects":    list(obj_by_name.values()),
        "rules":      rule_result["rules"],
        "interfaces": iface_result["interfaces"],
        "routes":     route_result["routes"],
        "vrfs":       [{"name": "default", "interface_members": []}],
        "drops":      merged_drops,
        "nat_rules":  nat_result["nat_rules"],
    }
