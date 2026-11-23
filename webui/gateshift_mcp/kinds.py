# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The kinds of the network strand and the NAT rules, one field table: what add_item, edit_item and
delete_item accept per kind, what the API builds its bodies from, and what
describe_kind answers. Pure data without imports, so the tools and the API
cannot drift apart. A field is a dict with `type` (str, int, bool, list of
strings, or dict for the target's property keys), an optional `enum`, an
optional `required` and a `doc` sentence. `key` says how a row of the kind
is addressed, `properties_schema` names the schema module of its
properties (zone or nat), which describe_kind reads for the target."""

IFACE_TYPES = ("physical", "vlan", "bond", "loopback", "tunnel")
ROUTE_TYPES = ("static", "blackhole")
NAT_TYPES = ("snat", "dnat", "static")
TRANS_SRC_TYPES = ("static-ip", "dynamic-ip", "dynamic-ip-and-port", "interface-address", "none")

KINDS: dict[str, dict] = {
    "interface": {
        "key": "the interface's id or its shown name",
        "add": {
            "name": {"type": "str", "required": True, "doc": "the interface's name"},
            "type": {"type": "str", "enum": IFACE_TYPES, "doc": "physical when absent"},
            "parent": {"type": "str", "doc": "the parent of a vlan interface, by its shown name"},
            "vlan_tag": {"type": "int", "doc": "the tag of a vlan interface, 1 to 4094"},
            "ip_addresses": {"type": "list", "doc": "addresses with their length, 10.1.2.1/24"},
            "zone": {"type": "str", "doc": "the zone to bind, created when the project has none of that name"},
            "description": {"type": "str", "doc": "free text"},
            "dhcp": {"type": "bool", "doc": "the address comes from DHCP, no ip_addresses then"},
        },
        "edit": None,     # edit_interface carries the interface's edits
        "delete": {
            "empty_zone_ok": {"type": "bool", "doc": "accept that the interface's zone keeps no member"},
        },
    },
    "route": {
        "key": "the route's id, or prefix|vr, or the bare prefix in the default virtual router",
        "add": {
            "prefix": {"type": "str", "required": True, "doc": "the destination as CIDR, 10.0.0.0/8"},
            "interface": {"type": "str", "doc": "the egress interface, by its shown name"},
            "next_hop": {"type": "str", "doc": "the gateway address"},
            "vr": {"type": "str", "doc": "the virtual router, default when absent"},
            "metric": {"type": "int", "doc": "0 to 65535"},
            "route_type": {"type": "str", "enum": ROUTE_TYPES, "doc": "static when absent"},
        },
        "edit": {
            "prefix": {"type": "str", "doc": "a new destination: the route leaves and comes back under the new prefix"},
            "next_hop": {"type": "str", "doc": "the gateway address, an empty string clears it"},
            "interface": {"type": "str", "doc": "the egress interface, by its shown name"},
            "metric": {"type": "int", "doc": "0 to 65535, null clears it"},
            "route_type": {"type": "str", "enum": ROUTE_TYPES, "doc": "static or blackhole"},
        },
        "delete": {},
    },
    "vrf": {
        "key": "the virtual router's id or its shown name",
        "add": {
            "name": {"type": "str", "required": True, "doc": "the virtual router's name"},
        },
        "edit": None,     # the rename goes through rename_items
        "delete": {},
    },
    "zone": {
        "key": "the zone's id or its shown name",
        "add": None,      # create_zone carries the zone addition
        "edit": {
            "color": {"type": "str", "doc": "the zone's colour as the Network tab shows it"},
            "is_external": {"type": "bool", "doc": "the zone faces the outside"},
            "properties": {"type": "dict", "doc": "the target's property keys, describe_kind names them, null removes a key"},
        },
        "delete": {
            "cascade": {"type": "bool", "doc": "move the project's rules from the zone to its members' names first, after an auto-snapshot"},
        },
        "properties_schema": "zone",
    },
    "nat_rule": {
        "key": "the rule's nat_hash or its shown name",
        "add": {
            "name": {"type": "str", "required": True, "doc": "the rule's name"},
            "nat_type": {"type": "str", "enum": NAT_TYPES, "required": True, "doc": "snat, dnat or static"},
            "src_zones": {"type": "list", "doc": "the source zones, by their shown names"},
            "dst_zones": {"type": "list", "doc": "the destination zones, by their shown names"},
            "interface": {"type": "str", "doc": "the egress interface, by its shown name"},
            "orig_src": {"type": "list", "doc": "the original sources: object names or addresses"},
            "orig_dst": {"type": "list", "doc": "the original destinations: object names or addresses"},
            "orig_service": {"type": "list", "doc": "the original services: service names or proto/port"},
            "trans_src": {"type": "str", "doc": "the translated source: an object, an address, or the interface for interface-address"},
            "trans_src_type": {"type": "str", "enum": TRANS_SRC_TYPES, "doc": "none when absent"},
            "trans_dst": {"type": "str", "doc": "the translated destination: an object or an address"},
            "trans_dst_port": {"type": "str", "doc": "the translated destination port"},
            "description": {"type": "str", "doc": "free text"},
            "disabled": {"type": "bool", "doc": "the rule is kept but disabled"},
        },
        "edit": {
            "name": {"type": "str", "doc": "the shown name, through the project's name map"},
            "description": {"type": "str", "doc": "free text"},
            "disabled": {"type": "bool", "doc": "the rule is kept but disabled"},
            "properties": {"type": "dict", "doc": "the target's property keys, describe_kind names them"},
            "src_zone": {"type": "str", "doc": "the source zone overlay, an empty string clears it"},
            "dst_zone": {"type": "str", "doc": "the destination zone overlay, an empty string clears it"},
            "negate_source": {"type": "bool", "doc": "match everything but the sources"},
            "negate_destination": {"type": "bool", "doc": "match everything but the destinations"},
            "negate_service": {"type": "bool", "doc": "match everything but the services"},
        },
        "delete": {},
        "properties_schema": "nat",
    },
}


def fields_of(kind: str, verb: str) -> dict | None:
    """The field table of one kind for add, edit or delete, None when the
    kind has no such verb; raises KeyError for an unknown kind."""
    return KINDS[kind].get(verb)
