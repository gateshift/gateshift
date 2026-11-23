# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The step model of a project: the operator's path from the two Devices to the verified push, each
step judged from what the product holds. The fixed steps carry evidence (an
import, a fetch, the mapping gaps, a build, the stamps). The sections of the
project (routes, policy routing, VPN tunnels, the rulesets, objects, and since
D62 every view of Profiles & Settings and the Target Settings of NAT and policy
routing, each where the target has the view and the project carries something
for it) count as gone through once the operator opened them after the
import (D16, "seen"), the VPN tunnels also want their secrets. The blocking
findings of the current build become steps of their own, each with the
place that fixes it (D18). The navigation markers (D2, D17), the header
sentence (D6), the path dialog (D7, D22) and the project list (D8) all read
one evaluation.

Pure: `evaluate(facts)` takes a dict of plain values (main.py gathers them in
`_project_facts`) and answers the steps, the first open step with its
sentence and place, and the counts. `status_of` derives the project status
the list filters on. Importable without SQLAlchemy, like hitcounts.py.

States: done, open, locked (the target Device cannot be reached), na (the
step does not apply to this pair, or the project carries nothing for it).
"""
import datetime as _dt

STEPS = (
    ("devices", "Devices and project"),
    ("import", "Source imported"),
    ("fetch", "Target inventory fetched"),
    ("mapping", "Zones and interfaces mapped"),
    ("routing", "Routes reviewed"),
    ("zones", "Zone bindings looked at"),
    ("pbf", "Policy routing reviewed"),
    ("pbf_settings", "Policy routing target settings"),
    ("vpn", "VPN tunnels and secrets"),
    ("rules", "Firewall rules reviewed"),
    ("nat", "NAT reviewed"),
    ("nat_settings", "NAT target settings"),
    ("ssl", "Decryption reviewed"),
    ("tp", "Threat prevention reviewed"),
    ("objects", "Objects reviewed"),
    # the views of Profiles & Settings, one recommended step each (D62)
    ("profiles", "Security profiles attached"),
    ("applications", "Applications set"),
    ("logging", "Logging set"),
    ("schedule", "Schedules set"),
    ("identity", "Source users reviewed"),
    ("tags", "Tags reviewed"),
    ("review", "Reviewed"),
    ("push", "Pushed"),
    ("verify", "Verified and activated"),
)
STATES = ("done", "open", "locked", "na", "skipped")

# The steps the operator may skip (D20): the path moves on, the path dialog
# (the light bulb at the top of the page, D22) offers to resume. Never the import, the review or the push, and evidence
# beats a skip (a step that is done is done).
SKIPPABLE = frozenset({"fetch", "mapping", "routing", "zones", "pbf", "pbf_settings", "vpn", "rules", "nat", "nat_settings",
                       "ssl", "tp", "objects", "profiles", "applications", "logging", "schedule", "identity",
                       "tags", "verify"})


def skippable(key: str) -> bool:
    return key in SKIPPABLE or str(key).startswith("fix:")

# The sections that count as gone through once opened after the import
# (D16): the view key the client reports and the step share the name.
SEEN_VIEWS = ("routing", "pbf", "pbf_settings", "vpn", "rules", "nat", "nat_settings", "ssl", "tp", "objects",
              "profiles", "applications", "logging", "schedule", "identity", "tags", "zones")

# Where a step is completed: the workspace tab and sub-tab (gsGoTo's words),
# the navigation entry that carries the marker, and for a view inside a
# Profiles & Settings rulebase its name as the fourth element.
PLACES = {
    "devices": ("devices", None, "ws-nav-devices"),   # the Devices page (D30)
    "import": ("overview", None, "primary-btn-overview"),
    "fetch": ("network", "interfaces", "main-btn-interfaces"),
    # the interface-to-zone binding is the zones panel of Profiles & Settings, reached
    # from Network > Zones (D28); a target without zones keeps the step on
    # Network > Interfaces (the names)
    "mapping": ("enrichment", "access", "main-btn-zones-enrichment", "zones-enrichment"),
    "routing": ("network", "routing", "main-btn-routing"),
    "pbf": ("network", "policy-routing", "main-btn-policy-routing"),
    # the Target Settings mode of the leaf (D57, D62): the enrichment rulebase behind it
    "pbf_settings": ("enrichment", "routing", "main-btn-policy-routing"),
    # the zone bindings, after the routes (D90): the derived zones follow the routes
    "zones": ("enrichment", "access", "main-btn-zones-enrichment", "zones-enrichment"),
    "vpn": ("network", "vpn", "main-btn-vpn"),
    "rules": ("ruleset", "security", "main-btn-security"),
    "nat": ("ruleset", "nat", "main-btn-nat"),
    "nat_settings": ("enrichment", "nat", "main-btn-nat"),
    "ssl": ("ruleset", "decryption", "main-btn-decryption"),
    "tp": ("ruleset", "tp", "main-btn-tp"),
    # the objects step lands on Address Groups (D84): an unused group deleted frees its members,
    # and the object tab a browser remembers must not win over the hint
    "objects": ("objects", None, "primary-btn-objects", "address_group"),
    # the views of Profiles & Settings (D62); a FortiGate target puts profiles on UTM Profiles
    "profiles": ("enrichment", "access", "main-btn-security-profiles", "security-profiles"),
    "applications": ("enrichment", "access", "main-btn-applications", "applications"),
    "logging": ("enrichment", "access", "main-btn-logging", "logging"),
    "schedule": ("enrichment", "access", "main-btn-schedule-enrichment", "schedule-enrichment"),
    "identity": ("enrichment", "access", "main-btn-identity-enrichment", "identity-enrichment"),
    "tags": ("enrichment", "access", "main-btn-tags-enrichment", "tags-enrichment"),
    "review": ("deploy", None, "primary-btn-deploy"),
    "push": ("deploy", None, "primary-btn-deploy"),
    "verify": ("deploy", None, "primary-btn-deploy"),
}

# The navigation tree above the leaves (D17): a head aggregates the steps
# below it.
NAV_PARENTS = {
    "main-btn-interfaces": "primary-btn-network",
    "main-btn-routing": "primary-btn-network",
    "main-btn-policy-routing": "primary-btn-network",
    "main-btn-vpn": "primary-btn-network",
    "main-btn-security": "primary-btn-ruleset",
    "main-btn-nat": "primary-btn-ruleset",
    "main-btn-decryption": "primary-btn-ruleset",
    "main-btn-tp": "primary-btn-ruleset",
    "main-btn-zones-enrichment": "primary-btn-network",   # Zones sits under Network (D28)
    "main-btn-security-profiles": "primary-btn-enrichment",
    "main-btn-utm-profiles": "primary-btn-enrichment",
    "main-btn-applications": "primary-btn-enrichment",
    "main-btn-logging": "primary-btn-enrichment",
    "main-btn-schedule-enrichment": "primary-btn-enrichment",
    "main-btn-identity-enrichment": "primary-btn-enrichment",
    "main-btn-tags-enrichment": "primary-btn-enrichment",
}

# The navigation entry of a place (tab, sub-tab, view), for the fix steps.
NAV_OF = {
    ("network", "interfaces", None): "main-btn-interfaces",
    ("network", "routing", None): "main-btn-routing",
    ("network", "policy-routing", None): "main-btn-policy-routing",
    ("network", "vpn", None): "main-btn-vpn",
    ("ruleset", "security", None): "main-btn-security",
    ("ruleset", "nat", None): "main-btn-nat",
    ("ruleset", "decryption", None): "main-btn-decryption",
    ("ruleset", "tp", None): "main-btn-tp",
    ("objects", None, None): "primary-btn-objects",
    ("enrichment", "access", "zones-enrichment"): "main-btn-zones-enrichment",
    ("enrichment", "access", None): "primary-btn-enrichment",
    ("enrichment", "access", "security-profiles"): "main-btn-security-profiles",
    ("enrichment", "access", "utm-profiles"): "main-btn-utm-profiles",
    ("enrichment", "access", "applications"): "main-btn-applications",
    ("enrichment", "access", "logging"): "main-btn-logging",
    ("enrichment", "access", "schedule-enrichment"): "main-btn-schedule-enrichment",
    ("enrichment", "access", "identity-enrichment"): "main-btn-identity-enrichment",
    ("enrichment", "access", "tags-enrichment"): "main-btn-tags-enrichment",
    ("enrichment", "nat", None): "main-btn-nat",
    ("enrichment", "routing", None): "main-btn-policy-routing",
    ("deploy", None, None): "primary-btn-deploy",
}

# Targets whose firewall rules need an interface zone (the build's no_zone
# check), targets with a network strand (a fetch and physical names that must
# exist on the box), targets with the VPN, decryption and threat prevention
# views, and the interface types the zone rule waives, as the build waives
# them (bond parents and members, loopbacks, tunnels).
ZONE_TARGETS = frozenset({"panw", "firepower"})
NETWORK_TARGETS = frozenset({"panw", "fortigate", "checkpoint"})
VPN_TARGETS = frozenset({"panw", "fortigate", "checkpoint"})
SSL_TARGETS = frozenset({"panw", "checkpoint"})
TP_TARGETS = frozenset({"checkpoint"})
# the views of Profiles & Settings and the Target Settings modes per target (D62): a FortiGate
# matches applications per policy in NGFW policy-based mode only (the facts carry its mode)
SETTINGS_TARGETS = frozenset({"panw", "checkpoint", "fortigate"})
PROFILE_TARGETS = frozenset({"panw", "fortigate"})
APP_TARGETS = frozenset({"panw", "checkpoint"})
TAG_TARGETS = frozenset({"panw"})
PBF_SETTINGS_TARGETS = frozenset({"panw"})
ZONE_WAIVED_TYPES = frozenset({"bond", "aggregate", "loopback", "tunnel"})

LOCK_SENTENCE = ("The target Device needs an API key and a supported platform: "
                 "edit it under Devices.")
VERIFY_SENTENCES = {
    "panw": "Commit on the firewall, check the result, then mark the project verified under the light bulb at the top of the page.",
    "checkpoint": "Publish and install the policy, check the result, then mark the project verified under the light bulb at the top of the page.",
}
VERIFY_DEFAULT = "Check the result on the firewall, then mark the project verified under the light bulb at the top of the page."

# The finding kinds of the Review (R3, D18): title, go-to tab, go-to sub-tab,
# the remedy in one sentence, and for a view inside a Profiles & Settings
# rulebase its name. One table for the Review tab (handed to the page as
# JSON) and for the fix steps of the step model.
KINDS = {'excluded_leak': ['Deleted items still generated',
                   'deploy',
                   None,
                   'A defect in Gateshift, not in your configuration: something deleted in this project came '
                   'out of the build. The push stays refused. Please report it with the item names.'],
 'strand_declared': ['Network strand not pushed to this target',
                     'deploy',
                     None,
                     'The target is a virtual system: its interfaces, VLANs and routes are provisioned on '
                     'the VSX. The policy strand is pushed, the network strand is not.'],
 'no_interfaces': ['No interfaces on the source',
                   'network',
                   'interfaces',
                   'Import the source again, or add the interfaces under Network > Interfaces.'],
 'no_ip': ['Interfaces without an IP address',
           'network',
           'interfaces',
           'Give each interface an address under Network > Interfaces, or mark it skip.'],
 'no_zone': ['Interfaces without a zone',
             'enrichment',
             'access',
             'Bind each interface to a zone under Network > Zones, or mark it skip '
             'under Network > Interfaces.',
             'zones-enrichment'],
 'bond_unsupported': ['Bonded interfaces the target cannot take',
                      'network',
                      'interfaces',
                      'Mark the bond skip and give its addresses to a plain interface the target has.'],
 'vlan_no_parent': ['VLAN interfaces without a parent',
                    'network',
                    'interfaces',
                    'Set the parent interface under Network > Interfaces, or mark the VLAN skip.'],
 'vlan_no_tag': ['VLAN interfaces without a tag',
                 'network',
                 'interfaces',
                 'Set the VLAN tag under Network > Interfaces, or mark the VLAN skip.'],
 'vlan_orphan_parent': ['VLAN interfaces whose parent is missing',
                        'network',
                        'interfaces',
                        'Add the parent under Network > Interfaces or point the VLAN at an existing one.'],
 'vr_orphan': ['Interfaces in a virtual router that does not exist',
               'network',
               'routing',
               'Add the virtual router under Network > Routing, or move the interface to one that exists.'],
 'cp_multi_vr': ['Several virtual routers: Check Point takes one',
                 'network',
                 'routing',
                 'Push one virtual router at a time: mark the interfaces of the others skip, push, then '
                 'swap.'],
 'forti_loopback_in_zone': ['A loopback interface in a zone, FortiOS refuses it',
                            'enrichment',
                            'access',
                            'Take the loopback out of its zone under Network > Zones.',
                            'zones-enrichment'],
 'reserved_target_iface': ['Target interfaces the target reserves (HA, management)',
                           'network',
                           'interfaces',
                           'Rename the source interface under Network > Interfaces so it misses the reserved '
                           'name, or mark it skip.'],
 'mgmt_target_iface': ["The target's management interface is deferred",
                       'network',
                       'interfaces',
                       'Nothing to do now: the push dialog asks before it touches the management interface, '
                       'last.'],
 'cp_cluster_iface_unmatched': ['Cluster interfaces without a match on the target',
                                'network',
                                'interfaces',
                                "Name the interfaces like the cluster's under Network > Interfaces (Fetch "
                                'Target Interfaces lists them).'],
 'target_iface_unmatched': ['Physical interfaces the target does not have',
                            'network',
                            'interfaces',
                            'The push creates no physical port. Rename each to one of the target\'s ports '
                            'under Network > Interfaces (Fetch Target Interfaces lists them), make it a '
                            'VLAN on a port, or mark it skip.'],
 'cp_iface_unmatched': ['Physical interfaces the gateway does not have',
                        'network',
                        'interfaces',
                        "Gaia creates no physical interface. Rename each to one of the gateway's ports under "
                        'Network > Interfaces (Fetch Target Interfaces lists them), make it a VLAN on a '
                        'port, or mark it skip.'],
 'tunnel_unsupported': ['Tunnel interfaces the target cannot take',
                        'network',
                        'interfaces',
                        'Mark the tunnel interfaces skip. The VPN section creates the ones the target '
                        'needs.'],
 'iface_subnet_overlap': ['Ports outside this push still carry a subnet it assigns',
                          'network',
                          'interfaces',
                          'FortiOS refuses the overlap. Set "Reset the data ports this push does not '
                          'address" in the push dialog, or map the source interface onto that port under '
                          'Network > Interfaces.'],
 'iface_subnet_overlap_accepted': ['Ports outside this push will be reset (option set)',
                                   'network',
                                   'interfaces',
                                   'Nothing to do: the push clears those ports before it applies the '
                                   'addresses.'],
 'pa_rescue_point_refused': ['The firewall refuses to save a rollback point',
                             'network',
                             'routing',
                             'The firewall demands a full commit, which a configuration load on it leaves '
                             'behind. A push stops before writing until the firewall is committed, or '
                             '"Continue without a rollback point" is set in the push dialog.'],
 'pa_rescue_point_refused_accepted': ['Push without a rollback point (option set)',
                                      'network',
                                      'routing',
                                      'Nothing to do: the push goes ahead. A push that breaks off cannot be '
                                      'taken back and leaves a partly written candidate.'],
 'ipv6_deny_loss': ['Deny rules losing IPv6 members this target does not carry',
                    'objects',
                    None,
                    'The rule denied IPv6 traffic the target cannot express in this version, so the migrated '
                    'rule would let it through. Skip the rule for this push, or exclude the IPv6 member in '
                    'the project and build again.'],
 'appdef_widened': ['Allow rules that would match every service',
                    'ruleset',
                    'security',
                    'The source matched its applications on their default ports and the target cannot '
                    'resolve them, so the migrated rule would allow every service. If every service is '
                    "acceptable, set the rule's service mode to any under Policies > Security, which records "
                    'your decision. Otherwise exclude or disable the rule. Then build again.'],
 'vpn_psk_rule': ['Pre-shared keys the target refuses',
                  'network',
                  'vpn',
                  'A stored key does not meet the rule of this target (the finding names the rule). Set '
                  'the key again under Network > VPN, then push. The network push refuses until then.'],
 'pa_forward_trust_missing': ['Decryption rules without a forward-trust certificate on the target',
                              'ruleset',
                              'decryption',
                              'The firewall has no forward-trust certificate, so the commit would fail. '
                              'Provision it on the firewall (Device > Certificate Management > SSL '
                              'Decryption) and build again, or exclude the decryption rules.'],
 'unresolved_reference': ['Rules referencing objects the build does not create',
                          'objects',
                          None,
                          'A value has no address or service object, or the object is empty or dropped for '
                          'this target, and a side without it would match wider than the source. Create the '
                          'object with exactly that value under Objects, give an empty group a member, or '
                          'exclude the rule, then build again.']}


def _fmt(v) -> str | None:
    if v is None or v == "":
        return None
    if isinstance(v, _dt.datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    return str(v)[:16]


def _as_dt(v) -> _dt.datetime | None:
    """A datetime from the loader's value (a datetime or its text)."""
    if isinstance(v, _dt.datetime):
        return v
    if v is None or v == "":
        return None
    try:
        return _dt.datetime.fromisoformat(str(v)[:19].replace("T", " "))
    except ValueError:
        return None


def _members(v) -> list:
    """member_iface_names as a list, whether the loader decoded it or not."""
    if isinstance(v, list):
        return [str(m) for m in v]
    if isinstance(v, str) and v.strip().startswith("["):
        import json
        try:
            return [str(m) for m in json.loads(v)]
        except ValueError:
            return []
    return []


def mapping_gaps(rows, target_platform, target_ifaces, name_of=None) -> dict:
    """Step 4's evidence from the project's interface rows (the one loader's
    dicts): how many carry no zone where the target needs one, and how many
    physical interfaces carry a name the target does not have. Skipped rows
    are left out, the zone rule waives what the build waives, the name rule
    runs only once the target inventory is fetched (`checked_names`).
    `name_of` maps a row to its project name (the name map)."""
    tp = (target_platform or "").lower()
    names = set(target_ifaces or ())
    checked = bool(names) and tp in NETWORK_TARGETS
    member_names: set[str] = set()
    for r in rows or ():
        member_names.update(_members(r.get("member_iface_names")))
    total = unzoned = 0
    for r in rows or ():
        if r.get("deploy_skip"):
            continue
        total += 1
        itype = (r.get("iface_type") or "").lower()
        name = str(r.get("interface_name") or "")
        enabled = r.get("enabled")
        enabled = True if enabled is None else bool(enabled)
        if (tp in ZONE_TARGETS and enabled and itype not in ZONE_WAIVED_TYPES
                and name not in member_names and not str(r.get("zone_name") or "").strip()):
            unzoned += 1
    unmatched = len(unmatched_physical(rows, names, name_of, target_platform=tp)) if checked else 0
    return {"total": total, "unzoned": unzoned, "unmatched": unmatched, "checked_names": checked}


# Targets whose renderer derives a sub-interface from a dotted name: PAN-OS
# renders ethernet1/2.100 as unit 100 of ethernet1/2 whatever the row's type
# (deploy/panw.py, the ethernet/ae units). FortiOS derives nothing from a name.
DOTTED_SUB_TARGETS = frozenset({"panw"})


def unmatched_physical(rows, target_ifaces, name_of=None, target_platform=None) -> list[str]:
    """The project names of the physical interfaces (skipped rows left out)
    the target does not have, sorted, each once. One rule for the step
    model's mapping gap and the Review's target_iface_unmatched finding.
    Empty when the target inventory is not fetched: the fetch is the
    operator's, nothing is guessed. `name_of` maps a row to its project
    name (the name map). On a target in DOTTED_SUB_TARGETS a dotted name
    whose parent the target has is the sub-interface the push derives
    (for example ethernet1/2.100)."""
    names = set(target_ifaces or ())
    if not names:
        return []
    dotted = (target_platform or "").lower() in DOTTED_SUB_TARGETS
    out: list[str] = []
    for r in rows or ():
        if r.get("deploy_skip"):
            continue
        if (r.get("iface_type") or "").lower() != "physical":
            continue
        name = str(r.get("interface_name") or "")
        pname = str(name_of(r) if name_of else name) or name
        if dotted and "." in pname and pname.split(".")[0] in names:
            continue
        if pname and pname not in names and pname not in out:
            out.append(pname)
    return sorted(out)


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def evaluate(f: dict) -> dict:
    """The steps of one project from its facts. Keys read: target_platform,
    target_capable, is_optimization, source_name, target_name,
    source_import_ts, fetch_ts, mapping (mapping_gaps or None), edits,
    build {state, job_id, built_at, blockers}, reviewed_job_id, reviewed_at,
    pushed_policy_job_id, pushed_policy_at, pushed_network_job_id,
    pushed_network_at, edit_stamps {policy, network} (the last edit of each
    strand, D88), verified_job_id, verified_at, strands {policy, network}
    (optional: both on by default where the target's platform has a network
    strand, main.py switches network off where the driver declares it, a
    Check Point virtual system), counts {routes, pbf, vpn, rules, nat, ssl,
    tp, objects, groups, services, service_groups, schedules, url_categories}
    (None when not loaded: the project list wants the status only, the
    sections then do not apply), seen {view: datetime}, vpn {total,
    psk_missing, cert_missing} or None, blocker_kinds {kind: n} of the
    current build, skips {step: datetime} (D20), identities (the firewall rules of
    the import that carry source users, D62), target_ngfw_mode (a FortiGate's
    effective NGFW mode, D62)."""
    tp = (f.get("target_platform") or "").lower()
    capable = bool(f.get("target_capable"))
    opt = bool(f.get("is_optimization"))
    strands = dict(f.get("strands") or {"policy": True, "network": tp in NETWORK_TARGETS})
    net = bool(strands.get("network"))
    build = f.get("build") or {}
    bstate = build.get("state") or "missing"
    bjob = build.get("job_id")
    blockers = int(build.get("blockers") or 0)
    counts = f.get("counts")
    seen = f.get("seen") or {}
    import_dt = _as_dt(f.get("source_import_ts"))
    steps: list[dict] = []

    def add(key, state, detail="", hint=None, place=None, label=None):
        tab, sub, nav, *more = place or PLACES[key]
        steps.append({"key": key, "label": label or dict(STEPS)[key], "state": state, "detail": detail,
                      "hint": hint, "tab": tab, "sub": sub, "nav": nav, "main": more[0] if more else None})

    def seen_at(key):
        """The visit that counts (D16): the latest one, after the import."""
        ts = seen.get(key)
        if not ts:
            return None
        seen_dt = _as_dt(ts)
        if import_dt and seen_dt and seen_dt < import_dt:
            return None
        return ts

    def count(*keys) -> int:
        return sum(int((counts or {}).get(k) or 0) for k in keys)

    # 1 the project exists with both ends
    add("devices", "done", f"Source {f.get('source_name') or '?'}, target {f.get('target_name') or '?'}"
        + (" (the same Device, an optimization)" if opt else ""))
    # 2 the source import
    its = _fmt(f.get("source_import_ts"))
    add("import", "done" if its else "open",
        f"Imported {its}" if its else "Nothing imported from the source yet",
        None if its else "Import the source Device on the Dashboard.")
    # 3 the target inventory (a network strand only)
    if opt:
        add("fetch", "na", "The target is the source itself")
    elif not net:
        add("fetch", "na", "The target takes no network strand")
    elif not capable:
        add("fetch", "locked", LOCK_SENTENCE)
    else:
        fts = _fmt(f.get("fetch_ts"))
        ferr = f.get("target_fetch_error") or None
        if ferr:
            # the target's newest read failed (product finding 9, 2026-11-16): the step
            # reopens and names the refusal, whatever an earlier fetch brought
            when = _fmt(ferr.get("at"))
            add("fetch", "open",
                f"The target could not be read{' ' + when if when else ''}: {ferr.get('text') or 'the read failed'}",
                "Check the target's address and API key under Devices, then fetch its interfaces under Network > Interfaces.")
        else:
            add("fetch", "done" if fts else "open",
                f"Fetched {fts}" if fts else "The target's interfaces were not fetched yet",
                None if fts else "Fetch the target's interfaces under Network > Interfaces.")
    # 4 zones and names: the zones are bound under Network > Zones (the zones
    # panel of Profiles & Settings), the names are renamed under Network > Interfaces, so the
    # step's place follows the target (zones or names) and the open finding
    mplace = PLACES["mapping"] if tp in ZONE_TARGETS else PLACES["fetch"]
    m = f.get("mapping")
    if opt or (not net and tp not in ZONE_TARGETS):
        add("mapping", "na", "The target is the source itself" if opt else "The target takes no interface mapping", place=mplace)
    elif not capable:
        add("mapping", "locked", LOCK_SENTENCE, place=mplace)
    elif m is None:
        add("mapping", "open", "Not evaluated", None, place=mplace)
    elif not m.get("total"):
        add("mapping", "na", "The source carries no interfaces", place=mplace)
    else:
        uz, um = int(m.get("unzoned") or 0), int(m.get("unmatched") or 0)
        if uz == 0 and um == 0:
            add("mapping", "done", f"{m['total']} interface(s) mapped"
                + ("" if m.get("checked_names") or tp not in NETWORK_TARGETS
                   else ", names not checked until the target inventory is fetched"), place=mplace)
        elif uz:
            add("mapping", "open", f"{uz} interface(s) without a zone",
                f"Bind {uz} interface(s) to zones under Network > Zones.", place=PLACES["mapping"])
        else:
            add("mapping", "open", f"{um} interface name(s) the target does not have",
                f"{um} interface name(s) do not exist on the target, rename them under Network > Interfaces.", place=PLACES["fetch"])

    # 5 to 12 the sections of the project (D16): what the project carries,
    # gone through once opened after the import, the VPN tunnels also want
    # their secrets. Not loaded (the project list): they do not apply.
    def section(key, n, what, sentence, gate=None, na="", label=None, place=None, needs_target=False):
        if counts is None:
            add(key, "na", "Not evaluated", place=place, label=label)
        elif gate is False:
            add(key, "na", na or "The target has no such view", place=place, label=label)
        elif not n:
            add(key, "na", na or f"No {what} imported", place=place, label=label)
        elif gate is not False and not capable and (needs_target or key in ("vpn", "ssl", "tp")):
            add(key, "locked", LOCK_SENTENCE, place=place, label=label)
        else:
            ts = seen_at(key)
            if ts:
                add(key, "done", f"{n} {what}, seen {_fmt(ts)}", place=place, label=label)
            else:
                add(key, "open", f"{n} {what}", sentence, place=place, label=label)

    n_routes = count("routes")
    section("routing", n_routes if net else 0, "route(s)",
            f"Review the {n_routes} route(s) under Network > Routing: drop what the target should not carry.",
            na="The target takes no network strand" if not net else "")
    # the zone bindings of a target that uses zones, after the routes (D78, D82, D90): the derived
    # zones and the rule mapping follow the routes, so the look comes once the routes are reviewed
    if not capable:
        add("zones", "locked", LOCK_SENTENCE)
    elif opt:
        add("zones", "na", "The target is the source itself")
    elif not f.get("zones_review"):
        add("zones", "na", "The target takes no zone bindings")
    elif seen_at("zones"):
        add("zones", "done", f"Zones seen {_fmt(seen_at('zones'))}")
    else:
        add("zones", "open", "The zone bindings were not looked at",
            "Check the zone bindings under Network > Zones.")
    n_pbf = count("pbf")
    section("pbf", n_pbf, "policy routing rule(s)",
            f"Review the {n_pbf} policy routing rule(s) under Network > Policy Routing.")
    # the PAN-OS fields of the policy routing rules, the Target Settings mode of the leaf (D62)
    section("pbf_settings", n_pbf, "policy routing rule(s)",
            f"Set source user and symmetric return for the {n_pbf} policy routing rule(s) under Network > Policy Routing > Target Settings.",
            gate=(tp in PBF_SETTINGS_TARGETS) if n_pbf else None, needs_target=True)
    v = f.get("vpn") or {}
    n_vpn = int(v.get("total") if v.get("total") is not None else count("vpn"))
    if counts is None:
        add("vpn", "na", "Not evaluated")
    elif not n_vpn:
        add("vpn", "na", "No VPN tunnels imported")
    elif tp not in VPN_TARGETS:
        add("vpn", "na", "The target has no VPN view")
    elif not capable:
        add("vpn", "locked", LOCK_SENTENCE)
    elif int(v.get("psk_missing") or 0):
        k = int(v["psk_missing"])
        add("vpn", "open", f"{k} tunnel(s) without a pre-shared key",
            f"Set the pre-shared key of {k} tunnel(s) under Network > VPN.")
    elif int(v.get("cert_missing") or 0):
        k = int(v["cert_missing"])
        add("vpn", "open", f"{k} tunnel(s) without a certificate",
            f"Set the certificate of {k} tunnel(s) under Network > VPN.")
    elif seen_at("vpn"):
        add("vpn", "done", f"{n_vpn} tunnel(s) with their secrets, seen {_fmt(seen_at('vpn'))}")
    else:
        add("vpn", "open", f"{n_vpn} tunnel(s), secrets set",
            f"Review the {n_vpn} VPN tunnel(s) under Network > VPN.")
    n_rules = count("rules")
    section("rules", n_rules, "firewall rule(s)",
            f"Review the {n_rules} firewall rule(s) under Policies > Security: disable what the target should not carry, find shadowed ones.")
    n_nat = count("nat")
    section("nat", n_nat, _plural(n_nat, "NAT entry", "NAT entries").split(" ", 1)[1],
            f"Review the {_plural(n_nat, 'NAT entry', 'NAT entries')} under Policies > NAT.")
    # what the target's NAT needs per rule, the Target Settings mode of the leaf (D62)
    section("nat_settings", n_nat, _plural(n_nat, "NAT entry", "NAT entries").split(" ", 1)[1],
            f"Set the target's NAT fields for the {_plural(n_nat, 'NAT entry', 'NAT entries')} under Policies > NAT > Target Settings.",
            gate=(tp in SETTINGS_TARGETS) if n_nat else None, needs_target=True)
    n_ssl = count("ssl")
    section("ssl", n_ssl, "decryption rule(s)",
            f"Review the {n_ssl} decryption rule(s) under Policies > Decryption.",
            gate=(tp in SSL_TARGETS) if n_ssl else None)
    n_tp = count("tp")
    section("tp", n_tp, "threat prevention rule(s)",
            f"Review the {n_tp} threat prevention rule(s) under Policies > Threat Prevention.",
            gate=(tp in TP_TARGETS) if n_tp else None)
    n_obj = count("objects", "groups", "services", "service_groups", "schedules", "url_categories")
    section("objects", n_obj, "object(s)",
            f"Review the {n_obj} object(s) under Objects: rename, merge or delete what the target does not need.")
    # the views of Profiles & Settings, one recommended step each (D62): where the target
    # has the view and the project carries something for it
    ngfw = (f.get("target_ngfw_mode") or "").lower()
    if tp == "fortigate":
        section("profiles", n_rules, "firewall rule(s)",
                f"Attach UTM profiles to the {n_rules} firewall rule(s) under Profiles & Settings > UTM Profiles.",
                gate=True if n_rules else None, needs_target=True, label="UTM profiles attached",
                place=("enrichment", "access", "main-btn-utm-profiles", "utm-profiles"))
    else:
        section("profiles", n_rules, "firewall rule(s)",
                f"Attach security profiles to the {n_rules} firewall rule(s) under Profiles & Settings > Security Profiles.",
                gate=(tp in PROFILE_TARGETS) if n_rules else None, needs_target=True)
    section("applications", n_rules, "firewall rule(s)",
            f"Set the application match of the {n_rules} firewall rule(s) under Profiles & Settings > Applications.",
            gate=(tp in APP_TARGETS or (tp == "fortigate" and ngfw == "policy-based")) if n_rules else None,
            needs_target=True, na="The target matches applications per rule in NGFW policy-based mode only" if tp == "fortigate" else "")
    section("logging", n_rules, "firewall rule(s)",
            f"Set logging for the {n_rules} firewall rule(s) under Profiles & Settings > Logging.",
            gate=(tp in SETTINGS_TARGETS) if n_rules else None, needs_target=True)
    n_sched = count("schedules")
    section("schedule", n_sched, "schedule(s)",
            f"Review the {n_sched} schedule(s) on the firewall rules under Profiles & Settings > Schedule.",
            gate=(tp in SETTINGS_TARGETS) if n_sched else None, needs_target=True)
    n_ident = int(f.get("identities") or 0)
    section("identity", n_ident, "firewall rule(s) with source users",
            f"Review the source users of {n_ident} firewall rule(s) under Profiles & Settings > Source User.",
            gate=(tp in SETTINGS_TARGETS) if n_ident else None, needs_target=True)
    n_tags = count("tags")
    section("tags", n_tags, "tag(s)",
            f"Review the {n_tags} tag(s) under Profiles & Settings > Tags: add tags or a group tag to the rules.",
            gate=(tp in TAG_TARGETS) if n_tags else None, needs_target=True)

    # 13 the blocking findings of the current build, each with its place (D18)
    kinds = f.get("blocker_kinds") or {}
    if capable and bstate == "current" and kinds:
        for kind in sorted(kinds):
            n = int(kinds[kind] or 0)
            if n <= 0:
                continue
            k = KINDS.get(kind) or [kind.replace("_", " "), "deploy", None, ""]
            tab, sub = k[1], k[2]
            main = k[4] if len(k) > 4 else None
            nav = NAV_OF.get((tab, sub, main)) or NAV_OF.get((tab, sub, None)) or "primary-btn-deploy"
            steps.append({"key": f"fix:{kind}", "label": f"Fix: {k[0]}", "state": "open",
                          "detail": f"{n} finding(s) of this kind in the current build",
                          "hint": k[3] or "Open Review & Deploy.", "tab": tab, "sub": sub, "nav": nav,
                          "main": main, "fix": True})

    # 14 the review of a current build without blockers
    if not capable:
        add("review", "locked", LOCK_SENTENCE)
    elif bstate == "missing":
        add("review", "open", "No target configuration built yet",
            "Open Review & Deploy to build the target configuration.")
    elif bstate == "building":
        add("review", "open", "The target configuration is building",
            "The target configuration is building, open Review & Deploy when it is done.")
    elif bstate == "outdated":
        add("review", "open", "The target configuration is outdated",
            "The target configuration is outdated: open Review & Deploy, it rebuilds.")
    elif blockers:
        add("review", "open", f"{blockers} blocker(s) in the Review",
            f"{blockers} blocker(s) stop the push: open Review & Deploy.")
    elif bjob and f.get("reviewed_job_id") == bjob:
        add("review", "done", f"Reviewed {_fmt(f.get('reviewed_at')) or ''}".rstrip())
    else:
        add("review", "open", "The current build was not reviewed yet",
            "Review the target configuration under Review & Deploy.")
    # 15 the push of every strand from the current build
    enabled = [s for s in ("network", "policy") if strands.get(s)]
    if not capable:
        add("push", "locked", LOCK_SENTENCE)
    elif not (bstate == "current" and not blockers and bjob):
        add("push", "open", "Waits for a current build without blockers", None)
    else:
        stamps = f.get("edit_stamps") or {}

        def carried(s):
            # a strand pushed from an earlier build still counts when nothing of it changed since
            # that push and the rebuild came from an edit to the other strand (D88): the render
            # of an unchanged strand is the same. A version change carries no edit stamp, a
            # Rebuild by hand neither, both ask for every strand of the new build.
            pat = _as_dt(f.get(f"pushed_{s}_at"))
            own = _as_dt(stamps.get(s))
            if not pat or (own and own > pat):
                return False
            return any((_as_dt(stamps.get(t)) or pat) > pat for t in enabled if t != s)
        pushed = {s: f.get(f"pushed_{s}_job_id") == bjob or carried(s) for s in enabled}
        if enabled and all(pushed.values()):
            ts = max((f.get(f"pushed_{s}_at") for s in enabled if f.get(f"pushed_{s}_at")), default=None)
            add("push", "done", f"Pushed {_fmt(ts) or ''} ({', '.join(enabled)})".replace("  ", " "))
        elif "network" in enabled and not pushed.get("network"):
            add("push", "open", "The network strand of this build was not pushed",
                "Push the network strand under Review & Deploy, then the policy." if "policy" in enabled
                else "Push the network strand under Review & Deploy.")
        else:
            add("push", "open", "The policy strand of this build was not pushed",
                "Push the policy strand under Review & Deploy.")
    # 16 the operator's word
    push_done = steps[-1]["state"] == "done"
    if not capable:
        add("verify", "locked", LOCK_SENTENCE)
    elif bjob and f.get("verified_job_id") == bjob and push_done:
        add("verify", "done", f"Verified {_fmt(f.get('verified_at')) or ''}".rstrip())
    elif not push_done:
        add("verify", "open", "After the push", None)
    else:
        add("verify", "open", "The pushed build was not verified yet",
            VERIFY_SENTENCES.get(tp, VERIFY_DEFAULT))

    # the operator's skips (D20): an open step the operator put aside reads
    # skipped and is not the next one, evidence beats the skip
    skips = f.get("skips") or {}
    for s in steps:
        s["skippable"] = skippable(s["key"])
        if s["state"] == "open" and s["skippable"] and skips.get(s["key"]):
            s["state"] = "skipped"
            s["detail"] = f"Skipped {_fmt(skips[s['key']]) or ''}".rstrip()
            s["hint"] = None

    nxt = next((s for s in steps if s["state"] == "open" and s.get("hint")), None)
    if nxt is None:
        nxt = next((s for s in steps if s["state"] == "locked"), None)
        if nxt is not None:
            nxt = dict(nxt, hint=LOCK_SENTENCE, tab="projects", sub=None, main=None, skippable=False)
    applicable = [s for s in steps if s["state"] in ("done", "open", "locked")]
    skipped = sum(1 for s in steps if s["state"] == "skipped")
    verified = any(s["key"] == "verify" and s["state"] == "done" for s in steps)
    return {
        "steps": steps,
        "marks": nav_marks(steps, nxt["key"] if nxt else None),
        "next": nxt["key"] if nxt else None,
        "hint": ({"text": nxt["hint"], "tab": nxt["tab"], "sub": nxt["sub"], "main": nxt.get("main"), "nav": nxt["nav"],
                  "step": nxt["key"], "skippable": bool(nxt.get("skippable"))}
                 if nxt else None),
        "done": sum(1 for s in applicable if s["state"] == "done"),
        "total": len(applicable),
        "skipped": skipped,
        "complete": bool(applicable) and all(s["state"] == "done" for s in applicable),
        "done_text": ("The project is verified." if verified
                      else f"Every remaining step is done, {skipped} skipped: resume them under the light bulb at the top of the page." if skipped
                      else "Every step is done."),
    }


def nav_marks(steps: list, nxt: str | None) -> dict:
    """The navigation markers (D2, D17): per navigation entry one state, done
    when every step on it is done or does not apply (an entry whose steps all
    do not apply carries none), next for the first open step, locked when the
    target is out of reach, open otherwise, with the step's sentence or
    detail as the title. The heads above the leaves aggregate their branch:
    done when everything below is done, open while a step below is open or
    next (the client bubbles the Next tag onto a folded head), locked when
    everything below is locked. Devices carry no marker."""
    out: dict = {}
    for s in steps or ():
        if s["key"] == "devices":
            continue
        nav = s["nav"]
        if s["key"] == nxt:
            state = "next"
        elif s["state"] in ("done", "na"):
            state = "done"
        elif s["state"] == "locked":
            state = "locked"
        else:
            state = "open"
        title = s["hint"] if (s["key"] == nxt and s.get("hint")) else s["detail"]
        # a skipped step carries no marker and does not hold its entry open (D20)
        if s["state"] == "skipped":
            state = "done"
        applies = s["state"] not in ("na", "skipped")
        cur = out.get(nav)
        if cur is None:
            out[nav] = {"state": state, "title": title, "applies": applies}
            continue
        cur["applies"] = cur["applies"] or applies
        if state == "next":
            cur.update(state="next", title=title)
        elif cur["state"] == "next":
            pass
        elif cur["state"] == "done" and state != "done":
            cur.update(state=state, title=title)
    buckets: dict[str, list] = {}
    for nav, v in list(out.items()):
        if not v["applies"]:
            continue
        p = NAV_PARENTS.get(nav)
        while p:
            buckets.setdefault(p, []).append(v)
            p = NAV_PARENTS.get(p)
    for p, vs in buckets.items():
        own = out.get(p)
        allv = vs + ([own] if (own and own["applies"] and own not in vs) else [])
        if any(v["state"] == "next" for v in allv):
            st, title = "open", next(v["title"] for v in allv if v["state"] == "next")
        elif all(v["state"] == "done" for v in allv):
            st, title = "done", "Everything in this branch is done"
        elif all(v["state"] == "locked" for v in allv):
            st, title = "locked", LOCK_SENTENCE
        else:
            st, title = "open", f"{sum(1 for v in allv if v['state'] != 'done')} step(s) open in this branch"
        out[p] = {"state": st, "title": title, "applies": True}
    return {k: {"state": v["state"], "title": v["title"]} for k, v in out.items() if v["applies"]}


def status_of(result: dict, f: dict) -> str:
    """The project status the list filters on (D7): verified with step 16,
    pushed once any strand was pushed (a later build does not step it back),
    generated with a build, curated with the first edit, else draft. `closed`
    is the operator's and never derived here. The seen sections never move
    the status."""
    st = {s["key"]: s["state"] for s in result.get("steps") or []}
    if st.get("verify") == "done":
        return "verified"
    if (st.get("push") == "done" or f.get("pushed_policy_job_id") or f.get("pushed_network_job_id")
            or (f.get("status") in ("pushed", "verified"))):
        return "pushed"
    if (f.get("build") or {}).get("job_id"):
        return "generated"
    if int(f.get("edits") or 0) > 0:
        return "curated"
    return "draft"
