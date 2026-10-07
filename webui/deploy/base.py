# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
Abstract base class for vendor-specific deploy drivers.

Each vendor (panw, fortinet, checkpoint, …) implements a subclass of
DeployDriver.  The driver is responsible for:

  1. Declaring vendor-specific settings (default_settings)
  2. Converting the abstract ruleset → vendor config format (generate)
  3. Pushing that config to the device via vendor API (push)
"""

from __future__ import annotations

import contextlib
import dataclasses
import threading
from abc import ABC, abstractmethod
from typing import Any, Iterator

# ── Transport retry context ─────────────────────────────────────
#
# The drivers' HTTP helpers retry connection-level failures with a long
# push-grade backoff (up to minutes total) - right for a push, wrong for an
# interactive request: a probe/validation/catalog read against a dead box
# stalled the whole app for the length of the backoff chain (fgt-lab find,
# 2026-09-22). Interactive entry points wrap driver calls in
# `fail_fast_transport()`; the helpers consult `transport_fail_fast()` and
# skip the long backoff for that thread.

_TRANSPORT_CTX = threading.local()


@contextlib.contextmanager
def fail_fast_transport():
    """Within this context, driver transport helpers fail fast instead of
    retrying with the push backoff profile. Thread-local, reentrant."""
    prev = getattr(_TRANSPORT_CTX, "fail_fast", False)
    _TRANSPORT_CTX.fail_fast = True
    try:
        yield
    finally:
        _TRANSPORT_CTX.fail_fast = prev


def _default_rule_pristine(rule: dict) -> bool:
    """Is a marked default rule still in its canonical shape (no narrowing,
    no logging enrichment, enabled)? Only then may it be skipped as
    'matches the target built-in'. gs-side enrichment (logging/track/
    schedule/identity/apps) and import-side PA log tweaks
    (default_rule_log_mods) force the EXPRESS path so the modification
    actually lands on the target."""
    def _any(v):
        vals = [x for x in (v or []) if x and str(x).lower() != "any"]
        return not vals
    if rule.get("disabled"):
        return False
    if rule.get("default_rule_log_mods"):
        return False
    if not (_any(rule.get("sources")) and _any(rule.get("destinations"))
            and _any(rule.get("services"))):
        return False
    if (rule.get("schedule") or rule.get("source_identities")
            or (rule.get("application") or "").strip() not in ("", "any")
            or rule.get("negate_source") or rule.get("negate_destination")
            or rule.get("negate_service")):
        return False
    if (rule.get("log_forwarding") or rule.get("log_traffic")
            or rule.get("log_start") or rule.get("track_type")):
        return False
    return True


# Effective default split per platform: FGT and PA both ship
# interzone-deny + intrazone-allow; CP's Cleanup denies everything
# (zoneless); ASA's implicit deny is per-ACL (intrazone n/a).
_DENY_DEFAULTS = {"fgt-implicit-deny", "asa-implicit-deny", "pa-interzone"}


def default_rule_disposition(rule: dict, target_platform: str):
    """Classify a marked vendor-default rule for this target.

    Returns (disposition, note): disposition is None (not a default rule -
    render normally), 'skip' (target enforces the same behavior built-in),
    'express' (push as an explicit rule so the - possibly modified -
    behavior lands verbatim) or 'drop' (inexpressible; declared).

    The equivalence table is deliberately conservative: only PRISTINE
    defaults may be skipped; anything modified is expressed so what you
    see in Gateshift is what the target enforces.
    """
    kind = (rule.get("default_rule_kind") or "").strip()
    if not kind:
        return None, ""
    pristine = _default_rule_pristine(rule)
    action = (rule.get("action") or "").lower()
    deny = action in ("deny", "drop", "reject")

    if kind in _DENY_DEFAULTS and deny and pristine:
        if target_platform == "fortigate":
            return "skip", ("matches the target's built-in Implicit Deny, "
                            "not pushed")
        if target_platform == "checkpoint":
            return "skip", ("matches the target's Cleanup rule (drop all), "
                            "not pushed")
        if target_platform == "panw":
            return "skip", ("matches the target's interzone-default (deny), "
                            "not pushed")
        if target_platform == "opnsense":
            return "skip", ("matches the firewall's own default-deny at the "
                            "end of the pf ruleset, not pushed")
    if kind == "cp-cleanup" and deny and pristine:
        if target_platform == "checkpoint":
            return "skip", ("target keeps its own Cleanup rule, not pushed "
                            "twice")
        if target_platform == "opnsense":
            # pf denies everything that no rule passed, with no intrazone
            # exception - the same semantics the Cleanup rule expresses.
            return "skip", ("matches the firewall's own default-deny, not "
                            "pushed twice")
        # CP denied EVERYTHING (zoneless); FGT/PA defaults allow intrazone -
        # express an explicit deny-all so the CP semantics land verbatim.
        return "express", ("expressed explicitly: the source denied all "
                           "traffic (Cleanup), the target's built-in default "
                           "allows intrazone")
    if kind == "pa-intrazone" and action == "allow" and pristine:
        if target_platform == "panw":
            return "skip", ("matches the target's intrazone-default (allow), "
                            "not pushed")
        if target_platform == "fortigate":
            return "skip", ("matches FortiOS zone behavior (intrazone allow "
                            "by default), not pushed")
        if target_platform == "checkpoint":
            return "drop", ("intrazone-allow is not expressible on a zoneless "
                            "target. Review: traffic between same-zone "
                            "networks is handled by the rules above / Cleanup")
        if target_platform == "opnsense":
            # An interface group is a zone, but pf has no notion of traffic
            # staying inside one: a pass rule on the group would also let
            # traffic leave it, which is wider than the source intended.
            return "drop", ("pf has no intrazone default: an equivalent "
                            "rule on the interface group would also permit "
                            "traffic leaving it, so this needs a deliberate "
                            "decision")
    if kind == "pa-intrazone" and target_platform in ("fortigate", "checkpoint",
                                                      "opnsense"):
        # modified intrazone default - no generic intrazone rule type there
        return "drop", ("modified intrazone-default is not expressible on "
                        "this target: re-create the intent manually "
                        "(FortiGate: per-zone intrazone flag)")
    # Everything else (modified deny-defaults, modified pa defaults on PA,
    # unusual actions): push explicitly so the modification lands.
    return "express", ("vendor default pushed as an explicit rule so its "
                       "(modified) behavior lands verbatim")


def transport_fail_fast() -> bool:
    return bool(getattr(_TRANSPORT_CTX, "fail_fast", False))


@dataclasses.dataclass
class StepResult:
    """Result of a single push step (e.g. 'delete rules', 'push zones').

    `data` carries vendor-specific structured payload - used today by the
    Check Point driver's final push step to hand a pending-session handle
    back to the caller (so the UI can wire Publish / Discard buttons).
    Other drivers leave it None.
    """
    step: str
    success: bool
    detail: str = ""
    data: dict | None = None


@dataclasses.dataclass
class DroppedField:
    """A field on a rule that the target vendor cannot represent.

    Surfaced to the user before push so silent degradation is impossible.
    """
    rule_id: str       # rule identifier (name or pipeline id)
    field: str         # field that was dropped, e.g. "user_identity", "fqdn"
    reason: str        # why - "not supported by target", "exceeds limit", …
    fallback: str = "" # what was used instead (empty if dropped outright)
    rhash: str = ""    # the rule's content hash (hex) when the drop belongs to a rule - the Review's change log keys on it (R2)
    explained: bool = False  # the item is not pushed and that is the COMPLETE
                             # outcome - the operator skipped it, the target
                             # derives or already has it, or it is folded into
                             # something else. The Review counts these as an
                             # explanation, not as a loss (matrix 0.9.4).
    synthesized: bool = False  # the OPPOSITE of a drop: the generate CREATED an
                               # entity the source does not carry as one - a
                               # literal turned into an object, one tcp+udp
                               # service split in two, a VIP's external
                               # address. rule_id names the created entity and
                               # fallback starts with "created". The Review
                               # subtracts these from a surplus, so a plus the
                               # generate cannot account for stays visible.

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class DropTagger:
    """Wraps a renderer's `dropped` list so every DroppedField appended while
    `current` names a rule hash carries that hash (docs/REVIEW_TAB_DESIGN.md,
    R2: the change log keys on it). One assignment per rule iteration instead
    of one keyword per drop site; everything else delegates to the list, and
    the driver's final `[d.to_dict() for d in dropped]` iterates through."""
    def __init__(self, target: list):
        self.target = target
        self.current = ""
    def append(self, d) -> None:
        if isinstance(d, DroppedField) and not d.rhash and self.current:
            d.rhash = self.current
        self.target.append(d)
    def extend(self, items) -> None:
        for d in items:
            self.append(d)
    def __len__(self): return len(self.target)
    def __iter__(self): return iter(self.target)
    def __getitem__(self, i): return self.target[i]
    def __bool__(self): return True


def error_hint(hint_fns, ctx: dict) -> str:
    """Return the first non-empty hint a driver's error-hint functions produce
    for the push-error `ctx`, or '' if none apply.

    Lets each driver keep a readable TABLE of (condition → explanatory message)
    instead of inline if/elif chains scattered at the push error sites - the
    push loop builds a `ctx` dict (step, errcode, status_code, cli_error, entry,
    …) at the failure point and asks the driver's `_ERROR_HINTS` list to explain
    it. Each fn takes `ctx` and returns the hint text *with its leading
    ' - …' separator* when it applies, else ''. A raising fn is skipped (a
    broken explainer must never mask the underlying error)."""
    for fn in hint_fns:
        try:
            h = fn(ctx)
            if h:
                return h
        except Exception:
            continue
    return ""


class DeployDriver(ABC):
    """Base class every vendor driver must implement."""

    platform: str  # e.g. "panw", "fortinet", "checkpoint"

    @abstractmethod
    def default_settings(self) -> list[dict]:
        """Return vendor-specific setting definitions for the UI.

        Each dict:
            {"key": "rule_prefix", "label": "Rule Prefix", "type": "text",
             "default": "Gateshift-", "placeholder": "e.g. Gateshift-"}
        Supported types:
          - ``text``           - free-text input
          - ``select``         - static dropdown, options in ``options`` list
          - ``select_remote``  - dropdown whose options are fetched live from
                                 the device via ``setting_options(...)``. The
                                 driver MUST implement ``setting_options`` for
                                 every key declared as ``select_remote``.
        """

    def setting_options(
        self,
        *,
        device: dict,
        key: str,
        settings: dict[str, str],
    ) -> list[str]:
        """Return the live option list for a ``select_remote`` setting.

        Called when the user opens / refreshes a ``select_remote`` dropdown
        in the UI. Drivers should query the device (via API/SSH/whatever the
        vendor offers) and return a flat list of valid string choices for
        the given key.

        ``settings`` carries the *currently saved* values for this device so
        dependent dropdowns can scope their query (e.g. CP layer-list filtered
        by the chosen policy_package).

        Default: not implemented. Drivers without any select_remote settings
        don't need to override.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not provide options for {key!r}"
        )

    @abstractmethod
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
    ) -> tuple[dict[str, str], list[dict]]:
        """Convert the abstract ruleset into vendor-specific config sections.

        Returns (sections, dropped_fields):
          sections: dict mapping section name → rendered config string
                    e.g. {"Security Rules": "<security>…</security>", …}
          dropped_fields: list of DroppedField.to_dict() for every field on
                    every rule that the target cannot represent. Empty list
                    if nothing was dropped. UI surfaces this before push.

        ``tp_configs`` carries the per-(target, TP-layer) generator config
        rows loaded from ``fw_tp_layer_config``: each entry has keys
        ``layer_name``, ``strategy``, ``params``. Drivers without a TP
        rulebase concept (PA, Fortinet) ignore this argument. The CP
        driver uses it to emit a ``"TP Rules"`` section consumed by push.
        """

    @abstractmethod
    def push(
        self,
        *,
        device: dict,
        config: dict[str, str],
        strand: str = "policy",
    ) -> Iterator[StepResult]:
        """Push config to the device.  NO auto-commit.

        device: dict with mgmt_ip, mgmt_port, api_key, platform, …
        config: output of generate()
        strand: ``'policy'`` (rules / objects / NAT) or ``'network'``
                (zones / interfaces / routes). Each strand pushes only its
                own slice of ``config``; cross-strand sections are ignored.
                Two independently triggerable push buttons in the UI map to
                the two strands - see project_network_strand.md.

        Yields StepResult for each phase (enables live streaming).
        Stops on first failure.

        For vendors with a session-scoped staging model (e.g. Check Point),
        the final StepResult must set ``data["session_handle"]`` to a
        serializable dict that can be passed to ``commit_session`` /
        ``discard_session`` later. Vendors with global candidate-config
        (e.g. PAN-OS) leave ``data`` None - the user commits via the
        device UI instead.
        """

    def commit_session(
        self,
        *,
        device: dict,
        handle: dict,
    ) -> Iterator[StepResult]:
        """Finalize a staged push (publish / commit-on-management).

        Default: not implemented. Vendors with session-scoped staging
        (Check Point) override; vendors without a separate management
        commit step (PAN-OS, where the user commits on the device)
        don't need this and the UI shouldn't call it for them.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support session-scoped commit"
        )

    def discard_session(
        self,
        *,
        device: dict,
        handle: dict,
    ) -> Iterator[StepResult]:
        """Drop a staged push without committing it. See commit_session."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support session-scoped discard"
        )

    def list_target_interfaces(self, *, device: dict) -> list[dict]:
        """Read the target's current interface configuration.

        Returns a list of dicts, one per interface, with at least:
          - ``name`` (str)
          - ``type`` (str, e.g. "ethernet", "tunnel", "loopback")
          - ``ip_addresses`` (list[str], CIDR strings; may be empty)
          - ``zone`` (str | None) - current zone binding at target, if known
          - ``description`` (str | None)
        Drivers may include extra vendor-specific keys; the UI ignores them.

        Snapshot for Discover-as-Verarbeitung-input (see
        project_network_strand.md "Target-read"). Stored in
        ``fw_target_discover``; the user explicitly saves selected rows into
        the source's ``fw_interfaces`` via the ``/network/discover/.../save``
        route. Never silent auto-merge into push.

        Default: NotImplementedError. UI hides the panel for drivers that
        don't implement it.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-interface discovery"
        )

    def list_target_zones(self, *, device: dict) -> list[dict]:
        """Read the target's current zone configuration.

        Returns a list of dicts, one per zone, with at least:
          - ``name`` (str)
          - ``interfaces`` (list[str]) - bound interface names
          - ``zone_type`` (str | None, e.g. "layer3")
        See ``list_target_interfaces`` for semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-zone discovery"
        )

    def list_target_routes(self, *, device: dict) -> list[dict]:
        """Read the target's current routing table.

        Returns a list of dicts, one per route, with at least:
          - ``prefix`` (str, CIDR)
          - ``interface_name`` (str | None)
          - ``next_hop`` (str | None)
          - ``vr_name`` (str | None) - VR / VDOM / VS the route belongs to
          - ``is_connected`` (bool)
        See ``list_target_interfaces`` for semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-route discovery"
        )

    def list_url_categories(self, *, device: dict) -> list[str]:
        """Read the target's predefined URL / application-site CATEGORY catalog
        - the category names a cross-vendor decryption rule can reference
        (site-category). Returns a sorted list of name strings.

        Snapshot for the URL-category mapping (project_cp_url_category_map_plan):
        the operator attaches a source category to one of these; the resolver
        name-matches against them. Default: NotImplementedError (target has no
        URL-category catalog, e.g. FortiGate does TLS inspection via profiles).
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not expose a URL-category catalog"
        )

    def list_target_vrfs(self, *, device: dict) -> list[dict]:
        """Read the target's VRF / virtual-router / VDOM list.

        Returns a list of dicts, one per VRF, with at least:
          - ``name`` (str)
          - ``interface_members`` (list[str])
          - ``properties`` (dict | None) - vendor-opaque (e.g. ``ecmp``)
        See ``list_target_interfaces`` for semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-VRF discovery"
        )

    def list_zone_protection_profiles(self, *, device: dict) -> list[dict]:
        """Read the target's zone-protection-profile catalog (PA-specific).

        Returns ``[{"name": str, "description": str | None}, ...]``. Used by
        Enrichment > Zone Mapping > Interfaces to populate the
        ``pa_zone_protection_profile`` dropdown in the bulk-apply form.

        Default: empty list. Vendors without a zone-protection-profile
        concept (Forti, CP, ASA, OPNsense, FTD) leave this as-is - the
        Bulk-Form catalog field stays empty and the schema-driven UI shows
        a "No catalog" hint.
        """
        return []

    def list_target_addresses(self, *, device: dict) -> list[dict]:
        """Read the target's address-object catalog.

        Returns ``[{"name": str, "type": str | None, "value": str | None}, ...]``.
        Used by Enrichment > NAT > Mapping (Phase F) to populate per-rule
        translation-object pickers so cross-vendor pushes can re-bind
        trans_src / trans_dst to objects that exist at the target.

        Default: empty list. Source-only vendors (ASA, OPNsense) leave
        this as-is.
        """
        return []

    def list_target_services(self, *, device: dict) -> list[dict]:
        """Read the target's service-object catalog.

        Returns ``[{"name": str, "proto": str | None, "port": str | None}, ...]``.
        Same use-case as ``list_target_addresses`` but for service refs
        (NAT-rule trans_service slots when present).

        Default: empty list.
        """
        return []

    def list_security_profiles(self, *, device: dict) -> dict[str, list[dict]]:
        """Read the target's per-rule attachable profile catalog.

        Returns ``{category: [{"name": str, "predefined": bool}, ...]}`` where
        keys are vendor-specific category labels (e.g. PA: ``antivirus``,
        ``url-filtering``, ``profile-group``). The ``predefined`` flag marks
        vendor-shipped entries (cannot be edited by the customer) so the UI
        can distinguish them from user-created ones. Read-only catalog query
        - surfaces what's there; Gateshift doesn't manage profile contents. The UI
        iterates whatever the driver returns; it doesn't enumerate categories
        itself.

        Out-of-scope catalog read (see project_design_decisions.md
        "Target-read scoping"): customer manages these objects, Gateshift only
        observes/references them.

        Default: NotImplementedError. Drivers without remote catalog reads
        leave this unimplemented; the Enrichment vendor sub-tab shows an
        "unsupported" hint.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support security-profile listing"
        )

    def list_applications(self, *, device: dict) -> dict[str, list[dict]]:
        """Read the target's user-curated application catalog.

        Returns ``{category: [{"name": str, "predefined": bool}, ...]}``.
        Same shape as ``list_security_profiles`` so the UI can reuse the
        catalog renderer. Categories are vendor-specific (PA: ``application``
        custom + ``application-group`` + ``application-filter``). Predefined
        vendor app catalogs (PA: thousands of content-DB apps) are
        intentionally NOT enumerated - only customer-curated objects are
        surfaced, mirroring the rule-attachment dropdown semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support application listing"
        )

    def list_threat_layers(self, *, device: dict) -> list[dict]:
        """Read the target's Threat-Prevention layer catalog.

        Returns a list of dicts, one per TP-layer:
          - ``name`` (str)         - full layer name (Gateshift stores this as key)
          - ``shared`` (bool)      - shared across packages?
          - ``uid`` (str | None)
        Read-only catalog query for the CP TP-enrichment UI; PA/Fortinet do
        not implement this (TP attaches per-rule via security-profile slot).

        Default: NotImplementedError. UI hides the TP-layer dropdown for
        drivers that don't implement it.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support threat-layer listing"
        )

    def list_threat_profiles(self, *, device: dict) -> list[dict]:
        """Read the target's Threat-Prevention profile catalog.

        Returns a list of dicts, one per TP-profile:
          - ``name`` (str)         - e.g. Basic, Optimized, Strict
          - ``predefined`` (bool)  - vendor-shipped, not user-editable
          - ``uid`` (str | None)
        Read-only; Gateshift only references profiles, doesn't manage their contents.

        Default: NotImplementedError. See ``list_threat_layers``.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support threat-profile listing"
        )

    def generate_tp_rules(
        self,
        *,
        layer_name: str,
        strategy: str,
        params: dict,
        rules: list[dict],
        zones: list[dict],
        address_objects: list[dict],
        address_groups: list[dict],
    ) -> list[dict]:
        """Deterministically generate TP-rules from a Strategy + Params.

        Pure function - no I/O - so the Preview UI and the eventual Push
        call the same code and there's no drift between what the user saw
        and what gets pushed.

        Strategy ``security-ruleset`` (V1):
          - Walk ``rules`` (the source Access-Rules) and emit one TP-rule
            per group-key (depends on ``params['scope']``).
          - Sane V1 default scope: ``source=destination=service=Any``,
            ``protected-scope`` = mapping target (e.g. dst-cidrs).

        Returns a list of dicts with the TP-rule shape (see
        project_cp_tp_rulebase_api.md for the response shape).

        Default: NotImplementedError. Drivers without a TP rulebase concept
        leave this unimplemented.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support TP-rule generation"
        )

    def canonical_port_apps(self) -> dict[tuple[str, int], list[str]]:
        """Curated (proto, port) → [app-name, …] map for the port→app
        auto-binder's tier-3 fallback.

        Drivers whose ``list_applications`` catalog already carries clean
        ``default_ports`` for every relevant app (CP's curated list) can
        leave this empty - the predefined-index tier resolves them.

        PA needs this because its predefined catalog's ``default_ports`` is
        incomplete (``imap`` handles 143 AND 993, but lists only tcp/143);
        the curated map fills those gaps. Names returned here are validated
        against the live catalog before use, so stale entries are harmless.
        """
        return {}


# ── Iface-name classification (vendor-agnostic) ──────────────────
#
# Both PA and CP encode iface type in the name. Single helper so both
# collectors classify identically, and so the lifespan-time backfill in
# main.py uses the same rules. CP-Network-Push V1 needs (parent, tag) for
# VLAN sub-IFs because Gaia's add-vlan-interface is typed.

import re as _re

_RE_TUNNEL    = _re.compile(r"^tunnel(\.|$)", _re.IGNORECASE)
_RE_LOOPBACK  = _re.compile(r"^(loopback|lo[0-9])", _re.IGNORECASE)
# 'bond' is the canonical type for both CP `bondN` and PA `aeN` aggregates.
# Vendor name pattern differs; canonical iface_type collapses both so the
# rest of the code (validation, push routing, member lookup) treats them
# uniformly.
_RE_BOND      = _re.compile(r"^(bond|ae)[0-9]+$", _re.IGNORECASE)
_RE_VLAN_TAG  = _re.compile(r"^[0-9]+$")


def parse_iface_name(name: str) -> tuple[str, str | None, int | None]:
    """Classify an interface name into (iface_type, parent, vlan_tag).

    Order is most-specific first: tunnel/loopback/bond names that happen to
    contain a dot must NOT be classified as VLAN. Returns:
      - iface_type: 'physical' | 'vlan' | 'loopback' | 'bond' | 'tunnel'
      - parent: parent IF name for VLAN sub-IFs (incl. VLAN-on-bond), else None
      - vlan_tag: VLAN ID for VLAN sub-IFs, else None
    """
    if not name:
        return "physical", None, None
    if _RE_TUNNEL.match(name):
        return "tunnel", None, None
    if _RE_LOOPBACK.match(name):
        return "loopback", None, None
    if _RE_BOND.match(name):
        return "bond", None, None
    if "." in name:
        head, _, tail = name.rpartition(".")
        if head and _RE_VLAN_TAG.match(tail):
            return "vlan", head, int(tail)
    return "physical", None, None


# ── Driver registry ──────────────────────────────────────────────

DRIVERS: dict[str, type[DeployDriver]] = {}


def register_driver(cls: type[DeployDriver]) -> type[DeployDriver]:
    """Class decorator - registers a driver by its platform attribute."""
    DRIVERS[cls.platform] = cls
    return cls


def expand_multiproto_services(
    service_objects: list[dict], service_groups: list[dict],
    dropped: list | None = None,
) -> tuple[list[dict], list[dict]]:
    """Fan out a source service that packs several (proto, port) combos into
    one object - multiple portrange families (Forti TCP+UDP+SCTP) and/or a
    space-separated port LIST per family (Forti ``"88 464"``) - into one
    single-(proto,port) service per combo PLUS a service-group with the
    ORIGINAL name holding them. Existing references (group members, rules)
    then stay valid against the group.

    Vendor-neutral: input and output are agnostic shapes
    (``{name, value:{protocol, port, description}}`` services,
    ``{name, value:{members, description}}`` groups). Single-proto, multi-port
    services on a target that natively supports them (Forti) should NOT call
    this - it is for targets whose service object is single-(proto,port)
    (Check Point, PAN-OS). A whitespace token is itself a single port ("88")
    or a hyphen range ("1-1024"), both valid. Single-combo services pass
    through (normalized to {protocol, port})."""
    families = (("tcp_portrange", "tcp"), ("udp_portrange", "udp"),
                ("sctp_portrange", "sctp"))
    new_objs: list[dict] = []
    extra_groups: list[dict] = []
    for obj in service_objects:
        val = obj.get("value") or {}
        name = obj.get("name") or ""
        desc = val.get("description") or ""

        combos: list[tuple[str, str]] = []
        fam_present = [(k, p) for k, p in families if str(val.get(k) or "").strip()]
        if fam_present:
            for k, proto in fam_present:
                for port in str(val.get(k)).split():
                    combos.append((proto, port))
        else:
            proto = (val.get("protocol") or "").strip().lower()
            portfield = str(val.get("port") or "").strip()
            if proto in ("tcp", "udp") and " " in portfield:
                for port in portfield.split():
                    combos.append((proto, port))

        if not combos:
            new_objs.append(obj)            # icmp / single-port / other → as-is
            continue
        if len(combos) == 1:
            proto, port = combos[0]
            new_objs.append({"name": name,
                             "value": {"protocol": proto, "port": port,
                                       "description": desc}})
            continue

        members: list[str] = []
        seen: set[str] = set()
        for proto, port in combos:
            sub = f"{name}_{proto}_{port}"
            if sub in seen:
                continue
            seen.add(sub)
            new_objs.append({"name": sub,
                             "value": {"protocol": proto, "port": port,
                                       "description": desc}})
            members.append(sub)
        extra_groups.append({"name": name,
                             "value": {"members": members, "description": desc}})
        if dropped is not None:
            # One source service became len(members) services and a group.
            # The first service stands for the source one; every further
            # service and the group are entities the generate created - said
            # so, or the Review's surplus check reads them as unexplained
            # (a FortiGate source: 30 such services, +64 and +30 on PAN-OS).
            for sub in members[1:]:
                dropped.append(DroppedField(
                    rule_id=sub, field="service", synthesized=True,
                    reason=f"split of '{name}': several protocols in one "
                           "source service, one protocol per target service",
                    fallback=f"created by splitting '{name}'"))
            dropped.append(DroppedField(
                rule_id=name, field="service_group", synthesized=True,
                reason=f"split of '{name}': the group keeps the source name so "
                       "references stay valid",
                fallback=f"created by splitting '{name}'"))
    # Prepend synthetic (leaf) groups so they're created before any group that
    # references them.
    return new_objs, extra_groups + list(service_groups)
