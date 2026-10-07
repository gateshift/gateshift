# Changelog

All notable changes to Gateshift, newest first. This file covers the current
major version. It ships with every release and is the source of the release
notes.

## 0.9.3 (2026-10-07)

Feature and fix release.

**New**

- **Review & Deploy**: builds the target configuration and compares it with
  the source, with counts of imported, changed and dropped items for every
  kind and the change per rule.
- **Projects and snapshots**: reference your devices in projects, and keep
  snapshots and branches of your configurations.
- **Login and TLS**: one admin account, set on the first visit. HTTPS on 443
  from the web container, HTTP on 80 redirects.
- **Tenants** in the Community Edition.
- **New navigation**: projects first, one navigation tree instead of tab
  strips.
- **OPNsense configuration upload** as a source.

**Improved**

- The generate declares what it leaves out and what it creates, each with
  its reason. The Review flags whatever nothing explains.
- FortiGate: a VIP that no policy uses is declared on PAN-OS and Check Point
  targets. The device dialog's NAT-mode select offers Auto.
- Check Point: the collect lets Gaia add to the gateway object, never
  contradict it.

**Fixed**

- FortiGate: an object the render dropped stayed valid for the rules and
  groups that referenced it.
- An any-source rule reached the drivers as the literal "::". An IPv6 literal
  no longer becomes an address object on the target.
- Check Point: "Fetch target interfaces" never finished its refresh.
- `install.sh` rebuilds the images on every run, so an update actually runs
  the new code instead of the image of the earlier installation.

**Updating from 0.9.2**

- The UI moves from HTTP on 8080, bound to the loopback address by default,
  to HTTPS on 443 on every address of the host (HTTP 80 redirects). Free both
  ports, and set `WEBUI_BIND=<address>` in `.env` if the UI must stay on one
  address. The first visit after the update sets the admin password.
- There is no guaranteed database migration path between releases.

**Reporting**: bugs via [issues](https://github.com/gateshift/gateshift/issues)
(vendor, exact firmware version, verbatim error text), vulnerabilities via
[private reporting](https://github.com/gateshift/gateshift/security/advisories/new).

## 0.9.2 (2026-09-25)

Note: 0.9.1 was a development build and was never released; 0.9.2 is the
first release after 0.9.0.

Feature and fix release, validated with a full 12-leg cross-vendor migration
matrix (Palo Alto Networks, FortiGate, Check Point and Cisco ASA sources
against Palo Alto Networks, FortiGate and Check Point targets) on a
production-sized estate.

**New**

- **Shadowed-rule detection**: the Ruleset gains a "Shadowed" filter that
  finds rules an earlier, broader rule fully covers (including duplicates),
  follows the selected target's semantics (Check Point access layers are
  zoneless), and supports bulk disable/delete before the push.
- **Deploy log**: one persistent, expandable log for pushes, publishes,
  generates, pipeline runs, imports and collects, with status, duration, failing
  step and push parameters. Still-running pushes re-attach from
  their history row.
- **Conflict check after every Check Point policy publish**, naming the
  affected rules in the log, including partial overlaps only Check Point's
  own verification can see.
- **FortiGate NAT**: per-policy hide NAT survives migration (resolved to the
  egress address, optional consolidation), the ruleset shows each rule's NAT
  state, and a NAT-mode preflight (central vs per-policy) stops mismatched
  pushes early.
- **Default-policy fidelity**: vendor default rules are imported and marked.
  On push a pristine default is skipped, a modified one lands as an explicit
  rule, inexpressible cases are declared. Palo Alto rule types
  (intrazone/interzone) push faithfully.
- **Management-port preflight**: a push that would touch a FortiGate
  management port requires a typed confirm. Check Point targets show the
  dialog only when a pushed interface actually maps onto the management
  interface (unconfirmed pushes skip it safely).
- **Syslog captures upload directly in the UI** (Add device > Log source),
  with format pre-check and immediate discovery.
- **Palo Alto Networks revert on failure**: a failed push restores the
  candidate configuration instead of leaving a partial candidate behind.

**Improved**

- Explicit re-generate button, batched object cleanup, NAT zone derivation
  with bulk apply, renameable default virtual router, tunnel as interface
  type, routing egress derived from the next hop.
- Push resilience on all targets: transient connection failures retry with
  backoff, interactive probes fail fast instead of freezing the UI, and long
  Check Point publishes are polled patiently instead of being reported as
  failed.
- Unconfigured Palo Alto chassis ports are discovered on import and by
  "Fetch target interfaces". A fresh target offers its full port inventory
  for mapping.
- The optional fallback ruleset (Palo Alto targets) now strips security
  profiles from its clones along with zones and App-ID.
- UI polish: compact push dialogs, consistent font sizes, proper vendor names
  ("Check Point", "Palo Alto Networks"), bulk disable/delete on rule
  selections, dimmed unset profile slots, clearer hints on Check Point API
  refusals and Docker permission errors.

**Fixed**

- Curation survives re-import: interface renames, zone bindings, type/VLAN
  corrections, skip flags, rule toggles, route edits and user-added objects
  re-attach to the new import (content fields deliberately reset to the
  source).
- Zone auto-derive fills instead of freezing, derived zone lists are
  deterministic, and the ruleset shows exactly the zones the push sends.
- Check Point: predefined services resolve from the target's catalog instead
  of being pushed as renamed copies. Unpushable NAT translations are declared
  and skipped. Push results count objects, not API commands. VLAN push
  enables admin-down parent ports as a declared step. The add-device
  wizard's Back button works.
- FortiGate: zones emptied by skips push as valid empty zones, and tunnel
  interfaces in zone members or rule slots no longer fail the push. Both are
  declared per rule instead.
- Palo Alto Networks: IKE DH groups downgrade to what the target version
  supports, and application names normalize against the live catalog (both
  used to fail commits).
- Cisco ASA: object NAT with a static mapping imported with the wrong NAT
  type.
- A schedule the target cannot represent drops with a per-rule note instead
  of failing the push. The Schedules view renders readable intervals and
  correct "unused" badges.
- The server-side push validation gate actually runs now. Deleting an
  interface behind a rule-referenced zone asks for confirmation instead of
  hard-blocking. Result banners no longer replay on reload.

**Documentation**

- README links four full-length demo videos. KNOWN_LIMITATIONS describes the
  Shadowed filter and the post-publish conflict check.

**Updating from 0.9.0**

- There is no guaranteed database migration path between releases until
  1.0: dump your database before updating. Re-import from the sources is the
  supported fallback.

## 0.9.0 (2026-09-01)

First public release.

Gateshift migrates firewall configurations between vendors and deployment
models, generates rulesets from traffic logs, and optimizes existing
configurations, fully offline and under the operator's control at every step.

**Highlights**

- Cross-vendor migration between Palo Alto Networks (PAN-OS), FortiGate
  (FortiOS) and Check Point (Management API + Gaia), each as source and
  target, standalone or HA cluster
- Additional sources: Cisco FTD (FDM-managed), Cisco ASA configuration
  files, OPNsense traffic logs
- Migration scope: interfaces, routes, zones, rulesets, NAT, objects and
  groups, security profiles, schedules, tags, IPsec site-to-site VPN, threat
  prevention
- Ruleset generation from traffic logs, with quality filtering and
  consolidation
- Enrichment workflow: zone and interface auto-derivation, application
  auto-assignment, bulk profile/logging/schedule editing
- In-place optimization and cleanup, using the same pipeline with one device
  as source and target
- Guided installer (`./install.sh`), full stack via Docker Compose

**Before you start**

- Read KNOWN_LIMITATIONS.md and docs/vendor-prerequisites.md before the
  first migration
- Until 1.0 there is no guaranteed database migration path between releases:
  dump your database before updating. Re-import from the sources is the
  supported fallback
