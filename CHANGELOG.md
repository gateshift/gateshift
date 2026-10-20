# Changelog

All notable changes to Gateshift, newest first. This file covers the current
major version. It ships with every release and is the source of the release
notes.

## 0.9.4 (2026-10-20)

**New**

- **New platforms**: Amazon Web Services, Microsoft Azure, Google Cloud,
  Smart-1 Cloud and FortiGate Cloud.
- **FortiGate in NGFW policy-based mode**, as a target and as a source.
- **Enterprise Edition**: FortiManager Cloud and Strata Cloud Manager support.

**Fixed**

- **Two Devices with one name no longer share a ruleset**, keep their own
  curation and push their own rule order.
- **IPv6 values are declared per rule**, and a deny or drop rule that loses
  one blocks the push, because the migrated rule would let through what the
  source denied.
- **IPv6 on the targets**: Check Point gateways take IPv6 interface addresses
  and static routes, PAN-OS targets IPv6 addresses, static routes and
  policy-routing next hops, FortiOS targets IPv6 objects and policies of both
  families.
- **IPv6 NAT is declared on every target**, as is a rule whose two sides are
  of different families, which is not pushed.
- **IPv6 from the sources**: a FortiGate brings its IPv6 objects, groups,
  VIPs, pools and routes, and the Cisco ASA, OPNsense, FDM and cloud readers
  import the IPv6 they left out before.
- **A rule side of one family carries its family**, so a dual-stack target
  gets a catch-all object of that family instead of a widened rule.
- **IPv6 in the VPN strand**: a tunnel's peer may be an IPv6 address and its
  selectors IPv6 pairs on all three vendors.
- **Dual-stack address objects**: one object holds both families, and a rule's
  literal of either family resolves to the object that covers it.
- **The zone derivation takes IPv6**, matching addresses against IPv6 routes
  and folding public IPv6 destinations into the internet placeholder.
- **A Check Point management on an IPv6 address no longer fails open**, where
  the push could reach a host that was not the management and log in there
  with the operator's API key.
- **An IPv6 static route no longer fails a network collect**, and the routes
  stored before the fix are repaired at the first start.
- **A single imported IPv6 host** no longer stops address objects from
  resolving for IPv4 networks.
- **PAN-OS object names from IPv6 addresses** kept only the digits, so such a
  name stays readable now and a collision of two of them is declared.
- **Palo Alto target**: a failed push in additive-merge mode left an imported
  VPN certificate on the firewall.
- **Palo Alto target**: a push that breaks off mid-way no longer discards an
  uncommitted network push, because Gateshift saves a rescue point before it
  writes.
- **Palo Alto target**: a group tag the firewall did not keep no longer fails
  the whole push, and the report names the rules that went out without it.
- **PAN-OS routes**: a static route whose interface belongs to another virtual
  router no longer fails the whole router step.
- **PAN-OS catalogs**: the security profile and application catalogs listed a
  profile's own rules and a custom application's signatures as profiles and
  applications of their own.
- **Routing**: a static route whose gateway lies in no interface subnet is
  marked "no egress", and all three targets say the same about it.
- **FortiGate target**: a push removed the firewall's vendor-shipped services,
  groups, addresses and schedules whenever no policy held them.
- **FortiGate target**: a rule whose destination is a VIP the push creates
  itself was refused as an unresolved reference.
- **FortiGate target**: a zone names only interfaces the firewall has, where
  one it does not made FortiOS refuse the whole zone and stopped the network
  push.
- **FortiGate target**: a deny rule that logs UTM traffic no longer stops the
  rule push, because FortiOS takes no UTM logging on a policy that inspects
  nothing.
- **FortiGate target in central NAT mode**: a policy for a destination NAT
  matches the mapped address instead of the VIP, which FortiOS rejects there.
- **FortiGate source in central NAT mode**: a VIP yielded no destination-NAT
  rule, and a rule matching a VIP's translated address now gets the VIP as a
  destination where the target matches before translation.
- **FortiGate target in NGFW policy-based mode**: a security policy naming a
  user, group or profile the box does not have stopped the push instead of
  having the reference pruned and reported.
- **Check Point target**: a physical interface the gateway does not have is a
  blocker in the Review and stops the Gaia push before it writes anything.
- **Check Point target**: a Gaia task the gateway does not report yet no
  longer ends the push.
- **Check Point target**: the source's own applications vanished without a
  word and are declared per rule now.
- **Check Point target**: FQDN address objects are pushed as domain objects, a
  wildcard FQDN with its subdomains.
- **Check Point import**: a layer with sections came back with every rule
  repeated about fifty times.
- **Check Point import**: a security zone in a rule's source or destination
  becomes the rule's zone instead of an address nothing defined.
- **Check Point import**: domain objects are imported as FQDN objects, a
  subdomain-matching one as a wildcard FQDN.
- **Cisco ASA source**: FQDN network objects were left out and an access-list
  member naming an interface stayed unresolvable, so every rule naming either
  lost its destination.
- **Google Cloud source**: the auto-mode default network's regional subnets
  became zones and interfaces even where nothing lived in them.
- **Cloud accounts could not be changed after they were added**, as the edit
  dialog offered only the notes field.
- **An import that failed said nothing on the page**, so the page names the
  reason now and an AWS account is refused without a region.
- **An incomplete add dialog no longer returns in silence**: a missing name,
  management address, platform, cloud id or secret keeps it open and names the
  field.
- **The Community Edition showed Enterprise manager entries** in the add
  dialog.
- **A Palo Alto firewall added without an API key** read like a log source in
  the Device list.
- **Network tab**: the add-route form's Save and Cancel buttons sat in a
  hidden column, so only Enter in one of its fields saved a route.
- **Review**: the service objects built for a rule with `application-default`
  on a target without App-ID counted as an unexplained surplus.
- **Review & Deploy**: the per-rule edits of the SSL decryption rules were
  lost when a Device was renamed.
- **Log sources**: two firewalls sending the same hostname were one Device,
  and a sender is told apart by its hostname, address and serial now.
- **Log sources**: FortiOS and Check Point syslog was discarded without a
  word, and the ingest reports per file what parsed and what did not.
- **Log sources**: a line the collector could not store was dropped without a
  word, and a re-ingest of the same files writes nothing twice.
- **Log sources**: ingesting the same files twice doubled every hit count in
  the traffic evidence.
- **Devices**: a reset wiped every Device of the same vendor when the Device
  was named after its platform, and left imported objects behind.
- **VPN**: a push whose tunnels reference a pre-shared key the device holds
  under another tunnel went out with a placeholder and a tunnel that never
  came up.
- **Enterprise Edition**: re-importing a manager replaced every scope with a new
  Device, orphaning the per-rule edits, tags, settings and keys of each scope.

**Changed**

- **Renaming a Device keeps its curation**, and two Devices with one name keep
  theirs apart.
- **A bookmark that names a Device** opens the project list instead of that
  Device's rules.
- **Devices**: a display name two Devices share is refused, with both Devices
  named.
- **Review & Deploy**: a rule referencing an address or service object the
  build does not create is a blocker instead of a side that goes out as any.
- **Review & Deploy**: a target configuration built by an older Gateshift
  version counts as outdated and is built again.
- **Navigation**: Decryption and Threat Prevention sit under Rules and VPN
  under Network, and a saved view takes you to its new place.
- **The add dialog's platform list** is grouped into Firewalls and Clusters,
  Cloud Platforms, Manager and Log Sources, with no platform preselected.
- **Manager discovery**: the add dialog connects a Panorama, a FortiManager, a
  Check Point management or a Strata Cloud Manager tenant and shows its scopes
  and managed firewalls, storing nothing.
- **A cloud account** takes either its credentials or a collector bundle
  through one entry with a switch.
- **A Google Cloud account's key** is picked as the JSON file the provider
  created, and pasting the file's content still works.
- **The push dialog says what it takes to apply the push**, per vendor, where
  it claimed a manual commit on every target before.
- **Push options**: the first push dialog carries the decisions that reach
  beyond the estate, remembered per project and target.
- **PAN-OS push**: the push stops before writing when the firewall refuses to
  save a rescue point, and the dialog offers to go ahead without a rollback.
- **FortiGate push**: the box's NGFW mode is read, never switched, and a push
  built for the other mode is refused up front.
- **Updating**: the webapp refuses a run from a collector of another version,
  so both halves are updated together.
- **VPN**: pre-shared keys and identity certificates survive a re-import, and
  existing keys are carried over on update.
- **Log sources**: a sender no longer registers a Device by itself, and a
  Device is created from the sender or senders that are that firewall.
- **Devices**: deleting or resetting a Device no longer deletes the log lines
  its senders sent, which stay with the sender.

**Updating from 0.9.3**

- Dump your database before updating, and see the README's Updating section
  for the standing guidance, including when a fresh install is the shorter
  path.
- The syslog receiver writes the sender's address into the file name now, so
  a firewall that keeps sending appears once more as a new sender carrying
  its address and is attached to the same Device.
- The first start after the update takes a while, gives every stored log line
  its sender and moves the stored curation onto the Devices themselves.
- While that runs the collector does not start and every push is refused, and
  the webapp log says when it is done.
- Afterwards every target configuration is built again when its project is
  opened, and the Review tab's rule changelog lists every rule once, as
  changed, on that first build.
- A bookmark that names a Device stops working, so reach the Device from the
  Devices page.

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

Feature and fix release.

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
