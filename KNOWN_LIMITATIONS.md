# Known Limitations

Deliberate scope boundaries of the current release. Each entry states the limit,
the behavior you will see, and the workaround where one exists. None of these
fail silently: where a limit applies, Gateshift blocks or warns explicitly.

## Access

- **One account.** The UI knows the single account `admin`. There are no
  further users and no roles. The login delay after wrong passwords is
  kept in memory and starts over with a restart of the web container.
- **Self-signed certificate.** The installer's certificate is not issued
  by a CA the browser knows, so every browser warns once. The remedy is a
  certificate from your own CA in `certs/` (OPERATING.md, Access). The
  UI sets no HSTS header for that reason.

## Review & Deploy

- **The rules change log covers the firewall ruleset.** NAT, decryption,
  threat prevention and the network kinds appear in the kind table with
  their counts and declared drops, not as a per-rule log.
- **No driver declares a split yet.** Where a vendor would need several
  entries for one source rule the drivers push one or declare a drop, so
  the "split" group stays empty today.
- **One target configuration per project.** The build keeps the latest
  only. Earlier builds are not retained (snapshots hold the edits, not
  the rendered configuration).
- **Outdated means edits Gateshift saw.** The state follows the edits,
  imports and push settings made through Gateshift. A change made on the
  source appliance itself is not an edit: re-import to pick it up.
- **Shadowing follows the target's match semantics** and skips rules it
  cannot compare (listed as "not analysed").

## Network / routing

- **Check Point network push is single routing-table.** Gaia supports native
  VRF since R81.20, but Gateshift's CP network renderer targets one routing table.
  A source with multiple virtual routers is **hard-blocked** by validation
  (`cp_multi_vr`) instead of silently collapsing the VRs.
  *Workaround:* migrate one VR at a time.
- **IPv6 is not migrated.** IPv6 objects, rules and routes are dropped with a
  warning at import.
- **Dynamic routing (BGP/OSPF) is not migrated.** Static routes and PA
  logical-router (ARE) configs are. Routing-protocol config is not.
- **Bond modes / m:1 bonds, bridge/L2 interfaces, ECMP**: not migrated.
- **Static routes with an off-link next hop and no interface are left
  out of PA and FortiGate pushes.** A route whose gateway sits in no
  subnet of the pushed interfaces (Gaia statics via a VPN peer address,
  for example) cannot be resolved by PAN-OS (the candidate fails
  validation) or FortiOS (`device` is mandatory). Both targets omit the
  route with a declared drop. Check Point targets take it as a Gaia
  static unchanged.
  *Workaround:* bind the route's egress interface in Network > Routing.
  It then renders on every target.

## Migration scope

- **Captive Portal / identity redirect policies** are not migrated.
  User/group *references* on rules migrate (vendor-native). Portal
  configuration (authentication rulebases, portal settings, auth profiles)
  does not: it depends on local identity infrastructure and is set up
  fresh on the target.
- **Check Point certificate-based VPN (ICA-issued certs)** as target: PSK and
  third-party cert auth migrate. ICA enrollment does not.
  *Workaround:* complete cert enrollment in SmartConsole after the push.
- **Cisco ASA is source-only** (config-file import, no push target).
- **(!) OPNsense 26.7 truncates any HTTP/1.1 response at 64 KiB.** Measured
  on a live box: the body stops at exactly 65528 bytes (65536 less 8) and
  ends mid-document, for every request whose reply would exceed that. It is
  the firewall and not the client: the same request over HTTP/2 returns
  311408 bytes intact, and Python's HTTP client speaks 1.1. This is why an
  OPNsense is added from an **exported configuration** rather than over the
  API: the browser speaks HTTP/2 and gets an intact file, so the ceiling
  cannot be reached on the normal path. Where the API is used anyway, a
  device registered with credentials only, Gateshift parses what it
  receives and **refuses the import** rather than migrating a policy with
  holes in it.
- **Cisco FTD is source-only, FDM-managed boxes only.** Standalone FTDs are
  imported live via the on-box FDM REST API (admin credentials). There is no
  FTD push target. FMC-managed estates cannot be read this way: registering
  an FTD to an FMC permanently disables its FDM API.

## Vendor-specific behavior

- **Panorama-managed PAN-OS / FortiManager-managed FortiGate direct imports** see only the
  device-local config layer (PA) or risk push conflicts with the manager
  (FortiGate). Gateshift detects this and warns (amber "managed" chip). Register
  the manager for the full picture.
- **FortiGate policy-held objects survive network wipes by design**: Gateshift
  never auto-deletes user firewall policies. Push the policy strand first, then
  the network strand (the push error hints say exactly this when it applies).
- **FortiGate targets take no per-policy application or URL-category match.**
  FortiOS in its default profile-based mode matches applications and URL
  categories through profiles attached to the policy (application control,
  web filter), not on the policy itself. NGFW policy-based mode is not
  supported. Application and URL-category matches of a Palo Alto or Check
  Point source are declared in the review and not pushed. Attach the profiles
  under Target Settings > UTM Profiles. Custom URL categories are pushed as
  URL filter tables for that purpose.
- **Cloud HA clusters with DHCP-addressed heartbeat/management ports**: a
  network push never modifies the HA-reserved interfaces, but the config sync
  it triggers can propagate the primary's addressing onto the secondary.
  Both members then hold the same heartbeat address and the cluster goes
  split-brain (observed on an AWS FortiGate FGCP pair). Gateshift warns before such a
  push. Give the members static per-member addresses on the heartbeat and
  management ports, and check HA health after pushing.
- **Check Point cluster targets get no new interfaces.** A push onto a
  ClusterXL target stages interface VIPs onto the cluster's *existing*
  interfaces by name match and pushes routes per member via Gaia. Source
  interfaces the cluster does not already have, including VLAN
  sub-interfaces, are skipped with a warning (the cluster infrastructure
  stays operator-managed. Standalone CP gateways do get VLAN sub-interfaces
  created).
  *Workaround:* create the interfaces on the cluster first (members in Gaia +
  cluster topology in SmartConsole), then use "Fetch Target Interfaces" in
  Gateshift and map or rename the source interfaces to the cluster's names.
- **Check Point VPN toward Palo Alto targets migrates policy-shaped.** A
  Check Point source models S2S VPN as communities (policy-based). On a
  PAN-OS target this renders as IKE gateways + IPSec tunnels with
  proxy-IDs from the encryption domains. Two parts stay with the
  operator for now: tunnel interfaces (tunnel.N) are not synthesized,
  create and bind them on the target. Long community+peer composite
  names can exceed PAN-OS name limits on some VPN entities, rename on
  the source or target where the commit complains. Crypto profiles
  without source lifetimes get PAN-OS defaults (IKE 8h, IPSec 1h).
- **VPN tunnels without a local interface are left out of PA and
  FortiGate pushes.** Check Point communities carry no local egress
  interface. A PAN-OS IKE gateway and a FortiOS phase1-interface both
  need one, and an empty local-address fails the whole PAN-OS candidate.
  Such tunnels are omitted with a declared drop (`local_interface`).
  *Workaround:* pick the interface per tunnel in the VPN tab ("set local
  IF") and regenerate.
- **Check Point cluster targets keep their existing VPN domain.** The
  Check Point Management API silently ignores VPN-domain changes on an
  existing cluster object (the set call reports success but changes
  nothing: name and uid form alike, observed on R81.x / API 1.9), so a
  VPN push onto a ClusterXL target cannot switch the cluster's local
  encryption domain. Peer devices, encryption-domain groups and
  communities are created normally.
  *Workaround:* set the cluster's VPN domain once in SmartConsole
  (Gateways & Servers > cluster > Network Management > VPN Domain).
  Everything else about the VPN push works unattended.
- **Check Point HTTPS-inspection "predefined" rules migrate even when the
  source blade is off.** A CP source ships a predefined HTTPS-inspection
  rule. Gateshift imports it and renders it as an active decryption rule on
  the target: regardless of whether HTTPS inspection was enabled on the
  source. The migration can thus produce decryption behavior the source
  never had. Predefined content is shown, not hard-filtered (you decide
  what migrates).
  *Workaround:* review the decryption rules on the target before
  committing and soft-delete rules you do not want (Target Settings >
  Decryption). Forward-proxy also needs a target-side trust certificate
  anyway (see Palo Alto prerequisites), so a decryption review is expected.
- **Check Point Threat Prevention** pushes as a separate rulebase with CP's own
  semantics (single scope, no service column). Blade-dependent track levels are
  downgraded automatically where a target layer lacks the blade.

## Cross-vendor NAT

- **Cisco FTD NAT rules carry interface references, not zones** (an FDM
  modeling quirk). On a PAN-OS target those references do not resolve into
  NAT zones yet, and the NAT push step fails, which stops the policy strand
  before the firewall rules.
  *Workaround:* deselect the **NAT Rules** section in the push dialog and
  build the NAT policy on the target. The firewall rules then push cleanly.

## Ruleset installation

- **Check Point refuses to install conflicting rules ("Rule X conflicts
  with Rule Y").** Policy verification rejects a rulebase with rule
  conflicts: fully shadowed rules as well as PARTIAL overlaps where an
  earlier rule already decides part of a later rule's traffic. PAN-OS
  and FortiOS install such rulesets silently. This surfaces on migrations whose source
  legitimately contains dead rules: an ASA config concatenates per-interface
  ACLs into one flat ruleset (each ACL's broad permits and deny-all tails
  then shadow the following ACL blocks), and shadowed entries are faithful
  imports. They were equally dead on the source.
  *Mitigation (built in):* the Configure > Rules > Firewall tab has a "Shadowed"
  filter that finds rules made unreachable by an earlier, broader rule
  (following the selected target's semantics: Check Point is zoneless),
  shows who shadows whom, and lets you disable or delete the selection
  before pushing. Disabling is safe: the rules are unreachable by
  definition, so effective behavior does not change within their own
  block. After every Check Point policy publish, Gateshift additionally
  runs the target's own policy verification and reports the rules Check
  Point names by name in the push log: that list is the authority for
  installability and includes the partial-overlap conflicts the
  Shadowed filter deliberately does not flag. Review cross-ACL fall-through after
  disabling, with a per-interface deny-all disabled, traffic can reach
  the following block's rules on the flat rulebase.

## Rules referencing skipped resources

- **Interface names are pushed as-is.** A source interface name that is
  invalid on the target platform (for example `eth0` pushed to PAN-OS)
  fails the interface push step. Rename source interfaces to target-valid
  names during curation ("Fetch Target Interfaces" offers the target's
  names), or skip interfaces that should not migrate: the reference
  guard walks you through what still depends on them.

## Source modeling gaps

- **FTD VLAN subinterfaces reference their parent by FDM hardware name**
  (for example `TenGigabitEthernet0/3`), and unnamed parent ports are not
  imported as interface rows, so the parent cannot be renamed, and the
  literal hardware name fails on FortiGate (name length) and Check Point
  (invalid interface) targets.
  *Workaround:* set the subinterface's type to `physical` in
  Network > Interfaces: it then deploys as a plain L3 interface (verified
  end-to-end).
- **IKE crypto proposals migrate literally.** Verify DH-group
  compatibility per IKE version on the target: PAN-OS, for example,
  rejects DH group21 on an IKEv1 gateway. Adjust the profile on the
  target before committing where validation complains.

## Projects and tenants

- **A device's tenant is fixed at registration.** There is no move:
  delete the device and register it in the other tenant. Its projects
  (which must be deleted first) and imported data stay with the tenant
  they were made in. Log sources the receiver registers on its own land
  in the default tenant.
  *Workaround:* with several tenants, discover new log senders from the
  right tenant's page (+Add Device, log source) before the receiver does.
- **Repairs of the imported data are the device's, not the project's.**
  Resolving two objects that arrived under the same name, and sanitizing a
  group whose members do not exist, fix the import itself: every project of
  that source sees the result. Everything a project does is its own:
  firewall rules, objects, services, groups, schedules, NAT rules, tags and
  the network side (interfaces, zones, routes, virtual routers): deleting
  one hides it in that project while the device keeps it, editing an
  interface's or route's fields applies in that project only, a row added
  in a project exists only there, and the project's Overview lists what it
  deleted and restores it. Renames work the same way (the source name stays
  in the imported data), so two projects of one source may show, generate
  and push different names, and a re-import keeps all of it.
- **Snapshots carry what the project holds.** A restore replaces the
  project's names, its per-rule edits, its deletions, its network field
  edits and the rows it added. What belongs to the device is not part of a
  snapshot and is not brought back by a restore: the repairs above, and the
  deletions an optimization project applies to the box itself (which have
  their own backup step). A snapshot saved before 0.9.3 carries no names: a
  restore of it keeps the project's current names and says so.
- **Host names are unique per installation, across tenants.** A device
  registered in one tenant cannot be registered again in another.
  *Workaround:* move the device (Devices > edit > Tenant). Its projects
  move with it.
- **Log discovery registers devices into the default tenant.** The syslog
  stream is installation-wide and carries no tenant.
  *Workaround:* move discovered devices to their tenant (Devices > edit).
- **A project follows its source's tenant.** Moving a source to another
  tenant takes its projects along. A project whose target stays behind has
  no target on offer until the target is moved too.

## Log sources

- **Log-source devices (OPNsense) push the policy strand out of the box.
  The network strand needs curated addressing.** Traffic logs carry no
  interface addressing, so the network push starts gated (`no_ip`). Add
  interface addresses (and zones) during curation and the network strand
  pushes like any other source. Without them, push the generated policy
  onto a target whose network layout already exists (brownfield), with
  zones pre-provisioned to match the rule zones.
- **A zone the traffic logs recorded is the device's, not the project's.**
  For a log source Gateshift fills a rule's zones from the device's own
  addressing while it builds the ruleset. Re-addressing an interface, or
  adding a route, inside a project changes what that project derives for the
  zones still open and what it pushes, not the zones already recorded from
  the logs.
  *Workaround:* curate the addressing before generating, or clear a rule's
  zone (Target Settings > Zone Mapping) to have the project derive it again.
