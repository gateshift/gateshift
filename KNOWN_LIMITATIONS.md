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
  certificate from your own CA in `certs/` (docs/install.md, TLS). The
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
- **Shadowing reports full coverage only**, where an earlier, always-active
  rule covers a later rule's whole match space, and follows the selected
  target's match semantics (Check Point access layers are zoneless). A
  partial overlap is legal on every platform and is not reported, which is
  where a Check Point target's own verification goes further.
- **What the analysis cannot judge it counts instead of clearing.** A rule
  whose addresses or services do not resolve, or that carries a negation,
  gets no verdict, and their number is named next to the filter so silence
  is not read as a clean bill.
- **A rule's applications narrow it only where the target matches them.**
  The analysis follows the target: on Palo Alto Networks and a FortiGate in
  policy-based mode a rule with applications covers nothing wider than them,
  on Check Point only a bound App-Site narrows and the source's applications
  do not, on a FortiGate in profile-based mode none do. A source whose rules
  all take their service from an application the table does not know still
  yields no verdict for them, as the service cannot be resolved.

## Network / routing

- **Check Point network push is single routing-table.** Gaia supports native
  VRF since R81.20, but Gateshift's CP network renderer targets one routing table.
  A source with multiple virtual routers is **hard-blocked** by validation
  (`cp_multi_vr`) instead of silently collapsing the VRs.
  *Workaround:* migrate one VR at a time.
- **IPv6 is carried in the model and declared where a target does not
  write it.** Dual-stack support is in this version.
  What is in place: an address object holds both
  families (a Check Point dual-stack host, network or range arrives
  whole), the rules view and the zone derivation take IPv6 addresses, and
  an IPv6 literal in a rule becomes an address object like an IPv4 one.
  Check Point targets write IPv6 and dual-stack objects as the management
  holds them, PAN-OS targets write IPv6 objects natively and a dual-stack
  object as its two halves under a group of the source's name, and
  FortiOS targets write IPv6 objects and groups into their own namespaces
  (`address6`, `addrgrp6`) with one policy carrying both families. All
  three targets write IPv6 interface addresses and IPv6 static routes
  (Check Point through the gateway's command line, because its REST API
  has no IPv6 route command, and only while IPv6 is enabled on the
  gateway). What is not written is declared on the build: IPv6 NAT
  (NAT66, NPTv6, FortiOS `vip6` and `ippool6`), an IPv6 blackhole route on
  Check Point, a rule whose sources and destinations are of different
  families (no packet matches it on any vendor), and the IPv6 side of a
  FortiOS policy that carries per-policy NAT (FortiOS needs an IPv6 pool
  for that: the IPv4 side keeps its NAT and the IPv6 side is left off, a
  policy of IPv6 alone keeps its addresses and loses the NAT flag). A rule of one family
  (a FortiOS or OPNsense rule, an ASA `any4`, a cloud rule with
  `0.0.0.0/0` alone) keeps that family: PAN-OS and Check Point targets get
  a catch-all object of the family (`any-ipv4`, `All_Internet`,
  `any-ipv6`), declared on the build. VPN tunnels take an IPv6 peer and
  IPv6 selectors on all three vendors (a FortiGate or PAN-OS tunnel
  negotiates over one family, a Check Point peer object carries both
  addresses). The traffic-log aggregation stays IPv4. Where a declaration
  says so, configure the IPv6 part on the target yourself.
- **An IPv6 management address is refused.** Devices are reached over IPv4
  or by host name in this version. A management address that is an IPv6
  literal is refused with a sentence before anything is sent, on every
  vendor, instead of being parsed into a wrong host.
- **Dynamic routing (BGP/OSPF) is not migrated.** Static routes and PA
  logical-router (ARE) configs are. Routing-protocol config is not.
- **Bond modes / m:1 bonds, bridge/L2 interfaces, ECMP**: not migrated.
- **Static routes with an off-link next hop and no interface are left
  out of PA and FortiGate pushes.** A route whose gateway sits in no
  subnet of the pushed interfaces (Gaia statics via a VPN peer address,
  for example) cannot be resolved by PAN-OS (the candidate fails
  validation) or FortiOS (`device` is mandatory). Both targets omit the
  route with a declared drop. A Check Point target takes it as a Gaia
  static and declares it too: Gaia accepts the route and leaves it
  inactive until the gateway becomes reachable, for example once the VPN
  tunnel of the same migration is up. On a FortiGate target a route whose
  interface the project does not push (a skipped one, for example) goes
  over the interface its gateway sits on, or is left out when the gateway
  sits on no pushed interface, each declared in the Review.
  *Workaround:* Network > Routing marks such a route with "no egress" and
  names the gateway. Bind an egress interface there and it renders on
  every target.

## Migration scope

- **Captive Portal / identity redirect policies** are not migrated.
  User/group *references* on rules migrate (vendor-native). Portal
  configuration (authentication rulesets, portal settings, auth profiles)
  does not: it depends on local identity infrastructure and is set up
  fresh on the target.
- **Check Point certificate-based VPN (ICA-issued certs)** as target: PSK and
  third-party cert auth migrate. ICA enrollment does not.
  *Workaround:* complete cert enrollment in SmartConsole after the push.
- **Cisco ASA is source-only** (config-file import, no push target).
- **OPNsense 26.7 truncates any HTTP/1.1 response at 64 KiB.** A larger
  reply stops mid-document, the same reply over HTTP/2 arrives intact.
  Gateshift reads the API over HTTP/1.1 and the browser speaks HTTP/2,
  which is why an OPNsense is added from an **exported configuration**
  rather than over the API. Where the API is used anyway, a Device
  registered with credentials only, Gateshift parses what it receives and
  **refuses the import** of a damaged download rather than migrating a
  policy with holes in it.
  *Workaround:* upload the exported configuration.
- **Cisco FTD is source-only.** A standalone FTD is imported live through
  its on-box FDM REST API (admin credentials). An FTD managed by a Secure
  Firewall Management Center is imported through the Management Center,
  which registers as a manager and fans into domain, access-policy and
  device scopes (an HA pair is one device scope, read through its primary,
  a cluster's members are read as devices). There is no FTD or FMC push
  target. What the Management Center import leaves out is declared in the
  import log: MONITOR rules, the prefilter's ANALYZE and tunnel rules,
  VLAN tags, security group tags, dynamic objects, URL conditions,
  application filters and the inspection policies on rules, bridge groups,
  redundant and switch-port interfaces, and object overrides (the base
  value is imported, the override count is declared).
- **Virtual instances are scopes, never created.** A FortiGate in multi-VDOM
  mode, a PAN-OS firewall with several vsys and a Check Point VSX gateway are
  imported as one scope per instance under the box. A push lands inside one
  instance and never creates, deletes or re-homes an instance or moves a port
  between instances. The operator assigns ports to instances on the box. A
  push into a Check Point virtual system carries the policy strand only
  (objects, rules, NAT, Threat Prevention and decryption rules into its
  package): its interfaces, VLANs and routes are provisioned on the VSX, the
  management API of R81.20 carries no provisioning command, so the network
  strand is declared on the deploy page and never pushed. Not migrated: inter-VDOM links,
  PAN-OS external zones, transparent-mode VDOMs (listed and skipped), and the
  static routes of a Check Point virtual system (the Gaia API of R81.20
  carries no virtual system context), and the network of a virtual system
  beyond what its management object answers.
- **Managers are discovered, not migrated, in the Community Edition.**
  Panorama, FortiManager and FortiManager Cloud, a Check Point Multi-Domain
  server and Strata Cloud Manager connect through the add dialog's "Manager
  (Discovery)" entries, which show the scopes with their counts and store
  nothing. Importing, curating and pushing those scopes is the Enterprise
  Edition. A SmartCenter is migrated one gateway at a time through the
  Check Point gateway entry, the discovery shows the management as a whole.
  The exception is the Cisco Secure Firewall Management Center: the
  Community Edition imports it in full, since Cisco is a source only.
- **Cloud accounts are source-only: Microsoft Azure, AWS and
  Google Cloud.** An account is read as a firewall would be, with these
  translations and limits. Subnets are the zones and become interfaces
  without an address (the target's interface addressing is the operator's).
  Containers (security groups, application security groups, prefix lists,
  tags, service accounts, address groups) become address groups whose
  members are the private addresses found at import time: a snapshot,
  re-import to refresh it. Every address a rule names directly (a CIDR, a
  host) becomes an address object named after it, and every service a
  rule names as protocol and port becomes a service object, so the
  ruleset reads as objects and groups like any other source. Each route table (Google: each VPC network) is
  a virtual router, only routes with an IP next hop migrate. IPv6
  prefixes, routes and rule sides are read like IPv4 ones, and a
  dual-stack subnet's IPv6 block places IPv6 rule sides in its zone.
  - *Azure*: network security groups become the ruleset, one rule per NSG
    rule, the attached subnets as the rule's zone, plus the six default
    rules of every NSG marked as defaults. Service tags with an address
    form resolve (VirtualNetwork, AzureLoadBalancer, Internet), any other
    tag leaves its rule imported but disabled with the reason. Azure
    Firewall policies (and the rule collections of a firewall without a
    policy) are read in front of the NSG rules in Azure's order: DNAT,
    network, application, parent policy before child. DNAT rules become
    destination NAT rules plus the allow Azure adds for the translated
    traffic. Application rules keep their FQDN targets as FQDN objects
    (wildcards declared) and Http, Https and Mssql as TCP ports, while
    FQDN tags, web categories, target URLs and TLS termination are
    declared, a rule with nothing else is imported disabled. The
    firewall's implicit deny is imported disabled, because only traffic
    routed through the firewall is subject to it. IP groups become
    address groups. A firewall in a Virtual WAN hub is read through its
    policy the same way and its rules are marked with the hub firewall's
    name. A firewall whose policy lies outside the read subscription is
    declared, its rules are not read.
  - *AWS*: security-group rules become the ruleset (allow only, closed by
    one implicit deny marked as a default). Network ACLs are stateless and
    only a necessary condition beside the groups, so their explicit deny
    entries are imported as active rules at the top of the ruleset while
    their allow entries, including the ephemeral return-traffic ranges,
    are imported disabled with the reason. A group or prefix list a rule
    references but the read did not contain (another account, a peered
    VPC, an unread region) becomes an empty address group. Routes to an
    internet, NAT, transit or peering gateway are declared, not migrated.
    AWS Network Firewall is read in front of the network ACLs, per
    firewall: its policy's stateless rules by priority (pass allows, drop
    denies, forward_to_sfe decides nothing and imports disabled), then the
    stateful rule groups in the policy's order (strict order as listed, the
    default action order sorted pass, drop and reject, alert): 5-tuple
    rules with pass and drop, reject as a deny declared, alert imported
    disabled, application-layer protocols declared, IP set variables and
    reference sets as address groups, domain lists as FQDN objects (the
    allow list's drop of every other host imported disabled), Suricata
    rule strings as one disabled placeholder per group with the count. The
    stateless and stateful default actions are marked default rules.
  - *Google Cloud*: VPC firewall rules and network firewall policies
    (hierarchical as the network sees them, global, regional) become one
    ruleset in the network's enforcement order. The implied allow-egress
    is expressed as "from the subnets to anything outside them" with a
    negated destination, because inside the VPC the destination's ingress
    rules still decide, and the implied deny-ingress closes the ruleset. A
    rule that applies a security profile group is imported as an allow
    with the inspection declared, goto_next rules and rules matching only
    on region codes or threat intelligence are imported disabled. Secure
    tags resolve through the instances' effective tags when the service
    account may read them. Cloud NGFW features beyond that are not read.
    An auto-mode network (a project's `default` network) carries a subnet
    in every region. Only the regional subnets with an instance in them
    are read, the empty ones are counted, and an auto-mode network left
    without subnets is counted with its rules.

## Vendor-specific behavior

- **Panorama-managed PAN-OS / FortiManager-managed FortiGate direct imports** see only the
  device-local config layer (PA) or risk push conflicts with the manager
  (FortiGate). Gateshift detects this and warns (amber "managed" chip). Register
  the manager for the full picture.
- **A Panorama scope renamed on the Panorama itself is a new Device to
  Gateshift.** PAN-OS gives a device group, a template or a template stack
  no id of its own, so a Panorama scope is matched across imports by its
  name: after a rename made in the Panorama UI, the next import removes the
  old scope with its edits and creates a new one. FortiManager, Check Point
  and Strata Cloud Manager scopes carry the manager's id and keep their
  Device across a rename.
  *Workaround:* rename a Panorama scope from its manager page in Gateshift,
  which renames it on the Panorama and keeps the Device.
- **FortiGate policy-held objects survive a network push by design.** The
  network push never deletes a firewall policy, so an interface or tunnel a
  policy still references stays on the box. The policy strand replaces the
  policies, as every push replaces the target within its scope. Push the
  policy strand first, then the network strand (the push error hints say
  exactly this when it applies).
- **A FortiGate in profile-based mode takes no per-policy application or
  URL-category match.** FortiOS in its default profile-based mode matches
  applications and URL categories through profiles attached to the policy
  (application control, web filter), not on the policy itself. Application
  and URL-category matches of a Palo Alto or Check Point source are declared
  in the review and not pushed there. Attach the profiles under Profiles &
  Settings > UTM Profiles. Custom URL categories are pushed as URL filter
  tables for that purpose. A FortiGate in NGFW policy-based mode carries the
  applications on its security policies: Gateshift reads the mode from the
  box, never switches it, and refuses a build made for the other mode (see
  docs/vendor-prerequisites.md, FortiGate).
- **FortiGuard factory objects are recognized by name.** A FortiOS import
  leaves out the address objects FortiOS ships (the `all` and `none`
  sentinels and the FortiGuard objects such as `wildcard.google.com`) and
  names them in the import log. FortiOS marks none of them read-only, so
  the name decides: a customer object that carries a factory name is left
  out as factory too.
  *Workaround:* rename such an object on the source before the import.
- **A wildcard FQDN does not reach a PAN-OS target.** An address object
  with a wildcard FQDN (`*.example.com`, as FortiOS carries them) is
  imported like any other object. PAN-OS FQDN objects take no wildcard, so
  a PAN-OS target leaves the object out and declares it, a group loses it
  as a member, and a rule side that names only that object is a blocker in
  the Review (an unresolved reference, the side would match any).
- **Cloud HA clusters with DHCP-addressed heartbeat/management ports**: a
  network push never modifies the HA-reserved interfaces, but the config sync
  it triggers can propagate the primary's addressing onto the secondary.
  Both members then hold the same heartbeat address and the cluster goes
  split-brain. Gateshift warns before such a push. Give the members static
  per-member addresses on the heartbeat and management ports, and check HA
  health after pushing.
- **Check Point object names are unique across all object types.** A pushed
  host, network, group or service whose name the management already holds
  for an object of another type (a security zone of the same name, a
  predefined service) is created as `FF_<name>`, and every rule of that push
  references the new name. The push log names each renamed object. The
  review shows the source name.
- **Check Point cluster targets get no new interfaces.** A push onto a
  ClusterXL target stages interface VIPs onto the cluster's *existing*
  interfaces by name match and pushes routes per member via Gaia. The VIPs
  it stages are IPv4 only: an IPv6 address of a source interface gets no
  cluster VIP, add it on the cluster object in SmartConsole. Source
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
  *Workaround:* pick the interface per tunnel under Network > VPN ("set
  local IF") and regenerate.
- **Check Point cluster targets keep their existing VPN domain.** The
  Check Point Management API silently ignores VPN-domain changes on an
  existing cluster object (the set call reports success but changes
  nothing, by name and by uid alike, on R81.x with API 1.9), so a
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
  committing and soft-delete rules you do not want (Policies >
  Decryption). Forward-proxy also needs a forward-trust certificate on
  the target (see Palo Alto prerequisites), and the Review blocks the
  policy push while it is missing, so a decryption review is expected.
- **Check Point's Internet object and "HTTPS default services" become any
  on a PAN-OS target.** Neither has a PAN-OS equivalent. A security or
  decryption rule that names Internet gets any on that side (the direction
  stays with the rule's zones), and a decryption rule that names "HTTPS
  default services" gets the service any. The Review declares each. The
  predefined HTTPS-inspection rule (destination Internet, services "HTTPS
  default services") therefore reaches a PAN-OS target with any for both
  and decrypts more than the source did.
- **A Check Point push replaces the rulebases and sets objects by name.**
  The access layer, NAT and the Gateshift rulebases of the pinned package are
  wiped and rewritten on every push. Hosts, networks, services and groups
  are created or updated by name, never removed: objects an earlier push
  from another source created in the same domain stay on the management.
  Remove them in SmartConsole when a target changes its source.
- **A Check Point cluster push leaves the cluster object's member interfaces as
  they were.** On a standalone gateway the network push refreshes the gateway
  object from the gateway after the Gaia writes (the management's Get
  Interfaces with topology) and binds the project's zones to its interfaces,
  which needs SIC and the right to edit the gateway object (see
  docs/vendor-prerequisites.md, Check Point).
  On a cluster the push stages the cluster interface VIPs and leaves the member
  interfaces, topology and zone bindings to the operator.
  *Workaround:* run "Get Interfaces" with topology on the cluster object in
  SmartConsole after the network push, then install the policy.
- **Check Point Threat Prevention** pushes as a separate rulebase with CP's own
  semantics (single scope, no service column). Blade-dependent track levels are
  downgraded automatically where a target layer lacks the blade.

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
  *Mitigation (built in):* the Policies > Security view has a "Shadowed"
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

## Target interfaces

- **A physical interface the target does not have blocks the network
  push.** No push creates a physical port. A source interface whose name
  the target lacks (for example `eth0` pushed to PAN-OS) is a blocker in
  the Review: on PAN-OS and FortiOS once the target's interfaces were
  fetched ("Fetch Target Interfaces"), on Check Point when the gateway's
  Gaia API answers. Without that read there is no finding and the push is
  the gate. Rename source interfaces to the target's names during
  curation, make one a VLAN on a port, or skip interfaces that should not
  migrate: the reference guard walks you through what still depends on
  them.

## Source modeling gaps

- **A Management Center VLAN subinterface on an unnamed port references
  its parent by hardware name** (for example `TenGigabitEthernet0/3`). The
  Management Center import leaves an unnamed port out (declared in the
  import log), so the parent is no interface row and cannot be renamed. A
  Check Point target blocks the subinterface in the Review (its parent is
  not in the source's interfaces), on a FortiGate target the literal
  hardware name fails (name length). An FDM import brings such a port in
  under its hardware name, ready to be mapped.
  *Workaround:* set the subinterface's type to `physical` in
  Network > Interfaces: it then deploys as a plain L3 interface.
- **IKE crypto proposals migrate literally.** Verify DH-group
  compatibility per IKE version on the target: PAN-OS, for example,
  rejects DH group21 on an IKEv1 gateway. Adjust the profile on the
  target before committing where validation complains.

## Hit counts from the box

The box's own rule counters are read beside the rules and shown as Device
hits and Last hit in the ruleset. They are a decision aid: the
push never sees them, the Quality Filter keeps judging from logs, and
nothing is excluded by a counter.

- **Not read, declared instead:** the Cisco ASA file import, the cloud
  sources (their APIs carry no per-rule counters), NAT rules on FortiOS
  and on Check Point (the management API refuses hits on the NAT
  rulebase), a Management Center policy assigned to no device or to
  several (counters are per device and are never summed), an OPNsense
  Device with an uploaded configuration and no API key or whose upload is
  not the box's current configuration (pf keys its counters by the box's
  rule ids), a Check Point row
  without a pinned gateway, and the scopes of a central manager (Panorama,
  FortiManager, MDS). The import results and the Review carry the reason.
- **Pairs and clusters:** a PAN-OS or FortiOS pair answers for the
  registered member only, a Check Point cluster for the cluster object, a
  Management Center HA pair for its primary, an OPNsense CARP pair for the
  node whose address is registered (pf counters are not synchronised
  between the nodes, a virtual address answers for the current master).
  The other member's counters are not read.
- **What the counter means is the vendor's:** PAN-OS and Check Point count
  sessions that matched the rule, FortiOS counts policy hits, the
  Management Center and the Device Manager count rule hits as fetched
  from the device, OPNsense answers pf's packets matched by the rule
  since the last ruleset load, without a first or last hit. The since-date
  is the last reset or the rule's creation on PAN-OS, the policy's creation
  on FortiOS (a cleared counter keeps its creation time) and unknown
  elsewhere. Nothing is normalised across vendors.
- **A rule the box lists no counter for** stays empty (the usage filter's
  "not read"): vendor default rules PAN-OS does not count, the
  Management Center's default action, rules synthesised by the import, and
  disabled policies on FortiOS (the box keeps no counter for them).

## Projects and tenants

- **A Device moves to another tenant only while no project binds it.**
  With a second tenant its edit dialog offers the move. A Device in a
  project stays in its tenant, so its projects stay too, and a manager's
  scopes move with the manager, never alone. A Device created from the
  log stream joins the tenant of the page it was created from. The log
  senders themselves belong to no tenant.
- **Repairs of the imported data are the Device's, not the project's.**
  Resolving two objects that arrived under the same name, and sanitizing a
  group whose members do not exist, fix the import itself: every project of
  that source sees the result. Everything a project does is its own:
  firewall rules, objects, services, groups, schedules, NAT rules, tags and
  the network side (interfaces, zones, routes, virtual routers): deleting
  one hides it in that project while the Device keeps it, editing an
  interface's or route's fields applies in that project only, a row added
  in a project exists only there, and the project's Dashboard lists what it
  deleted and restores it. Renames work the same way (the source name stays
  in the imported data), so two projects of one source may show, generate
  and push different names, and a re-import keeps all of it.
- **Snapshots carry what the project holds.** A restore replaces the
  project's names, its per-rule edits, its deletions, its network field
  edits and the rows it added. What belongs to the Device is not part of a
  snapshot and is not brought back by a restore: the repairs above, and the
  deletions an optimization project applies to the box itself (which have
  their own backup step). A snapshot saved before 0.9.3 carries no names: a
  restore of it keeps the project's current names and says so.

## Log sources

- **Log-source Devices (OPNsense) push the policy strand out of the box.
  The network strand needs curated addressing.** Traffic logs carry no
  interface addressing, so the network push starts gated (`no_ip`). Add
  interface addresses (and zones) during curation and the network strand
  pushes like any other source. Without them, push the generated policy
  onto a target whose network layout already exists (brownfield), with
  zones pre-provisioned to match the rule zones.
- **A zone the traffic logs recorded is the Device's, not the project's.**
  For a log source Gateshift fills a rule's zones from the Device's own
  addressing while it builds the ruleset. Re-addressing an interface, or
  adding a route, inside a project changes what that project derives for the
  zones still open and what it pushes, not the zones already recorded from
  the logs.
  *Workaround:* curate the addressing before generating, or clear a rule's
  zone (Network > Zones) to have the project derive it again.
- **OPNsense is the only log-stream source in this version.** The add
  dialog offers no other vendor's traffic logs. The receiver still records
  FortiGate and Check Point senders, and the Log Senders page at
  /devices/senders shows them.
