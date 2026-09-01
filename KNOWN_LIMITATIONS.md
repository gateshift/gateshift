# Known Limitations

Deliberate scope boundaries of the current release. Each entry states the limit,
the behavior you will see, and the workaround where one exists. None of these
fail silently - where a limit applies, Gateshift blocks or warns explicitly.

## Network / routing

- **Check Point network push is single routing-table (V1).** Gaia supports native
  VRF since R81.20, but Gateshift's CP network renderer targets one routing table.
  A source with multiple virtual routers is **hard-blocked** by validation
  (`cp_multi_vr`) instead of silently collapsing the VRs.
  *Workaround:* migrate one VR at a time.
- **IPv6 is not migrated.** IPv6 objects, rules and routes are dropped with a
  warning at import.
- **Dynamic routing (BGP/OSPF) is not migrated.** Static routes and PA
  logical-router (ARE) configs are; routing-protocol config is not.
- **Bond modes / m:1 bonds, bridge/L2 interfaces, ECMP**: not migrated.

## Migration scope

- **Captive Portal / identity redirect policies** are not migrated.
  User/group *references* on rules migrate (vendor-native); portal
  configuration (authentication rulebases, portal settings, auth profiles)
  does not - it depends on local identity infrastructure and is set up
  fresh on the target.
- **Check Point certificate-based VPN (ICA-issued certs)** as target: PSK and
  third-party cert auth migrate; ICA enrollment does not.
  *Workaround:* complete cert enrollment in SmartConsole after the push.
- **Cisco ASA is source-only** (config-file import; no push target).
- **Cisco FTD is source-only, FDM-managed boxes only.** Standalone FTDs are
  imported live via the on-box FDM REST API (admin credentials); there is no
  FTD push target. FMC-managed estates cannot be read this way - registering
  an FTD to an FMC permanently disables its FDM API.

## Vendor-specific behavior

- **Panorama-managed PAN-OS / FortiManager-managed FortiGate direct imports** see only the
  device-local config layer (PA) or risk push conflicts with the manager
  (FortiGate). Gateshift detects this and warns (amber "managed" chip); register
  the manager for the full picture.
- **FortiGate policy-held objects survive network wipes by design** - Gateshift
  never auto-deletes user firewall policies. Push the policy strand first, then
  the network strand (the push error hints say exactly this when it applies).
- **Cloud HA clusters with DHCP-addressed heartbeat/management ports**: a
  network push never modifies the HA-reserved interfaces, but the config sync
  it triggers can propagate the primary's addressing onto the secondary -
  both members then hold the same heartbeat address and the cluster goes
  split-brain (observed on an AWS FortiGate FGCP pair). Gateshift warns before such a
  push. Give the members static per-member addresses on the heartbeat and
  management ports, and check HA health after pushing.
- **Check Point cluster targets get no new interfaces.** A push onto a
  ClusterXL target stages interface VIPs onto the cluster's *existing*
  interfaces by name match and pushes routes per member via Gaia; source
  interfaces the cluster does not already have - including VLAN
  sub-interfaces - are skipped with a warning (the cluster infrastructure
  stays operator-managed; standalone CP gateways do get VLAN sub-interfaces
  created).
  *Workaround:* create the interfaces on the cluster first (members in Gaia +
  cluster topology in SmartConsole), then use "Fetch target interfaces" in
  Gateshift and map or rename the source interfaces to the cluster's names.
- **Check Point VPN toward Palo Alto targets migrates policy-shaped.** A
  Check Point source models S2S VPN as communities (policy-based); on a
  PAN-OS target this renders as IKE gateways + IPSec tunnels with
  proxy-IDs from the encryption domains. Two parts stay with the
  operator for now: tunnel interfaces (tunnel.N) are not synthesized -
  create and bind them on the target (until then the IKE gateway's
  local-address fails validation); and long community+peer composite
  names can exceed PAN-OS name limits on some VPN entities - rename on
  the source or target where the commit complains. Crypto profiles
  without source lifetimes get PAN-OS defaults (IKE 8h, IPSec 1h).
- **Check Point cluster targets keep their existing VPN domain.** The
  Check Point Management API silently ignores VPN-domain changes on an
  existing cluster object (the set call reports success but changes
  nothing - name and uid form alike, observed on R81.x / API 1.9), so a
  VPN push onto a ClusterXL target cannot switch the cluster's local
  encryption domain. Peer devices, encryption-domain groups and
  communities are created normally.
  *Workaround:* set the cluster's VPN domain once in SmartConsole
  (Gateways & Servers - cluster - Network Management - VPN Domain);
  everything else about the VPN push works unattended.
- **Check Point HTTPS-inspection "predefined" rules migrate even when the
  source blade is off.** A CP source ships a predefined HTTPS-inspection
  rule; Gateshift imports it and renders it as an active decryption rule on
  the target - regardless of whether HTTPS inspection was enabled on the
  source. The migration can thus produce decryption behavior the source
  never had. Predefined content is shown, not hard-filtered (you decide
  what migrates).
  *Workaround:* review the decryption rulebase on the target before
  committing and soft-delete rules you do not want (Enrichment >
  Decryption). Forward-proxy also needs a target-side trust certificate
  anyway (see Palo Alto prerequisites), so a decryption review is expected.
- **Check Point Threat Prevention** pushes as a separate rulebase with CP's own
  semantics (single scope, no service column); blade-dependent track levels are
  downgraded automatically where a target layer lacks the blade.

## Cross-vendor NAT

- **Cisco FTD NAT rules carry interface references, not zones** (an FDM
  modeling quirk). On a PAN-OS target those references do not resolve into
  NAT zones yet, and the NAT push step fails - which stops the policy strand
  before the access rules.
  *Workaround:* deselect the **NAT Rules** section in the push dialog and
  build the NAT policy on the target; the access rules then push cleanly.

## Rulebase installation

- **Check Point refuses to install shadowed rules ("Rule X conflicts with
  Rule Y").** Policy verification rejects a rulebase in which an earlier,
  broader rule makes later rules unreachable - PAN-OS and FortiOS install
  such rulebases silently. This surfaces on migrations whose source
  legitimately contains dead rules: an ASA config concatenates per-interface
  ACLs into one flat rulebase (each ACL's broad permits and deny-all tails
  then shadow the following ACL blocks), and shadowed entries are faithful
  imports - they were equally dead on the source.
  *Workaround:* disable the flagged rules in the Ruleset (they are
  unreachable by definition, so this does not change effective behavior
  within their own block) and push again; verification may report further
  pairs in a second round. Review cross-ACL fall-through afterwards - with
  a per-interface deny-all disabled, traffic can reach the following
  block's rules on the flat rulebase.

## Rules referencing skipped resources

- **FortiGate target: a zone whose member interfaces are all
  deploy-skipped is dropped from the push, but rules referencing that
  zone are still emitted** and fail on the box (error -651) - typical for
  ASA sources with ACLs on tunnel interfaces (ASA VPN is not parsed, so
  the tunnel interface can never exist on the target).
  *Workaround:* push the network strand, then create the zone empty on
  the FortiGate (a zone without interfaces is valid), then push the
  policy strand. Creating it before the network push does not work - the
  push wipes it again.
- **Interface names are pushed as-is.** A source interface name that is
  invalid on the target platform (for example `eth0` pushed to PAN-OS)
  fails the interface push step. Rename source interfaces to target-valid
  names during curation ("Fetch target interfaces" offers the target's
  names), or skip interfaces that should not migrate - the reference
  guard walks you through what still depends on them.

## Source modeling gaps

- **FTD VLAN subinterfaces reference their parent by FDM hardware name**
  (for example `TenGigabitEthernet0/3`), and unnamed parent ports are not
  imported as interface rows - so the parent cannot be renamed, and the
  literal hardware name fails on FortiGate (name length) and Check Point
  (invalid interface) targets.
  *Workaround:* set the subinterface's type to `physical` in
  Network > Interfaces - it then deploys as a plain L3 interface (verified
  end-to-end).
- **IKE crypto proposals migrate literally.** Verify DH-group
  compatibility per IKE version on the target: PAN-OS, for example,
  rejects DH group21 on an IKEv1 gateway. Adjust the profile on the
  target before committing where validation complains.

## Log sources

- **Log-source devices (OPNsense) push the policy strand out of the box;
  the network strand needs curated addressing.** Traffic logs carry no
  interface addressing, so the network push starts gated (`no_ip`). Add
  interface addresses (and zones) during curation and the network strand
  pushes like any other source; without them, push the generated policy
  onto a target whose network layout already exists (brownfield), with
  zones pre-provisioned to match the rule zones.
