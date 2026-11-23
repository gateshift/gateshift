# Changelog

All notable changes to Gateshift, newest first. This file covers the current
major version. It ships with every release and is the source of the release
notes.

## 0.9.6 (2026-11-23)

**Added**

- **An MCP server at the installation's own endpoint**: an AI client connects to `https://<gateshift>/mcp` with a token, nothing is installed beside the client, and no tool pushes, publishes or discards.
- The MCP server's edit_interface takes type, parent, VLAN tag and addresses.
- The MCP server retries a call once when the installation closed the connection between two calls.
- `GATESHIFT_MCP_READ_ONLY=1` in `.env` offers an AI client the reading tools only.
- **An automation API at `/api/v1`** with its own document: Devices, projects, interfaces, zones, rules, findings and jobs, the review stamp, the build, push, publish and discard as jobs, the last three for a token of scope `full`, every write audited under its token.
- **The Automation page** under Manage carries the API, the MCP endpoint, where an AI client's data goes, and the API tokens with scope and expiry, the Add API Token dialog says what each scope allows.
- **The network strand, the NAT rules and the snapshots through the API and the MCP server**: interfaces, routes, zones, virtual routers and NAT rules added, edited and deleted in a project, snapshots taken and restored, and through the API also deleted and branched.
- A re-import keeps the NAT rules a project added, in their order behind the imported ones.
- **The curation through the API and the MCP server**: objects listed with lint flags, renamed, left out and merged, the rules' fields, names and order, the target's stored catalogues and the automatic application assignment.
- A naming workbench in the API and the MCP server renames a selection of objects or rules by a scheme with variables or an explicit map, planned as a whole first.
- A rule's name and its position are the project's decisions and survive refreshes and re-imports.
- Editing a rule's zones, service, applications, profiles, logging or track marks the policy strand outdated on the Review & Deploy page.
- The pickers of Profiles & Settings read the target's stored catalogue and work offline.
- The Applications pane of a PAN-OS target and a policy-based FortiGate offers a search over the target's application catalogue.
- A pre-shared key is checked against the target's rule when it is saved.
- A browser without JavaScript is told so at the top of every page.
- docs/install.md carries the command that sets the admin password anew.

**Changed**

- The claim under the wordmark reads Migrate & optimize firewalls.
- The install check after a Check Point policy push names both rules of a conflict.
- Network > Interfaces re-renders its rows after an edit instead of reloading the page.
- The hint on the Review & Deploy button offers the PAN-OS fallback ruleset as an option for the transition instead of telling every push to append it.

**Fixed**

- Restoring a project's Original snapshot takes the names back too.
- The FortiGate policy-NAT fold sets NAT on every outbound policy of a source NAT that matches every source, keeps a renamed rule's flag and never lands on an unrendered default rule.
- A re-import removes the exclusions of items the import no longer carries and names them in the log.
- A FortiGate network push releases the interfaces an earlier push's zones hold before it writes the new zones.
- A FortiGate push clears every kind of its strand, also a kind the new configuration has none of.
- A NAT rule with an IPv4-only or IPv6-only catch-all side reaches a Check Point target instead of being dropped.
- A static route whose egress interface the FortiGate target lacks is pushed over its gateway's interface or declared, instead of stopping the push.
- A stored pre-shared key the target refuses stops the network push before its first write and shows as a Review finding.
- A first start on a fresh database no longer prints failures about the deploy settings table.
- The completeness check of a manager's policy scope knows its paired network scope.
- A Check Point network push to a standalone gateway refreshes the gateway object's interfaces and binds the project's zones to them.
- A Check Point network push writes both address families and the declared admin state of every physical interface.
- A FortiOS network push writes both address families of every interface it declares.
- A `GATESHIFT_SECRET_KEY` that is no Fernet key stops the start with one sentence instead of storing credentials in clear text.
- A target read the driver does not offer answers with one sentence instead of a Python error.
- The Threat Prevention apply's catalogue reads report a refused key or an unreachable box like every other read.
- The Check Point push stages in a session of its own and logs out after Publish or Discard.
- A route's network is stored as the CIDR in one form, so two routes of one network with different lengths are two rows.
- The Review names a physical interface the PAN-OS or FortiOS target does not have as a blocker, and a dotted PAN-OS name on a target port passes as the sub-interface it becomes.
- A PAN-OS network push with no interface to push leaves the interface skeleton in place.
- An addition that collides with another project's row says so.
- A skipped VLAN or bond member and an excluded NAT rule reference nothing, so the parent, bond or interface they name can be skipped too.
- The Review's interface type checks pass a skipped interface.
- The Firepower (FDM) reader imports a port FDM leaves unnamed under VLAN sub-interfaces, and reads NAT on any-ipv4 and any-ipv6 as any4 and any6.
- Another project's additions on a shared Device no longer read as deleted, as a leak or as a dangling reference in this project.
- A Check Point cluster is registered through its first member's Gaia, and its IPv6 preflight no longer stops the member route push.
- An import stores the connected routes of its interfaces right away.
- The FortiOS import keeps a customer's own wildcard FQDN address.
- The Review names forward-proxy decryption rules on a PAN-OS firewall without a forward-trust certificate as a blocker, the certificate read from the vsys or the shared settings.
- The build's leak check reads only the Devices it renders.
- The PAN-OS rollback point check reads an unreachable firewall as unknown.
- A Check Point network push releases an address that moves from a port to a VLAN, a bond or a loopback.
- The project dashboard's step "Target inventory fetched" no longer counts a catalogue read as the fetch.
- `install.sh --renew-cert` restarts the web server, so the renewed certificate is served right away.
- `install.sh` stops on an existing `.env` whose `GATESHIFT_SECRET_KEY` is no Fernet key and says how to replace it.

**Updating from 0.9.5**

- Dump your database before updating, and see the Updating section of docs/install.md for the standing guidance and the dump command.
- The first start adds the tables of the API tokens, the audit and the rules' names and order, rewrites the stored routes to the one form and seeds the connected routes of every import, which takes a moment.
- A target configuration built by 0.9.5 stays as it is until its next build.
- A `GATESHIFT_SECRET_KEY` that is set but no Fernet key now stops the start: the key `install.sh` writes is valid, a hand-written `.env` may carry an invalid one.

## 0.9.5 (2026-11-16)

**Added**

- **The operator's path through a project**: the path judges every step from what
  Gateshift holds (Devices and project, source imported, target inventory fetched,
  zones and interfaces mapped, every section the project carries, the blocking
  findings of the current build with the place that fixes each, then reviewed,
  pushed, verified).
- A section counts as gone through once it was opened after the import.
- A step you do not want to take can be skipped with the x beside the next-step
  sentence or in the path dialog, and resumed there.
- The next-step box counts the skipped steps as long as there are any.
- The page head names the first open step in a box of its own with a link to the
  place that completes it, and the light bulb in that box opens the path dialog.
- The navigation marks done entries with a check and the next one with an arrow
  and the light bulb, its branch stays open and the entry pulses when the next
  step moves.
- The path dialog lists the steps with their evidence and offers Mark Verified
  after the push.
- The project list shows status, last activity and snapshots.
- A build after a push no longer steps the status back, a rebuild reopens review,
  push and verification.
- The add dialog links the platform's prerequisites.
- **Hit counts from the Device**: the import reads the firewall's own rule
  counters where the vendor offers them (PAN-OS security and NAT rules, FortiOS
  policies, Check Point access rules for the pinned gateway, cluster or virtual
  system, Management Center and Device Manager access rules, OPNsense pf
  counters) and keeps them beside the usage derived from logs, never mixed.
- Policies > Security shows them as Box hits and Last hit with a usage filter the
  bulk actions work on.
- "Read hit counts" on the Dashboard reads them again without a re-import.
- The Review names the rules without a hit on the Device, and a source whose
  counters are not read says why.
- The push never sees the counters and nothing is ever reset on the Device.
- On FortiOS the implicit deny carries the Device's counter too, and the
  since-date is the policy's creation time.
- On OPNsense an uploaded configuration that is not the Device's current one gets
  no counters, and the import says so.
- **Cisco Secure Firewall Management Center as a source** (on-premises FMC and
  the cloud-delivered one in Security Cloud Control): the Management Center
  registers through the add dialog's Manager group and is imported as a whole,
  its domains, access policies and devices (standalone or HA pair) as scopes a
  project picks as its source.
- Each access policy is read as the FTD evaluates it (prefilter, base policies,
  own rules, default action), NAT follows the device, literals become objects,
  what is left out is declared.
- The two discovery entries read a Management Center without storing anything.
- **A manager's scopes as project sources** in the project wizard, and a
  read-only scope page for a manager row.
- **Virtual instances as scopes**: a FortiGate in multi-VDOM mode, a PAN-OS
  firewall with several vsys and a Check Point VSX gateway are imported as one
  scope per instance under the Device, each a source and a target of its own.
- A Check Point virtual system takes the policy strand into its package, its
  network is provisioned on the VSX and declared on the deploy page.
- The Device row becomes the container, a single-instance Device is unchanged.
- The Check Point wizard accepts a VSX gateway or cluster, and the domain of a
  Multi-Domain management.

**Changed**

- **Navigation and texts**: the tree reads by the operator's questions in the
  words of firewall menus.
- Projects and Devices are the global entries (the Devices page is the tenant's
  inventory, the project picker sits under them).
- A project's tree is Dashboard, Network (Interfaces, Routing, Zones, Policy
  Routing, VPN), Policies (Security, NAT, Decryption, Threat Prevention),
  Objects, Profiles & Settings, Review & Deploy and Logs, without a Configure
  group.
- Profiles & Settings and Review & Deploy stay visible when locked and say why,
  groups are folded unless the view is inside them, and the active path reads in
  brighter bold type.
- The panel's type is one grid: one size, the two weights the typeface carries,
  the picker, Collapse, version and Logout on the text column.
- The navigation runs the full height of the window with the brand at its top,
  and the pages with the tree have no header bar (the next step sits in a box of
  its own beside the page title, a manager's scope pickers on the row below).
- The navigation is three menus with quiet headings in their lines (Manage:
  Projects and Devices, Active Project: the picker, Migrate & Optimize: the
  project's tree), stacked in the middle of the column.
- The branch that was Target Settings reads Profiles & Settings.
- Every view opens with a light bulb that says what you can do there, and the
  browser tab names the view and the project.
- The empty states and the remedies name the places that exist today, browser
  prompts gave way to the product's dialogs, and the terminology follows the
  standard (ruleset, Policy Routing, Profiles & Settings, Device).
- **Shorter view hints, Device throughout**: every hint of the workspace reads in
  one pattern with button names in quotes, and the registered row is the Device
  in every text, the rules table (Device hits), the review notes and the push
  messages included.
- **The first page is the page of the next step**: after the setup and after a
  login without a destination the operator lands on Devices until a source and
  a target Device are registered, then on Projects.
- The next-step chain counts Devices: register the source, register the target
  (or create an optimization project on the one), create the first project.
- The Manage entry of that page carries the arrow and the light bulb of the next
  step, like a step of the tree.
- **The path recommends every target feature**: Profiles & Settings is no longer
  one step, each of its views (security or UTM profiles, applications, logging,
  schedules, source users, tags) and the Target Settings of NAT and Policy
  Routing is a recommended step of its own where the target has the view and
  the project carries something for it, with its marker in the tree.
- The path dialog labels the recommended steps, the three the path needs stand
  out.
- **The zone bindings want one look**: when the target uses zones, the path
  carries a step of its own after Routing until Network > Zones was looked
  at, and the Network menu lists Routing before Zones: the derived zones and
  the rule mapping follow the routes.
- **NAT and Policy Routing settings sit with their rulesets**: Policies > NAT and
  Network > Policy Routing switch between Rules and Target Settings, Profiles &
  Settings holds what gets attached to firewall rules.
- **Toasts are opaque with a signal bar at the left**, a failure stays until it
  is closed and a warning holds eight seconds, the messages were transparent,
  grey and gone after three and a half seconds.
- **Project names read as a sentence**: the wizard suggests "<source> to <target>
  migration" and "<Device> optimization".
- **Tenants step back until there is a second one**: the landing shows no
  tenant row while only the default tenant exists.
- With a second tenant a picker sits in the navigation, the tenants are managed
  in one dialog behind the Tenants button of the Devices page (add, rename,
  delete when empty, switch), and a Device no project binds may move to another
  tenant from its edit dialog.
- **The Devices page shows Devices**: the Log Senders button and the count of
  unattributed senders left it.
- What the syslog receiver heard is listed at /devices/senders, the add dialog's
  "from the log stream" entry and the capture upload stay as they were.
- **Every manager has its entry in Add Device**: the Manager group lists Panorama,
  FortiManager, FortiManager Cloud, Check Point, Strata Cloud Manager and the
  Cisco Management Center, the firewall entries keep only the toggles that say
  how the firewall is reached or pushed.
- **Add Device asks for the API key**: the key (or the platform's password) is
  required for every platform that is read through its API, the add refuses an
  empty one, and the dialog keeps only its labels, the Prerequisites link carries
  the explanations.
- **Check Point Security Gateway**: the gateway entry carries Check Point's name
  and its wizard keeps only its labels.
- **The add dialog names the Check Point entries by what manages the Device**: the
  gateway entry reads SmartCenter or Smart-1 Cloud managed, and the management
  entries read SmartCenter, Smart-1 Cloud or MDS, the registering one in its own
  Manager group in the Enterprise Edition and the discovery one as before.
- The README is a landing page again: the vendor matrix moved to
  docs/support-matrix.md, the installation, TLS, update and first-project
  details to docs/install.md, and both files ship with the release.

**Fixed**

- **A catalogue read no longer holds the whole app**: reading a target's
  profiles, applications or logging profiles, the Check Point layers and
  categories, a target fetch, a hit-count read, a build, an import, the add and
  edit of a Device and the Check Point wizard made every other request of every
  browser wait, up to a minute for a PAN-OS App-ID catalogue.
- **A browser reload returns to the view it was made in**, a reload on
  Network > Zones or any other sub view landed on the first leaf of its branch.
- With a FortiGate target the Profiles & Settings branch opened without a hint
  and without the marked path after a reload.
- **A FortiGate dropping one read no longer fails the snapshot refresh**:
  FortiOS 7.6.7 and later rate-limit the admin HTTP interface per client and
  reset a connection over the limit, so the refresh reads one catalogue after
  the other and retries a connection the Device dropped.
- A FortiGate that is not reachable still fails the refresh at once.
- **A FortiOS push to a box that does not answer fails at once and says so**, it
  retried every call for up to four minutes, silently, step after step.
- The retry stays for a FortiGate that answers and drops the connection.
- **FortiOS push keeps the management route ahead**: a default route from a
  source whose metric is an administrative distance (a Management Center
  route carries 1) outranked the DHCP default route of the FortiGate's
  management port and took the replies with it.
- The network push reads the Device's active routing table and raises such a
  default route to the management route's distance plus one, with a step that
  says so.
- **FortiOS policy-NAT fold resolves address groups**: a source-NAT intent on a
  group member (a Management Center auto-NAT per network object) folds onto the
  outbound policy that names the group, instead of staying declared as "no
  matching outbound policy".
- **A Check Point policy push wipes the NAT rulebase also when the source
  carries no NAT**, so the NAT rules of an earlier push no longer survive such
  a project.
- **Check Point identities survive an unreadable role list**: when the target's
  access roles cannot be read, the push keeps the rules' identities and says so,
  instead of dropping every one of them.
- **A missing threat prevention layer is a warning, not a refusal**: the banner
  says the push skips the layer, and the push step says so with what to do.
- A Check Point fetch whose Gaia login fails says so with a warning, the
  interface list came back short without a word.
- A Device edit that the Gaia login probe refuses returns to the Devices page
  with one sentence, it landed on the project list.
- **A route PAN-OS cannot bind counts as a route in the Review**: a static route
  that names an interface of another virtual router and whose next hop is not
  on-link there is left out, declared and filed under routes, it counted against
  interfaces and left the routes row one short.
- A PAN-OS build declares a route without a next hop whose interface is not
  bound in the virtual router, it was left out of the configuration without a
  word.
- The PAN-OS address, service and zone-protection catalogues report a refused
  key or a box that does not answer as the failure it is, they answered
  "0 entries fetched".
- **A rule with application-default and no application the target can resolve**
  went out matching every service with nothing said, it is declared now and
  blocks the push of an allow rule until its service mode is set to any or the
  rule is excluded.
- **A rule whose applications resolved only in part** was declared as replaced
  by Any while it went out narrower than the source.
- **The target configuration lists its objects in name order**, so two builds of
  the same project read the same (a re-import or the objects made from literals
  could shuffle them).
- **NAT edits are the project's**: the rename, the description, the enable state
  and the target fields of an imported NAT rule live in the project like every
  other edit, survive a re-import and stay invisible to the Device's other
  projects.
- **Schedule Clear goes back to the import**: Clear gives the rule its imported
  schedule again, and the picker offers "none" for a rule that should run
  always.
- **The decryption rule's certificate field is gone**, no push read it, the
  forward-trust certificate is a setting of the firewall.
- Setting an interface address in a project no longer adds the imported
  connected networks a second time as the project's own routes.
- A route to a network the interface carries counts as connected whatever form
  its prefix is stored in, so the build no longer pushes it as a static route.
- A project whose target could not be read says so: the "Target inventory
  fetched" step reopens with the reason and the Review carries it as a warning.
- A refused API key or a box that does not answer reads as one sentence on the
  import, the network fetch and the target snapshot, instead of the raw HTTP
  error once per catalogue.
- A push step that fails on the connection or on a refused key says so in one
  sentence, and the Logs show that sentence as the job's summary.
- A catalogue read of a box that does not answer says "device unreachable"
  instead of the raw connection error, and the message names the catalogue.
- The Review's note on a FortiGate whose NAT mode could not be read is a
  sentence, it was a log line.
- The busy dialog closes when the last call holding it is done, a catalogue read
  that finished behind the applications auto-assign closed that dialog after
  three seconds while the match still ran.
- Opening the rules of a source that was never generated starts the generate
  run, and another source's run no longer masks it.
- The button of that run says Generate.
- The rule generation runs in the configured database, it used the default one
  and ignored DB_NAME.
- The rules page lists the instances of a Device (a VDOM, a vsys, a virtual
  system) as targets, a project whose target is an instance opened with the
  first plain target of the tenant instead.
- Adding or importing a Device from the Devices page returns to the Devices page,
  not to the project list.
- An import started on the project's Dashboard that fails shows its error on the
  project page, the page showed only "Nothing read from this Device yet".
- Deleting a Device that projects use returns to the Devices page with the
  refusal.
- A configuration file that is no ASA configuration returns to the page the
  wizard was opened from with one sentence.
- Rename, Add and Delete Tenant show their dialog above the Tenants dialog, not
  behind it.
- A FortiGate is reached one way: FortiGate Cloud and FortiManager exclude each
  other in Add Device, a form carrying both is refused instead of keeping only
  the cloud part.
- **Log senders: the Detach button did nothing** when the sender's name carried
  a double quote, it asks for confirmation again.
- **Updating from 0.9.2 or 0.9.3 in one step starts**, the first start on a
  database that had skipped 0.9.4 refused and kept the application from
  starting.
- The two tables of the step model were silently missing on such a database,
  they are created in the right order now.
- The release check boots the current version on an old database before every
  release candidate.
- The Check Point push log names the objects it created under a new name
  because the management already holds the name for another object type, with
  the names the rules of that push reference.

**Updating from 0.9.4**

- Dump your database before updating, and see the Updating section of
  docs/install.md for the standing guidance and the dump command.
- The first start after the update adds the tables and columns of the step
  model, the review, push and verification stamps and the hit counts, which
  takes a moment.
- Projects pushed before this version carry no push stamp and show that step
  open until their next push.
- A target configuration built by 0.9.4 stays as it is, the Review says which
  version built it, and the next build replaces it.

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
- **VPN**: a push whose tunnels reference a pre-shared key the Device holds
  under a tunnel name a rename or re-import left behind went out with a
  placeholder and a tunnel that never came up. The push is refused and the
  VPN view lists those keys for discarding, and a tunnel whose key was never
  entered goes out with the placeholder as before, named in the push record.
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
