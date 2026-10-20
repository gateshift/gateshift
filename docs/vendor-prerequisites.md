# Vendor prerequisites

What to set up on each firewall **before** connecting it. Getting these
wrong produces authentication errors that look like tool bugs: most of the
entries below exist because they cost someone an hour.

Common to all: the appliance's management interface must be reachable from
the host running Gateshift, and self-signed certificates are accepted.

---

## Palo Alto Networks (PAN-OS)

**Credential:** API key.

Generate it yourself, Gateshift never creates credentials:

```
curl -k "https://<fw>/api/?type=keygen&user=<admin>&password=<pw>"
```

Paste the `<key>` value. A common mistake is pasting the admin *password*
into the API-key field. You get HTTP 403 on every call.

**Permissions:** an admin role with XML-API access for config read/write and
operational commands.

**Notes**

- **Nothing is committed.** A push writes the *candidate* configuration. You
  review and commit in the UI. A commit will fail if a prerequisite is
  missing, see SSL decryption below.
- **A push keeps a rescue point.** Before it writes, Gateshift saves the
  candidate on the firewall as `gs-prepush-policy.xml` or
  `gs-prepush-network.xml`, and loads it back if the push breaks off mid-way.
  That is what keeps a network push you have not committed yet when a later
  policy push fails. The file stays on the firewall and the next push of that
  strand overwrites it, because removing a saved configuration needs superuser
  privileges and Gateshift asks only for an API role. You can load it yourself
  under Device > Setup > Operations.
- **After a rescue the firewall wants a full commit.** Loading a configuration
  puts PAN-OS into a state where it refuses partial saves, partial commits and
  the administrator-scoped revert until it has had one full commit. A rescued
  push therefore says so in its log, and a second rescue before that commit
  falls back to reverting the whole candidate.
- **SSL forward proxy** needs a vsys-level forward-trust certificate on
  the target. Certificates are never migrated (no key material leaves the
  source), so provision it before committing, see Palo Alto's decryption
  documentation. Gateshift warns at push time when it is absent.
- **Panorama-managed firewalls** can be connected directly, but you then
  see only the device-local configuration layer. The Panorama itself can be
  discovered here (see Managers below), registering it for the complete
  picture is the Enterprise Edition.
- **VM interfaces**: PAN-OS detects added NICs only at boot.
- Cloud PA-VMs have no aggregate-ethernet support (the hypervisor's NICs
  cannot bond).

---

## FortiGate (FortiOS)

**Credential:** REST API token of a dedicated REST API administrator
(see Fortinet's documentation on REST API administrators).

**Permissions:** a profile with read-write on the objects you migrate.

**Notes**

- **Trusthosts**: an API user usually restricts source IPs. Include the
  address Gateshift connects from, or every call returns HTTP 401.
- **In an HA cluster, whether the API key works on both members is
  FortiOS-version-dependent.** Recent releases (observed on 7.6) sync the
  key with the cluster config. Older releases mint per-member keys that
  the other member rejects. If a member answers HTTP 401, generate the key
  on the *current primary* (`execute api-user generate-key <user>`).
- Pushes go to the **primary**. Gateshift verifies that and refuses a
  subordinate (its configuration database is replica-only).
- FortiGate applies configuration **live** (there is no candidate config),
  but Gateshift never installs or activates anything beyond the objects it
  writes.
- **Physical ports outside the push keep their addresses.** A port the
  configuration does not address stays as it is. If it still carries a
  subnet the push assigns to another port, FortiOS refuses the overlap:
  the Review names the pair and the push dialog offers to reset those
  ports first ("Reset the data ports this push does not address").
  Management and HA ports are never touched by that option.
- **Cloud HA clusters**: if the heartbeat/management ports get their
  addresses from DHCP, give them static per-member addresses first. See
  `KNOWN_LIMITATIONS.md` - a config sync can otherwise propagate the
  primary's addressing to the secondary.
- FortiManager-managed units can be connected directly, but a direct push
  conflicts with the manager's ownership (the next install overwrites it).
  The FortiManager itself can be discovered here (see Managers below),
  registering it is the Enterprise Edition.
- **NGFW policy-based mode**: a FortiGate in policy-based NGFW mode gets
  two layers per rule, a firewall policy for the layer 3/4 match and a
  security policy that carries the applications, users and groups, UTM
  profiles and logging. Gateshift reads the mode from the box and never
  switches it (the switch needs an empty policy set and central NAT, which
  is the operator's step). A push built for the other mode is refused up
  front. Source applications are taken over only where the FortiGuard
  catalog carries an application of the same name (auto-assign in Target
  Settings, Firewall, Applications), the rest stays for you to pick from
  the catalog there, and the push report names what found no match. A
  rule with `application-default` renders service ALL with the
  applications' default ports enforced. As a source, the security
  policies are read as the ruleset (applications by name) and the
  firewall policies are declared as the envelope they run in.
- **Central NAT mode** as a source: each VIP is read as a dest-NAT rule
  (it translates before the policy lookup, no policy names it). A rule
  whose destination is a VIP's mapped address matches after translation
  on FortiOS. PAN-OS, Check Point and a FortiGate in policy-NAT mode
  match before it, so the VIP joins the mapped address as a destination
  on those targets. The import and the Review declare every such rule.

### Reached through FortiGate Cloud

A FortiGate that has no reachable management address can be read
through FortiGate Cloud instead: tick "Reached through FortiGate Cloud"
in the add dialog, choose the region of your FortiGate Cloud account,
enter the IAM API user and load the account's devices to pick the serial
number. Every call Gateshift makes then goes through the cloud's
per-device proxy, nothing connects to the box itself.

**Pushing through the cloud** needs the device's FortiGate Cloud
subscription with Management enabled for the device. Without it the
cloud gives read-only access: imports work, a write (creating, changing
or deleting anything on the box) is answered by the cloud with
"permission_deny", and Gateshift refuses the push up front when the
device's record says management is off. A box without the subscription
is pushed through its management address and an API token instead.

**Credential:** an IAM API user of the FortiCloud account (created in the
IAM portal) whose permission profile grants **Admin on FortiGate
Cloud**. Its id and password take the place of the API token, no REST
API administrator on the box is needed and trusthosts do not apply.

**What the box needs:** it is registered to the same FortiCloud account
and connected to FortiGate Cloud (the management tunnel is up, the
device list shows it online). The free tier is enough, a paid FortiGate
Cloud subscription is not required.

**Network:** outbound HTTPS from Gateshift to the FortiCloud sign-in
service and to the regional FortiGate Cloud API host. The box's own
address is never contacted.

**Notes**

- The IAM API user's password is stored encrypted like every other
  secret, the user id, region and serial number on the device row.
- Proxied calls are slower than direct ones. An import or a push that
  takes seconds against a box on the LAN takes a little longer here, the
  content is the same.

---

## Check Point

**Credential:** Management API key for a **dedicated** API user on the
management server (SmartCenter or MDS), not on the gateway.

**Permissions:** read-write on the relevant policy packages.

**Notes**

- **Publish the API user** after creating it. An unpublished user produces
  a non-JSON error response that reads like a parser failure.
- **The API key must be a generated key**: the account password is not
  accepted. On a SmartCenter the key can only be generated in SmartConsole
  (the `add-api-key` API command is MDS-only). See Check Point's
  documentation on administrators with API-key authentication.
- The **management API server must accept your client IP**: check the
  API server's access settings if logins fail from the Gateshift host.
- Use a dedicated user: Gateshift takes over its own sessions and discards
  them to release object locks. Sharing the account with a human in
  SmartConsole causes lock conflicts.
- **Nothing is published.** A push leaves a session for you to review and
  publish. Policy installation stays manual.
- **Gaia credentials** (username/password of the gateway) are additionally
  required for the network strand: interfaces and routes live in Gaia, not
  in the management API. In a cluster each member is configured through its
  own Gaia session.
- The gateway wizard **pins a policy package** to the device. Import and
  push both use exactly that package. The Review & Deploy tab shows the pin and can
  re-check it against the management server (it updates when the gateway
  was moved to another package in SmartConsole).
- **Smart-1 Cloud** is a hosted management server and takes the same
  path. Enter the tenant's Management API URL as the management address
  (`https://<name>.maas.checkpoint.com/<tenant-id>`, shown in the tenant's
  settings). The tenant id is part of every call, the host alone answers
  nothing. The API key is an administrator's API key created in the
  tenant's SmartConsole, Infinity Portal API keys do not log in to the
  management API. Gateways appear in the wizard once they exist in the
  tenant, a gateway without an installed policy is listed as such. The
  network strand still needs the gateway's own Gaia API, wherever that
  gateway runs.

---

## Cisco FTD (FDM-managed)

**Credential:** FDM admin username and password. FDM has no static API
keys: Gateshift obtains a short-lived token per run.

**Notes**

- **Source only.** FTD can be imported and migrated *from*. There is no
  push target.
- **FDM-managed devices only.** Registering an FTD to an FMC permanently
  disables its local API.
- A factory-fresh device rejects every API call until initial provisioning
  (EULA acceptance) is completed.

---

## Cisco ASA

**No credentials.** ASA is imported by uploading a `show running-config`
dump. It is source-only.

---

## OPNsense

OPNsense is offered in two roles: as a configuration source and as a log
source, and one firewall may hold both at once on a single device row.

### As a configuration source

**No credential.** Export the configuration under *System >
Configuration > Backups*, then add the firewall with *Devices > Add
device > Firewalls and Clusters > OPNsense*. The hostname comes from the
file, so nothing has to be typed.

**Notes**

- **Why a file rather than the API.** The configuration is the only
  complete read of an OPNsense: the firewall API exposes just its own
  ruleset and, in the vendor's words, has "no relation to any of the rules
  being managed via the core system", so an API-only import would miss
  most of a classic policy. Downloading it is also the one large response
  this platform's web server mishandles (see `KNOWN_LIMITATIONS.md`),
  which a browser export sidesteps. A source firewall therefore needs no
  credentials at all.
- **Secrets are never stored.** The configuration carries private keys,
  pre-shared keys and password hashes. They are stripped before anything
  reaches the database.
- **To pick up changes made on the firewall,** upload a fresh export. It
  replaces the stored configuration on the same device row: the device,
  its overrides and its curated edits all survive, and *Import* then
  reads the new one in.
- Interface groups are read as zones. A pf rule binds to a group exactly
  as it binds to an interface, which makes them this platform's zone
  concept rather than a convenience grouping.

### As a log source

**No credentials.** Gateshift generates rule candidates from the
firewall's traffic logs instead of importing a policy: useful when there
is no policy worth migrating, or to see what a ruleset actually carries.

**Setup:** point the firewall's remote logging at the Gateshift host
(UDP port 514) and include the firewall (`filterlog`) application, see
OPNsense's remote-logging documentation. Gateshift's built-in syslog
receiver listens on UDP 514. Alternatively, upload a syslog-format
capture file in the UI (+Add Device > Log Sources > OPNsense > upload) or
copy it into the receiver's log directory (`syslog-ng/logs/`).

**Notes**

- Only rules that **log** produce evidence: enable logging on the rules
  (or the default logging policy) for the traffic you want captured.
- Rule candidates build up from observed flows. Let the receiver collect
  during a representative period (include batch windows, backup schedules
  and month-end jobs, not just a quiet afternoon) before generating.
- Once logs arrive, create the device under +Add Device > Log Sources >
  OPNsense: the dialog lists the senders the receiver has heard
  (the hostname in the syslog header, the address the packets came from,
  a serial where the vendor sends one) and the device is created from the
  sender or senders that are this firewall. Nothing is registered from the
  stream by itself. Devices > Log senders shows what was heard and lets a
  sender be attached to a device later.
- A firewall created this way becomes a configuration source simply by
  being given credentials. It stays one device either way.

---

## Microsoft Azure (source only)

A subscription is read as a migration source: subnets become zones,
network security groups become the ruleset, application security groups
become address groups. Two ways in.

- **Credentials.** An app registration (service principal) with the
  Reader role on the subscription. Gateshift needs its tenant ID, client
  ID and client secret, and the subscription ID. Optionally a list of
  resource groups narrows the read. Reading happens over the Azure
  Resource Manager API, so the Gateshift host needs outbound HTTPS to
  Azure.
- **Bundle upload.** No credentials in Gateshift: one JSON object with the
  keys `virtualNetworks`, `networkSecurityGroups`,
  `applicationSecurityGroups`, `networkInterfaces` and `routeTables`, each
  holding the list the Resource Manager API returns for the subscription
  (the flattened shape the Azure CLI prints for `list` is read as well),
  optionally `ipGroups`, `azureFirewalls` and `firewallPolicies` (each
  policy with its rule collection groups under `ruleCollectionGroups`).
  The upload form offers a collector script that reads all of this with
  the Azure CLI and writes the bundle: run it where the CLI is signed in,
  Azure Cloud Shell is the easiest place, with the Reader role. Re-upload
  to pick up changes.

What is read: VNets and subnets, NSGs with their rules and default rules
and what they are attached to, ASGs and the network interfaces that give
them members, route tables, Azure Firewall policies with their rule
collection groups and the firewalls they are attached to (in a VNet or in
a Virtual WAN hub), IP groups. See KNOWN_LIMITATIONS.md for what the
translation leaves out.

---

## Amazon Web Services (source only)

An account is read as a migration source, region by region: subnets
become zones, security groups and network ACLs become the ruleset,
security groups and managed prefix lists become address groups. Two ways
in.

- **Credentials.** An IAM access key (key ID and secret) of a user or role
  that may read EC2 (the Describe calls for VPCs, subnets, route tables,
  security groups, network ACLs, network interfaces and managed prefix
  lists), the caller identity, and, where Network Firewall is in use, its
  List and Describe calls for firewalls, firewall policies and rule
  groups. Gateshift needs the key ID, the regions to read
  (comma-separated) and the secret. Optionally a list of VPC IDs narrows
  the read. Temporary credentials (session tokens) are not stored, use
  the bundle upload for those. Reading happens over the EC2, STS and
  Network Firewall APIs, so the Gateshift host needs outbound HTTPS to
  their regional endpoints.
- **Bundle upload.** No credentials in Gateshift: one JSON object with the
  keys `Vpcs`, `Subnets`, `RouteTables`, `SecurityGroups`, `NetworkAcls`
  and `NetworkInterfaces`, each holding the list the matching describe
  command of the AWS CLI prints, optionally `PrefixLists` and
  `PrefixListEntries` (prefix list ID to its entries), and for Network
  Firewall `NetworkFirewalls`, `NetworkFirewallPolicies` and
  `NetworkFirewallRuleGroups`, each holding the describe outputs
  (describe-firewall, describe-firewall-policy, describe-rule-group) as
  the CLI prints them. Several regions are concatenated into the same
  lists. The upload form offers a collector script that reads all of
  this with the AWS CLI and writes the bundle: run it where the CLI is
  signed in, AWS CloudShell is the easiest place, with read access only.
  Re-upload to pick up changes.

What is read: VPCs and subnets, security groups with their inbound and
outbound rules, network ACLs with their entries and associations, the
network interfaces that give the groups members, managed prefix lists a
rule references, route tables, Network Firewalls with their policies and
rule groups. See KNOWN_LIMITATIONS.md for what the translation leaves out.

---

## Google Cloud (source only)

A project is read as a migration source: subnetworks become zones, VPC
firewall rules and network firewall policies become the ruleset, network
tags, service accounts, secure tags and address groups become address
groups. Two ways in.

- **Credentials.** A service account with read access to the project's
  networks, subnetworks, firewall rules, network firewall policies,
  instances and routes (the Compute Engine API must be enabled in the
  project), plus, when policies use them, the address groups of the
  Network Security API and the instances' effective secure tags (the Tag
  Viewer role on the project). Gateshift takes the JSON key file whole,
  pasted into the key field. Optionally a
  list of networks narrows the read. Reading happens over Google's REST
  endpoints, so the Gateshift host needs outbound HTTPS to them.
- **Bundle upload.** No credentials in Gateshift: one JSON object with the
  keys `networks`, `subnetworks`, `firewalls`, `networkFirewallPolicies`,
  `instances` and `routes`, optionally `firewallPolicies` (hierarchical
  policies as `get-effective-firewalls` reports them), `addressGroups` and
  `instanceTags` (instance to its effective secure tags), each holding
  the list the matching gcloud list command prints as JSON. The upload
  form offers a collector script that reads all of this with gcloud and
  writes the bundle: run it where gcloud is signed in, Google Cloud Shell
  is the easiest place, with read access only. Re-upload to pick up
  changes.

What is read: networks and subnetworks, VPC firewall rules, global and
regional network firewall policies with their associations, hierarchical
policies as each network sees them, instances for tag and service-account
membership, routes, address groups. See KNOWN_LIMITATIONS.md for what the
translation leaves out.

---

## Managers (discovery)

The Community Edition reads a central manager and shows its scopes with
their counts (device groups, templates, ADOMs, policy packages, domains,
folders, and the managed firewalls) through the add dialog's "Manager
(discovery)" entries. Nothing is stored: the credentials travel in that
one request. Importing, curating and pushing a manager's scopes is the
Enterprise Edition.

What the discovery needs:

- **Panorama**: the address and an API key of an administrator with read
  access (the same key form as a PAN-OS firewall).
- **FortiManager**: the address and the API token of an API user with
  `rpc-permit read` (FortiManager 7.2 or later with the JSON-RPC API
  enabled).
- **FortiManager Cloud**: the instance name
  (`<customer id>.<region>.fortimanager.forticloud.com`) and a FortiCloud
  IAM API user with its password. Built against the vendor's documentation,
  see the verification status in KNOWN_LIMITATIONS.md.
- **Check Point management**: the management address, or the Smart-1 Cloud
  tenant URL (`https://<name>.maas.checkpoint.com/<tenant-id>`), and an
  administrator's API key created in SmartConsole. A SmartCenter is read as
  one context, a Multi-Domain server per domain (the first 50).
- **Strata Cloud Manager**: the tenant service group id (TSG id) and a
  service account's client id and secret from the tenant's identity and
  access settings. Built against the vendor's documentation, see the
  verification status in KNOWN_LIMITATIONS.md.

---

## Quick check

If a connection fails, the message usually names the cause. The three that
look most like tool bugs:

| Symptom | Cause |
|---|---|
| PAN-OS: HTTP 403 on everything | the API-key field holds a password, or the key was revoked |
| FortiOS: HTTP 401 on everything | trusthost doesn't cover this host, the API user's access profile lacks the object category, or the key belongs to the other cluster member. Repeated 401s can then trip FortiOS admin-lockout, which makes *all* calls 401 until it clears - wait it out rather than retrying into it. |
| Check Point: "Expecting value: line 1 column 1" | the API user isn't published, or the API server rejects this client IP |
