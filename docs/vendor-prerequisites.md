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
- **SSL forward proxy** needs a vsys-level forward-trust certificate on
  the target. Certificates are never migrated (no key material leaves the
  source), so provision it before committing, see Palo Alto's decryption
  documentation. Gateshift warns at push time when it is absent.
- **Panorama-managed firewalls** can be connected directly, but you then
  see only the device-local configuration layer. Register the Panorama for
  the complete picture (Enterprise).
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
- **Cloud HA clusters**: if the heartbeat/management ports get their
  addresses from DHCP, give them static per-member addresses first. See
  `KNOWN_LIMITATIONS.md` - a config sync can otherwise propagate the
  primary's addressing to the secondary.
- FortiManager-managed units can be connected directly, but a direct push
  conflicts with the manager's ownership (the next install overwrites it).

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
device > OPNsense (configuration upload)*. The hostname comes from the
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

### As a migration target

Not offered. The push driver exists and is tested, but OPNsense is not
currently selectable as a target: it needs a prerequisite no other target
has (a VLAN or tunnel must be assigned an interface by hand before a rule or
an interface group may name it, and that step has no API), and whether the
role is published is still open.

### As a log source

**No credentials.** Gateshift generates rule candidates from the
firewall's traffic logs instead of importing a policy: useful when there
is no policy worth migrating, or to see what a ruleset actually carries.

**Setup:** point the firewall's remote logging at the Gateshift host
(UDP port 514) and include the firewall (`filterlog`) application, see
OPNsense's remote-logging documentation. Gateshift's built-in syslog
receiver listens on UDP 514. Alternatively, upload a syslog-format
capture file in the UI (Projects & Devices > +Add Device > Log source) or copy it
into the receiver's log directory (`syslog-ng/logs/`).

**Notes**

- Only rules that **log** produce evidence: enable logging on the rules
  (or the default logging policy) for the traffic you want captured.
- Rule candidates build up from observed flows. Let the receiver collect
  during a representative period (include batch windows, backup schedules
  and month-end jobs, not just a quiet afternoon) before generating.
- Once logs arrive, register the device via *Discover from Logs* on the
  Devices tab: it is picked up from the log stream, not entered manually.
- A firewall discovered this way becomes a configuration source simply by
  being given credentials. It stays one device either way.

---

## Quick check

If a connection fails, the message usually names the cause. The three that
look most like tool bugs:

| Symptom | Cause |
|---|---|
| PAN-OS: HTTP 403 on everything | the API-key field holds a password, or the key was revoked |
| FortiOS: HTTP 401 on everything | trusthost doesn't cover this host, the API user's access profile lacks the object category, or the key belongs to the other cluster member. Repeated 401s can then trip FortiOS admin-lockout, which makes *all* calls 401 until it clears - wait it out rather than retrying into it. |
| Check Point: "Expecting value: line 1 column 1" | the API user isn't published, or the API server rejects this client IP |
