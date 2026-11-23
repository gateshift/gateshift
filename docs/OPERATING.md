# Operating Gateshift

How a migration runs, what the tool guarantees, and how to read what it
tells you. Set up Device access first, see `vendor-prerequisites.md`.

## Installing

```
cp .env.example .env      # then fill it in
./make-cert.sh            # self-signed TLS certificate under certs/
docker compose up -d      # UI on https://<this host>/
```

`./install.sh` does all three. The UI listens on every address: HTTPS on
443, HTTP on 80 only redirects there. `WEBUI_BIND=<address>` in `.env`
restricts it to one interface. The automation API (`/api/v1`) and the MCP
endpoint (`/mcp`) are served on the same port as the pages. The syslog
receiver listens on UDP 514 on every address, and `SYSLOG_BIND=<address>`
restricts it.

## Updating

```
git pull
docker compose up -d --build
```

The `--build` matters. The code of both images, the SQL jobs included, is
built into them, so `docker compose up -d` after a pull keeps the old code
running. Dump the database first (`install.md` has the dump and the restore
commands): there is no guaranteed migration path between releases before
1.0, and a re-import from the sources is the supported fallback.

`DB_ROOT_PASSWORD` and `DB_PASSWORD` have no defaults and the stack will not
start without them. A shipped default would be the same password on every
installation in the world, guarding a database that holds credentials for
your firewalls. Root is for administration. The application itself connects
as the unprivileged account, which holds rights on its own schema and nothing
else.

**Set `GATESHIFT_SECRET_KEY`.** `install.sh` writes one into the `.env` it
generates. It encrypts the stored Device credentials (API keys, Gaia
passwords), the VPN pre-shared keys and the keys of uploaded VPN
certificates. Without it the tool still works, but the Device credentials
sit in the database in clear text, and pre-shared keys and certificate keys
cannot be stored at all. Keep a copy of the key somewhere safe and back up
`.env`: losing or rotating it makes the stored credentials undecryptable,
and every Device's credentials have to be entered again. Gateshift says so plainly when it happens rather than
failing as a vendor authentication error. The value must be a Fernet key (32
random bytes as url-safe base64, 44 characters):
`openssl rand 32 | base64 | tr '+/' '-_'` makes one. A value that is set but
is no such key stops the start, because the alternative would be clear-text
storage behind a key you believe is in place. The installer refuses such a
key in an existing `.env`. A `.env` written by hand may still carry one, and
the web container's log then names the reason (`docker compose logs webapp`).

Credentials stored in clear text before the key was set stay readable and
are encrypted the next time they are written: enter them again in the
Device's Details dialog to encrypt them right away.

Two things worth knowing before you put this on a shared host:

- **The UI has a login and TLS, but the certificate is self-signed.** The
  browser warns about the unknown issuer until you replace the two files
  under `certs/` with a certificate from your own CA (see Access). A
  management network you would trust with firewall credentials is still
  the place for it.
- **The web container mounts the host's Docker socket.** It needs it to run
  the ruleset pipeline, which every import and every build goes through, and
  the syslog flow discovery, both in the python sidecar. The access it grants
  is root-equivalent on the host. Run the stack on a host you would trust
  with firewall credentials anyway.

The first start pulls the MariaDB and syslog-ng images and builds the two
others, which downloads a Python base image, Debian packages, Python
packages from PyPI and the Tailwind CLI from GitHub. Every update with
`--build` needs the same access again for whatever changed. In an
air-gapped management network, the normal case for this tool, build the
images where there is egress, or provide a proxy.

## Access

The UI has one account, `admin`. On the first visit of a fresh
installation the setup page asks for its password (at least 10
characters). From then on every page and every request needs a login.
A session lasts 12 hours of use. "Logout" at the foot of the navigation
ends it. After five wrong passwords in a row the next attempts wait a
growing number of seconds (up to 30).

A forgotten password is set anew from the server, without touching the
data:

```
docker compose exec webapp python reset_admin.py
```

The command prompts for the new password. `--password '...'` passes it
for scripts.

**TLS.** The web container serves HTTPS itself, with no proxy in front of
it, from `certs/gateshift.crt` and `certs/gateshift.key`, which it reads
when it starts. `make-cert.sh` (run by `install.sh`) writes a self-signed
pair valid for 825 days, with `localhost` and the host's names and
addresses in it. `./install.sh --renew-cert` writes a new one when names
change or it runs out, and restarts the web container.
`./make-cert.sh --force` writes one as well and leaves the restart to you
(`docker compose restart webapp`). The browser warns about the unknown
issuer once per browser. A certificate from your own CA ends that: put its
certificate (with the chain) and key into the two files and run
`docker compose restart webapp`. Plain HTTP on port 80 answers every
request with a redirect to HTTPS and serves nothing else. HSTS is not set,
so a replaced certificate never locks a browser out.

A program reaches Gateshift through the automation API at `/api/v1` with a
token a signed-in user creates on the Automation page (`/automation`, under
Manage in the navigation). The token is shown once and can be revoked
there. A token has a scope (`read`, `project` for the writes of a project,
`full` for everything), may expire, and may be bound to one tenant. A
`project` token curates and builds but cannot push: pushing, publishing and
discarding need `full`. docs/API.md describes the calls. `/api/v1/docs`
carries the generated document (your sign-in or a token opens it). Its page
loads its scripts from a public CDN and stays blank in a browser without
internet access, while `/api/v1/openapi.json` serves the document itself.
The Automation page also names the MCP endpoint for an AI client, says
where a client's data goes, and lists every write that came through the API
or the MCP server under its token's name, with the reason the program gave.

An AI client of your choice can operate Gateshift through the installation's
MCP endpoint, `/mcp` on the same address as the pages (docs/MCP.md). The
client is given the URL and a token of scope `project`. Nothing is installed
beside it. The agent reads and curates a project on its own word, builds,
and asks you in the client before it marks a build reviewed or restores a
snapshot. It cannot push: the MCP server has no push tool, and a `project`
token is refused a push. The push stays yours, on the Review & Deploy page,
or through the API with a token of scope `full`. A reverse proxy in front of
Gateshift has to pass server-sent events through unbuffered for that
endpoint. A restart of Gateshift drops the clients' sessions, and they
connect again.

## The safety model

Read this before the first push.

- **Gateshift never activates configuration.** PAN-OS receives a *candidate*
  config you commit yourself. Check Point receives the policy as a session
  you publish yourself, and policy installation stays manual. FortiGate
  applies objects live because FortiOS has no candidate concept, and the
  Check Point network strand writes interfaces and routes through Gaia,
  which applies them at once. Nothing is installed or enabled beyond what
  was written.
- **A push replaces the target within its scope**, it does not merge. The
  sections you push are wiped and rebuilt from the source. Sections you opt
  out of are left alone.
- **A failed push is taken back where the vendor allows it.** PAN-OS saves a
  rescue point of the candidate before the push writes and loads it back
  when a step fails, so the candidate is as it was before the push. When
  the firewall refuses to save one, the push dialog warns before anything
  is written: commit on the firewall and push again, or continue without a
  rollback point. Check Point stages the policy in a session of its own and
  discards it when a step fails, so the management is untouched by the
  failed push. FortiGate and the Check Point network strand keep what
  already went out, because every write there is live.
- **Secrets are never migrated.** VPN pre-shared keys are pushed as
  placeholders, or injected from Gateshift's own encrypted store when you
  saved one. A source's certificate is referenced by name only, and no key
  material is read from the source. A certificate tunnel to a PAN-OS or FortiGate
  target can carry an identity certificate you upload with its key on the
  VPN page: the key is stored encrypted, and the push imports both onto the
  target.
- **Nothing is silently lost.** Anything the target cannot represent shows
  up as a drop with a reason before you push.

## Terms

- **Device** is anything registered in the inventory: a firewall, a
  configuration file, a log source or (Enterprise) a manager. A project's
  two ends are its **source Device** and its **target Device**. An
  optimization has one Device.
- **Firewall rule** is a rule of the main ruleset, whatever the vendor
  calls it (security rule, access rule, policy). NAT rules, decryption
  rules, policy routing rules and threat prevention rules are named by
  their kind.
- **Ruleset** means all rules of one kind on a Device or in a project. The
  generated ruleset is what Review & Deploy pushes. "Rulebase" appears only
  where a Check Point concept is meant.
- **Project** is a source Device, a target Device and every edit made for
  that pair: renames, zone bindings, rule settings, disabled rules.
- **Tenant** is an estate: the Devices and projects that belong together.
- **Snapshot** is a project's edits frozen at a moment.

## The workflow

**Projects and tenants.** A project is one migration: a source, a target,
and every edit made for that pair (zone assignments, application and
profile choices, disabled rules, NAT, policy routing, decryption and VPN
edits, threat-prevention layers and deploy settings). Projects are the
entry point. The navigation's first menu, Manage, holds Devices (the
tenant's Device inventory), Projects (the list of projects, and the way
back to it from any project) and Automation (the API, the MCP endpoint and
their tokens). With two or more tenants a Tenant menu follows on these
pages and picks the estate they show. The Active Project menu is the picker
that switches to another project of any tenant. "+Add Project" on the
Projects page asks for a source and a target: pick the source, then either
keep the Device itself as the target (an optimization: it is curated and
pushed back to itself) or pick another target (a migration). Devices are
registered on the Devices page. A pair may carry several projects. The
header of the workspace shows which one you are in, its Dashboard (the
first view, where a project opens) shows the two Devices with what
Gateshift holds of each and the project's snapshots, and the Logs view
lists every job of the project. The last menu, Migrate & Optimize, reads
top to bottom as the way through a project: Dashboard, Network, Policies,
Objects, Profiles & Settings (what the target needs beyond the source,
called Target Settings until 0.9.4), Review & Deploy, Logs. Snapshots
freeze a project's edits. "Original" is the empty set every project starts
from, and a saved snapshot can be restored (replacing the current edits)
or branched into a new project. Tenants keep estates apart: Devices and
projects belong to one tenant, and a source is only offered targets of its
own tenant. Names are edits too: an interface, zone, VRF, object or service
renamed in a project keeps its source name in the imported data and is
shown, generated and pushed under the project's name. So two projects of
one source may name things differently, a re-import keeps the names, and a
snapshot carries them. The Dashboard lists them and lets you drop one.
Deleting, editing and adding belong to the project as well: a firewall
rule, object or network row deleted in a project leaves that project's view
while the Device keeps it, the fields of an interface or route edited in a
project apply only there, and a row added in a project exists only in it.
The Dashboard lists what the project deleted and restores it, and a
snapshot carries all of it. What stays with the Device is the repair of
imported data, such as two objects that arrived under the same name (see
KNOWN_LIMITATIONS.md).

**Where you stand.** Every project is judged against the same path from
what Gateshift holds: Devices and project, source imported, target
inventory fetched, zones and interfaces mapped, then the sections the
project carries (routes, policy routing, VPN tunnels and their secrets,
firewall rules, NAT, decryption, threat prevention, objects, Profiles &
Settings), then the blocking findings of the current build, each with the
place that fixes it, then reviewed, pushed, verified and activated. A
section counts as gone through once you opened it after the import. A
section the project carries nothing for is left out, and the VPN step
stays open while a tunnel misses its pre-shared key or certificate. A step
you do not want to take (a key you set on the target yourself) can be
skipped with Skip beside the header sentence or in the path dialog: the
path moves on, the dialog offers to resume it, and a step that is done is
done whatever was skipped. The page head (the row at the top of the page
with the title) names the first open step in one sentence in a box of its
own and links to the place that completes it. The light bulb in that box
opens the path dialog with every step, its evidence, Skip, Resume and Mark
Verified, and as long as a step is skipped the box counts it with a link
into the dialog. A skip holds until you resume the step, even when its
finding changes. The navigation marks the entries whose step is done (a
check) or recommended next (an arrow and the light bulb, the entry pulses
once the next step moves), and the project list shows the status that
follows from them: draft, curated with the first edit, generated with a
build, pushed, verified by you. A step the pair does not need (the network
of a Check Point virtual system, the target fetch of an optimization) says
so instead of waiting. "Reviewed" means the findings of the current build
were on the Review & Deploy page, or a program marked the build reviewed
through the API (an AI client asks you in the client first). "Pushed" means
that every strand of the current build went out, and "verified" is your
word, given with Mark Verified in the path dialog (the light bulb at the
top of the page) after you checked the result on the target. A rebuild
reopens the last three. The add dialog links the platform's prerequisites.

**1. Connect the Device.** Platform, management address, credentials.
The role (source, target, or both) decides where it appears later. The
Device joins the tenant shown on the Devices page, the inventory.
"+Add Device" registers one, and each row carries Import (Re-import once
data is there), Details (the Device's dialog: credentials, notes, platform
settings), Reset (wipes what was collected, the registration stays) and
Delete. A Device no project uses can move to another tenant in its Details
dialog, which offers the tenant once a second one exists. Its imported data
moves with it. A Device that projects use stays in its tenant and cannot be
deleted: delete those projects first. A Device created from the log stream
(its platform's "from the log stream" entry in the add dialog, which lists
the senders the receiver has heard) joins the tenant shown. The receiver
registers nothing on its own: a sender no Device is attached to is listed
on the Log Senders page at /devices/senders, which has no button in this
version.

**2. Import.** Reads the policy (rules, objects, groups, services, NAT,
and whatever else the vendor exposes) and, in the same run, the network
side (step 3). A re-import replaces the previous import and keeps the
project's edits. They are keyed to rule content, not to names, so a rule
changed on the Device arrives as a new rule, without the edits of the old
one. The project's rule names and rule order stay, and so do its
additions, NAT rules included. What the project deleted and the import no
longer carries is cleared from the project, and the import's log names it.
An import stores the connected routes of the Device's interfaces right away.

The import also reads the Device's own rule counters where the vendor
offers them: PAN-OS security and NAT rules, FortiOS policies, Check Point
access rules for the pinned gateway, cluster or virtual system, Management
Center access and prefilter rules of a policy assigned to one device,
Device Manager access rules, and OPNsense pf counters through the API.
They show under Policies > Security as Device hits and Last hit, beside the
Hits and Last seen derived from logs, with the read time and the vendor's
since-date as the tooltip, and a usage filter (no Device hits, no hit for
30, 90 or 180 days, not read) the bulk actions work on. "Read hit counts"
on the Dashboard's source card reads them again without a re-import.
Review & Deploy names how many rules saw no hit on the Device, and a source
whose counters were not read says why there and in the import results (a
file import, a cloud source, a policy assigned to several devices, a failed
read). The counters change nothing in what is pushed, the Quality Filter
keeps judging from logs, and Gateshift never resets a counter.

**3. Collect.** The network side (interfaces, zones, routes, VRFs, VPN) is
read by the import itself, right after the policy, so the UI has no
separate action for it. `vendor-prerequisites.md` names the credentials it
needs per platform (Check Point: Gaia). The API runs a collect on its own
(`POST /api/v1/devices/{id}/collect`, docs/API.md).

**4. Profiles & Settings.** Review and adjust what the target needs beyond
the source: profiles, applications, logging, schedules, source users and
tags. Which entries appear depends on the **target** platform: a FortiGate
target offers UTM profiles, a PAN-OS target security profiles and tags.
Until a usable target Device is picked the branch stays in the navigation,
marked locked, and its tooltip names the reason. The target settings of NAT
and Policy Routing sit with their rulesets: Policies > NAT and, for a
PAN-OS target, Network > Policy Routing switch between Rules and Target
Settings. The views that are rulesets or network configuration in their own
right live with their kind as well: Decryption and Threat Prevention under
Policies, VPN under Network. They need a target too, so they appear once
one is usable.

Interface names deserve attention: the source's names rarely exist on the
target, so a migration to a FortiGate names them `portN`, one to PAN-OS
`ethernet1/N`. Interfaces are renamed under Network > Interfaces, where
"Fetch Target Interfaces" offers the target's names. A rename belongs to
the project, so two projects of one source can name its interfaces for two
different targets.

**5. Review & Deploy.** The Review & Deploy page holds the target
configuration. It is built offline, by itself, when the page is opened and
the configuration is missing or outdated (after edits, an import or a
changed push setting), and its state line says where it stands: up to
date, outdated and rebuilding, building. Nothing has to be generated by
hand. Rebuild is there for a build on demand. The page reads top to
bottom: the target configuration with its push buttons, the build's
numbers, the firewall rules change log and the findings, then the
generated sections themselves.

- **Target Configuration.** The first section of the page: what the
  artefact is ("Built <when>", "Outdated, rebuilding", "Building") and the
  three acts on it, Rebuild, Push Policy, Push Network. Push the network
  strand first, then policy on most targets, where rules reference zones
  that the network strand creates. Both push buttons carry the red frame of
  the acts that change a live appliance. They wait while the configuration
  is outdated or building, and each push waits for the blockers of its own
  strand. Their tooltip says why. The builds and pushes are listed in the
  project's Logs view. The push sends the configuration you reviewed, by
  reference: when it changed since (an edit elsewhere in the project, a
  rebuild), the push is refused, the page refreshes it, and you push again
  after a look at the findings. Each step is reported individually. A
  failed step stops the strand, and what that leaves on the target depends
  on the vendor (see The safety model).
- **Build Statistics.** Every scope of the source counted against the
  generated configuration: imported, generated, dropped. The vendor's note
  and the reconciliation are the row's tooltip. A generated count the drops
  do not explain keeps a visible mark, because that is the one number worth
  stopping at.
- **Firewall Rules.** Every source rule gets exactly one fate (unchanged,
  changed, dropped, split), and the folded groups list the rules that do
  not arrive as they are, with what changes and why. Disabled and shadowed
  rules have groups of their own. The groups reconcile against the
  generated rules. A difference the drops do not explain is shown as "not
  accounted for", never hidden. The rule name opens it under Policies >
  Security, and the arrows button shows the rule as the driver saw it next to
  the generated entry. Rules an earlier, broader rule makes unreachable on
  the target are found by the generate itself: a note among the findings,
  whose headline opens Policies > Security with the Shadowed filter on, and
  a Shadowed group in the change log.
- **Findings.** Blockers refuse the push of their strand until they are
  fixed (a source with several virtual routers going to a single-table
  target, interfaces the target reserves). Warnings are everything that
  does not arrive as it is on the source (rules that lose a field, items
  the target cannot represent). Notes are good to know (vendor default
  rules expressed or skipped, what the import already left out, the
  driver's reading of the migration). Each finding says why, what the
  target gets instead, and what to do. Its headline opens the place in the
  workspace where it is fixed. The three counts above the list are filters.

The generated sections stand at the bottom of the page, open, section by
section with the config the push will send. They, the report and the
before/after dialog read the stored configuration, so a reload changes
nothing.

**6. Verify and activate.** Check the result on the appliance, then commit
(PA), publish and install (Check Point), or simply verify (FortiGate).
Pushing the same configuration twice must produce the same end state,
which is a useful sanity check after a manual change.

## Managers

The Community Edition discovers Panorama, FortiManager, Check Point management and
Strata Cloud Manager and stores nothing. Importing, curating and pushing their scopes,
and migrating from one manager to another, is the Enterprise Edition. A single Check
Point gateway or cluster is read and pushed through its management in the Community
Edition too.

## Reading the push report

Steps look like `Delete Rules: deleted 6/6` or `Push Rules: pushed 61`.
Three kinds of message matter:

- **skipped** means deliberately untouched: management interfaces, HA
  links, vendor read-only objects. The count and the names are shown.
- **pruned** means a reference the target does not have was removed so the
  rest could be pushed: an identity the target's directory doesn't know, a
  security profile that isn't migrated, an object of an unsupported type.
  A pruned match side makes the rule *wider* than the source, which is why
  it is reported rather than done quietly.
- **hints** are vendor errors translated into an action. If a message tells
  you to push a different strand first or to create something on the
  target, that is usually the whole fix.

## Clusters

Pre-formed HA clusters are supported as targets. Gateshift pushes to the
primary (and refuses a subordinate), leaves the HA and management
interfaces untouched, and lets the cluster replicate. With Check Point,
per-member settings such as routes are written through each member's own
Gaia session.

The HA *relationship itself* is never migrated or created: form the cluster
first, then migrate into it. Check `KNOWN_LIMITATIONS.md` for the cloud-HA
caveat before pushing to a cluster whose heartbeat runs on DHCP addresses.

## When something goes wrong

- A failed step names the object it failed on. Start there.
- Validation blocks are usually a real vendor limit, not a bug. The message
  states the workaround.
- A re-import is safe: it replaces the imported data and keeps the
  project's edits (see Import above).
- `KNOWN_LIMITATIONS.md` lists the deliberate boundaries. If the behavior
  you see is in there, it is a decision, not a defect.
