# Gateshift

**The firewall migration tool.**

Built to make firewall migration and optimization projects easier, faster and more predictable.

## Demo

https://github.com/user-attachments/assets/ba927281-4384-41b8-9002-1399fe66783e

## What it can do

- Migrate firewall configurations between different vendors and deployment models: standalones / clusters / unmanaged / managed (Enterprise Edition) - hardware / virtual / cloud alike.
- Migrate interfaces, routes, rulesets, NAT, objects, security profiles, IPsec VPN, threat prevention, and more.
- Generate new rulesets from traffic logs.
- Optimize and clean up firewall configurations, directly on a firewall or during migrations.
- Operate fully offline: no telemetry, no phone-home, no license callbacks, no cloud uploads, no LLM calls.

## What it can't do

- Do 1:1 migrations.
- Run automated or unattended migrations.
- Guarantee flawless output.
- Make manual review obsolete.

## Install

**Local machine** - UI on http://127.0.0.1:8080

```
git clone https://github.com/gateshift/gateshift.git
cd gateshift
./install.sh
```

**Remote server** - UI on http://<server-address>:8080

```
git clone https://github.com/gateshift/gateshift.git
cd gateshift
./install.sh --bind 0.0.0.0
```

The installer checks the prerequisites, generates strong random credentials
into `.env` (never overwriting an existing one) and starts the stack.
`.env.example` documents every setting if you prefer to set up `.env` yourself.

The UI binds to loopback and has no authentication of its own. `--bind 0.0.0.0` makes it reachable from the network - do that only behind a reverse proxy or on a trusted management network. The web container mounts the host's Docker socket, which is root-equivalent access to the host - run the stack on a host you would trust with firewall credentials anyway.

Air-gapped installs: the image build downloads the Tailwind CLI from GitHub. Build the images where there is egress, or provide a proxy.

## Workflow

Every step is explicit and under the operator's control:

- Add devices via API, configuration file, or traffic logs.
- Select a source and a target.
- Re-map and rename interfaces - physical to virtual and vice versa.
- Filter and consolidate the rules.
- Drop unused and duplicate objects.
- Auto-derive zones and interfaces, auto-assign applications.
- Apply security profiles, log settings, schedules, etc.
- Push the whole configuration or just selected scopes.

Sources come from an API connection, a configuration-file upload, or traffic logs. Migrations run intra-vendor and cross-vendor, appliance to manager and manager to appliance (the manager tier is the Enterprise Edition). With the same device as source and target, the identical pipeline performs in-place optimization and cleanup. Traffic logs can be turned into rule candidates instead of importing a policy.

## Supported vendors

| Vendor | Read from | Push to |
|---|---|---|
| Palo Alto Networks (PAN-OS) | yes | yes |
| FortiGate (FortiOS) | yes | yes |
| Check Point (Management API + Gaia) | yes | yes |
| Cisco FTD (FDM-managed) | yes | - |
| Cisco ASA (config file) | yes | - |
| OPNsense (traffic logs) | yes | - |

## Editions

This repository is the **Community Edition**, and it is complete for what it covers: single firewalls and HA clusters, no rule-count caps, no time limit, no feature nagging. Service providers may use it in client projects free of charge.

The **Enterprise Edition** adds the manager tier - Panorama, FortiManager, Check Point MDS - with vendor cloud managers on the roadmap. It is commercial and not part of this repository. It is named here because a paid edition appearing later without warning would be a bait-and-switch.

## Verification, liability and intended use

> **Lab use only.** Gateshift is a private project, still under development, and not intended for production use. Do not connect it to production systems - neither API access to a production source nor pushes onto a production target. Use is entirely at your own risk.

Gateshift is a tool for specialists. It assumes you know the platforms involved and can judge a firewall configuration on its merits; it is not a substitute for that judgment.

Configuration backups and verification are the operator's responsibility and a mandatory part of every migration. Back up every system Gateshift touches, before it touches them. Read the generate report, review the pushed configuration on the target, and test the result for correctness and function before cutover.

Most "tool bug" reports turn out to be device access problems: an API user missing a trusthost, an unpublished Check Point API user, or a PAN-OS password pasted into the API-key field. Read `KNOWN_LIMITATIONS.md` before the first migration.

To the extent permitted by applicable law, Gateshift and everything it produces are provided "as is", without warranty of any kind and without any acceptance of liability. In particular, no liability is accepted for:

- generated or pushed configurations and their behavior on any device
- migration outcomes, including incomplete, incorrect or lossy migrations
- malfunctions or defects of the software itself
- damage to or outages of connected systems - production or otherwise
- data loss on any system Gateshift reads from or writes to
- any consequences for support agreements or warranties covering the connected devices

Gateshift is an independent project. It is not affiliated with, endorsed by, or supported by any vendor named in this repository; vendor names are used solely to describe compatibility.

`LICENSE` is authoritative; it carries the complete warranty disclaimer and limitation of liability.

## Transparency

Gateshift began as a hand-written one-man project; its development is now AI-assisted. The product itself contains no AI. The source is open, and every release is guaranteed to become genuine open source (MPL 2.0) four years after it ships (see License). `SBOM.json` (CycloneDX) lists every dependency and its license.

## License

| Part | License |
|---|---|
| Community Edition (this repository) | Business Source License 1.1 |
| Enterprise Edition | commercial, separate agreement |

BSL 1.1 is source-available, not OSI open source - at first. You may read, modify and run it, including commercially and including migration work you perform for clients. What the license excludes is offering a competing product.

Every release becomes genuine open source four years after it ships. The conversion to the Mozilla Public License 2.0 - an OSI-approved license - is written into the license text itself and happens automatically; it does not depend on anyone's goodwill, including ours. The change date is stamped per release.

`LICENSE` is authoritative; this table is a summary, not a grant. The name and logo are trademarks and are not licensed with the code.

## Bugs, requests and support

A bug is when Gateshift does not do what the documentation says. What it does not do lives in `KNOWN_LIMITATIONS.md`; anything beyond that is a feature request, not a defect.

- **Bug reports** are welcome and genuinely useful. Vendors rename fields and change response schemas between releases, and we cannot test every version of every supported vendor. Include the vendor, the exact firmware version, and the verbatim error or drop-report text.
- **Feature requests** are welcome from anyone. They are read and labeled, but carry no commitment or date. Enterprise subscribers get a say in release prioritization.
- **No support entitlement** for the Community Edition.
- **Pull requests** are not accepted as a rule. Single-copyright ownership is what makes the license model and the Enterprise Edition possible. Substantial contributions are possible case by case, under a contributor agreement.

Security: report vulnerabilities privately, not in a public issue. Only the latest release is supported; security fixes ship in the next release.

## Roadmap

Direction, not commitment - entries carry no dates, and feature requests feed the list without filling it:

- **1.0** - stability round incorporating first feedback.
- Vendor cloud managers: Strata Cloud Manager, Smart-1 Cloud, FortiManager Cloud (Enterprise).
- Additional vendor and device support.
- Configuration snapshots - save working states and revert to them.
- Multi-tenancy (Enterprise).

## Status

Version 0.9.0 - feature-complete and verified against live appliances across the full cross-vendor matrix. Gateshift remains a private project in active development, not intended for production use; work against lab appliances, not production systems (see the liability section above).
