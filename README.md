# Gateshift

**The firewall migration tool.**

Built to make firewall migration and optimization projects easier, faster and safer.

Gateshift reads a firewall configuration, translates it into a vendor-neutral form, enriches it with what the target platform can do, and pushes it through the target's API.

Website: [gateshift.org](https://gateshift.org)

## See it in action

Complete migrations, start to finish, on YouTube:

- [Check Point to Palo Alto Networks (Panorama): Part 1: Import and enrichment](https://youtu.be/LYKX6bk2_as), [Part 2: Push and verification](https://youtu.be/M-ZO3mGTqKQ)
- [Palo Alto Networks to FortiGate, single firewalls](https://youtu.be/vA38rwWIaUA)
- [FortiGate to Check Point, single firewalls](https://youtu.be/1o4KdD5kzVI)
- [Cisco ASA to FortiGate, single firewalls](https://youtu.be/B6m6rpfW9ns)

More on the [Gateshift channel](https://www.youtube.com/@Gateshifter).

## What it can do

- Migrate firewall configurations between different vendors and deployment models: standalones, clusters, unmanaged and managed devices, on hardware, virtual and cloud alike.
- Carry firewall rules, NAT, address and service objects, interfaces, static routes, policy routing, IPsec VPN, schedules, URL categories and tags across to the target.
- Attach what the target itself offers instead of copying the source: security profiles, applications, user identity and log settings.
- Find rules an earlier, broader rule already shadows, and disable them in bulk.
- Generate new rulesets from traffic logs.
- Optimize and clean up firewall configurations, directly on a firewall or during migrations.
- Keep every migration as a project with snapshots to save working states.
- Hold several tenants in one installation, so projects and devices stay sorted by tenant.
- Operate fully offline: no telemetry, no phone-home, no licence callbacks, no cloud uploads, no LLM calls.

Migrating to and from central managers (Panorama, FortiManager, Check Point MDS) is part of the Enterprise Edition. See Editions below.

## What it can't do

- Do 1:1 migrations.
- Run automated or unattended migrations.
- Guarantee flawless output.
- Make manual review obsolete.

## Install

Prerequisites on the host: Docker Engine with the Compose plugin (`docker
compose`, v2) from Docker's own repository, `git` and `openssl`. TCP 443 and
80 and UDP 514 must be free. The first start builds the images and needs
internet access for that.

```
git clone https://github.com/gateshift/gateshift.git
cd gateshift
./install.sh
```

UI on `https://<server-address>/`. The first visit asks you to set the
password of the one account, `admin`. Every later visit asks for a login.

The installer checks the prerequisites, generates strong random credentials
into `.env` (never overwriting an existing one), writes the TLS certificate
and starts the stack. `.env.example` documents every setting if you prefer to
set up `.env` yourself.

**TLS.** The web container serves HTTPS on 443 itself, with no proxy in front
of it, from `certs/gateshift.crt` and `certs/gateshift.key`. `make-cert.sh`,
which the installer runs, writes a self-signed certificate carrying this
host's names and addresses. `./install.sh --renew-cert` replaces it when the
names change or it runs out. To use your own CA instead, put its certificate
and key into those two files at any time and restart the stack. Nothing else
changes.

The UI listens on every address of the host. Reach it over a management network you trust, or restrict it with `WEBUI_BIND=<address>` in `.env`.

Air-gapped installs: the image build downloads the Tailwind CLI from GitHub. Install with internet access first. The connection can be cut afterwards.

## Workflow

Every step is explicit and under the operator's control:

- Add devices via API, configuration file, or traffic logs.
- Create a project: a source and a target for a migration, or the same device as both for an in-place optimization.
- Re-map and rename interfaces, physical to virtual and vice versa.
- Filter and consolidate the rules.
- Drop unused and duplicate objects.
- Auto-derive zones and interfaces, auto-assign applications.
- Attach security profiles, log settings and schedules to the rules.
- Review the target configuration before anything is pushed: what the target will receive, what the generate dropped and why, and the rule-by-rule change log against the source.
- Push the whole configuration or just selected scopes.
- Save a snapshot of the project's edits at any point, restore it later, or branch a second project from it.

Sources come from an API connection, a configuration-file upload, or traffic logs. Migrations run intra-vendor and cross-vendor, appliance to manager and manager to appliance (the manager tier is the Enterprise Edition). With the same device as source and target, the identical pipeline performs in-place optimization and cleanup. Traffic logs can be turned into rule candidates instead of importing a policy.

## Supported vendors

| Vendor | Read from | Push to |
|---|---|---|
| Palo Alto Networks (PAN-OS) | yes | yes |
| FortiGate (FortiOS) | yes | yes |
| Check Point (Management API + Gaia) | yes | yes |
| Cisco FTD (FDM-managed) | yes | - |
| Cisco ASA (config file) | yes | - |
| OPNsense (config file or traffic logs) | yes | - |

## Editions

This repository is the **Community Edition**, and it is complete for what it covers: single firewalls and HA clusters, no rule-count caps, no time limit, no feature nagging. Service providers may use it in client projects free of charge.

The **Enterprise Edition** adds the manager tier (Panorama, FortiManager, Check Point MDS), with vendor cloud managers on the roadmap. It is commercial and not part of this repository. It is named here because a paid edition appearing later without warning would be a bait-and-switch.

## Verification, liability and intended use

Gateshift is a tool for specialists. It assumes you know the platforms involved and can judge a firewall configuration on its merits. It is not a substitute for that judgment.

Gateshift can and will get things wrong. What it pushes onto a target is a draft, not a finished configuration: review it there, test it, and decide for yourself whether it goes live. Everything the tool does on a device happens on the operator's authority and remains the operator's responsibility.

Configuration backups and verification are the operator's responsibility and a mandatory part of every migration:

- Back up every system before Gateshift touches it.
- Read Gateshift's own log.
- Review the pushed configuration on the target.
- Test the result for correctness and function before cutover.

To the extent permitted by applicable law, Gateshift and everything it produces are provided "as is", without warranty of any kind and without any acceptance of liability. In particular, no liability is accepted for:

- generated or pushed configurations and their behavior on any device
- migration outcomes, including incomplete, incorrect or lossy migrations
- malfunctions or defects of the software itself
- damage to or outages of connected systems, production or otherwise
- data loss on any system Gateshift reads from or writes to
- any consequences for support agreements or warranties covering the connected devices

Gateshift is an independent project. It is not affiliated with, endorsed by, or supported by any vendor named in this repository. Vendor names are used solely to describe compatibility.

`LICENSE` is authoritative. It carries the complete warranty disclaimer and limitation of liability.

## Transparency

Gateshift started as a hand-written project. Its development is now AI-assisted. The product itself contains no AI. The source can be read, and every release is guaranteed to become genuine open source (MPL 2.0) four years after it ships (see License). `SBOM.json` (CycloneDX) lists every dependency and its licence.

## License

| Part | License |
|---|---|
| Community Edition (this repository) | Business Source License 1.1 |
| Enterprise Edition | commercial, separate agreement |

BSL 1.1 is source-available. It is not OSI open source at first. You may read, modify and run it, including commercially and including migration work you perform for clients. What the license excludes is offering a competing product.

Every release becomes genuine open source four years after it ships. The conversion to the Mozilla Public License 2.0, an OSI-approved license, is written into the license text itself and happens automatically. It does not depend on anyone's goodwill, including ours. The change date is stamped per release.

`LICENSE` is authoritative. This table is a summary, not a grant. The name and logo are trademarks and are not licensed with the code.

## Bugs, requests and support

A bug is when Gateshift does not do what the documentation says. What it does not do lives in `KNOWN_LIMITATIONS.md`. Anything beyond that is a feature request, not a defect.

- **Bug reports** are welcome and genuinely useful. Vendors rename fields and change response schemas between releases, and we cannot test every version of every supported vendor. Include the vendor, the exact firmware version, and the verbatim error or drop-report text.
- **Feature requests** are welcome from anyone. They are read and labeled, but carry no commitment or date. Enterprise subscribers get a say in release prioritization.
- **No support entitlement** for the Community Edition.
- **Pull requests** are not accepted as a rule. Single-copyright ownership is what makes the license model and the Enterprise Edition possible. Substantial contributions are possible case by case, under a contributor agreement.

Security: report vulnerabilities privately, not in a public issue. Only the latest release is supported. Security fixes ship in the next release.

## Roadmap

Direction, not commitment. These entries carry no dates, and feature requests feed the list without filling it:

- **1.0**: stability round incorporating first feedback.
- Vendor cloud managers: Strata Cloud Manager, Smart-1 Cloud, FortiManager Cloud (Enterprise).
- Additional vendor and device support.

## Status

The current release is feature-complete. Gateshift remains an independent project in active development.
