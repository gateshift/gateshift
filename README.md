# Gateshift

**The firewall migration tool.**

Built to make firewall migration and cleanup projects easier, faster and safer.

Runs on your own host, air-gapped after install, no activation, no account, no call-home, no AI, no LLM calls. Nothing leaves the host: configurations and credentials stay where they are, credentials encrypted at rest.

Website: [gateshift.org](https://gateshift.org)

**LIVE DEMO:** [demo.gateshift.org](https://demo.gateshift.org)

## Supported vendors

Palo Alto Networks, FortiGate and Check Point as sources and targets. Cisco Secure Firewall, Cisco ASA, OPNsense, AWS, Azure and Google Cloud as sources. Panorama, FortiManager, Check Point management and Strata Cloud Manager in the Enterprise Edition. Forms, directions and editions in full: [docs/support-matrix.md](docs/support-matrix.md). What each platform needs on its side: [docs/vendor-prerequisites.md](docs/vendor-prerequisites.md).

## Install

Docker Engine with the Compose plugin, `git` and `openssl` on the host, TCP 443 and 80 and UDP 514 free:

```
git clone https://github.com/gateshift/gateshift.git
cd gateshift
./install.sh
```

UI on `https://<server-address>/`. The first visit sets the password of the one account, `admin`. TLS, the bind address, air-gapped hosts, updating and the first project: [docs/install.md](docs/install.md).

## What it can do

- Migrate firewall configurations between vendors and deployment models: standalones, clusters, unmanaged and managed devices, on hardware, virtual and cloud alike.
- Carry rules, NAT, address and service objects, interfaces, zones, virtual routers, static routes, policy routing, IPsec VPN, decryption rules, Check Point threat prevention, schedules, URL categories and tags, IPv4 and IPv6 alike. What a target cannot express is declared per rule instead of going out silently.
- Attach what the target itself offers instead of copying the source: security profiles, applications, user identity and log settings.
- Find rules an earlier, broader rule already covers, read the firewalls' own hit counters beside the usage derived from logs, and disable in bulk what a migration need not carry.
- Generate new rulesets from traffic logs, optimize and clean up configurations in place.
- Keep every migration as a project with snapshots, several tenants in one installation.

## What it can't do

- Do 1:1 migrations.
- Run automated or unattended migrations.
- Guarantee flawless output.
- Make manual review obsolete.

## Editions

This repository is the **Community Edition**, complete for what it covers: single firewalls and HA clusters, no rule-count caps, no time limit, no feature nagging. Service providers may use it in client projects free of charge.

The **Enterprise Edition** adds the manager tier: Panorama, FortiManager and FortiManager Cloud, Check Point management (SmartCenter, Smart-1 Cloud or Multi-Domain) and Strata Cloud Manager. The Community Edition discovers every one of them and stores nothing, importing and pushing them needs the Enterprise Edition. It is commercial and not part of this repository. It is named here because a paid edition appearing later without warning would be a bait-and-switch.

## Verification, liability and intended use

Gateshift is a tool for specialists. It assumes you know the platforms involved and can judge a firewall configuration on its merits. It is not a substitute for that judgment.

Gateshift can and will get things wrong. What it pushes onto a target is a draft, not a finished configuration: review it there, test it, and decide for yourself whether it goes live. Everything the tool does on a device happens on the operator's authority and remains the operator's responsibility.

Configuration backups and verification are the operator's responsibility and a mandatory part of every migration:

- Back up every system before Gateshift touches it.
- Read Gateshift's own log.
- Review the pushed configuration on the target.
- Test the result for correctness and function before cutover.

To the extent permitted by applicable law, Gateshift and everything it produces are provided "as is", without warranty of any kind and without any acceptance of liability. `LICENSE` is authoritative. It carries the complete warranty disclaimer and the limitation of liability, including what it covers in detail.

Gateshift is an independent project. It is not affiliated with, endorsed by, or supported by any vendor named in this repository. Vendor names are used solely to describe compatibility.

## Transparency and license

Gateshift started as a hand-written project. Its development is now AI-assisted. The product itself contains no AI. `SBOM.json` (CycloneDX) lists every dependency and its licence.

| Part | License |
|---|---|
| Community Edition (this repository) | Business Source License 1.1 |
| Enterprise Edition | commercial, separate agreement |

BSL 1.1 is source-available, not OSI open source at first. You may read, modify and run it, including commercially and including migration work you perform for clients. What the license excludes is offering a competing product. Every release becomes genuine open source four years after it ships: the conversion to the Mozilla Public License 2.0 is written into the license text itself and happens automatically, the change date is stamped per release. `LICENSE` is authoritative. This table is a summary, not a grant. The name and logo are trademarks and are not licensed with the code.

## Bugs, requests and support

A bug is when Gateshift does not do what the documentation says. What it does not do lives in `KNOWN_LIMITATIONS.md`, anything beyond that is a feature request. Bug reports with the vendor, the exact firmware version and the verbatim error text are the most useful thing you can send. There is no support entitlement for the Community Edition, and pull requests are not accepted as a rule, see [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerabilities go to [SECURITY.md](SECURITY.md), never into a public issue.
