# Gateshift

**Migrate & optimize firewalls.**

Built to make firewall migration and optimization projects easier, faster and safer.

Gateshift migrates rulesets and configurations between firewalls and cloud network security of different vendors and models, and cleans up, optimizes and audits them.

Its main properties:

- Runs air-gapped: once installed, the host can be cut off from the internet.
- No sign-up, no activation, no call-home. Nothing leaves the host unless you connect an AI client of your own.
- Talks to the security devices and services through their APIs. What each platform needs on its side is in [docs/vendor-prerequisites.md](docs/vendor-prerequisites.md).
- Reads cloud firewall policies of AWS, Azure and Google Cloud as well.
- Stores Device credentials, pre-shared keys and certificate keys encrypted, API tokens as a hash only.
- Automation built in: an API ([docs/API.md](docs/API.md)) for scripts and an MCP endpoint ([docs/MCP.md](docs/MCP.md)) for optional AI assistance with a model of your own. Pushes stay with the operator. We recommend a locally hosted model, so no firewall data leaves your network.

Website: [gateshift.org](https://gateshift.org)

Live demo: [demo.gateshift.org](https://demo.gateshift.org)

## Install

Docker Engine with the Compose plugin, `git` and `openssl` on the host, TCP 443 and 80 and UDP 514 free:

```
git clone https://github.com/gateshift/gateshift.git
cd gateshift
./install.sh
```

UI on `https://<server-address>/`. The first visit sets the password of the one account, `admin`. TLS, the bind address, air-gapped hosts, updating and the first project: [docs/install.md](docs/install.md).

How a migration runs, what the tool guarantees and how to read the push report: [docs/OPERATING.md](docs/OPERATING.md).

## What it can do

- Migrate network configurations: interfaces, zones, virtual routers, static routes, IPsec VPN, IPv4 and IPv6 alike.
- Remap source interfaces freely onto the target's ports, physical and virtual alike: a port can become a VLAN, a bond, a loopback or a tunnel, and the other way round.
- Auto-derive zones when the source has none and the target needs them.
- Migrate rulesets: firewall rules, NAT, decryption, Policy Routing, Check Point threat prevention, with their objects, schedules, URL categories and tags.
- Treat each FortiGate VDOM, PAN-OS vsys and Check Point VSX virtual system as a scope of its own.
- Read the security profiles, applications, user identities and log settings the target itself offers and apply them to the rulesets.
- Review a build before the push: every finding, blocker and declared drop, rule by rule. What a target cannot express is declared instead of going out silently.
- Never push a reference to a missing object, zone or interface.
- Push the network and the policy separately. A failed push on PAN-OS returns to its rescue point, a failed policy push on Check Point discards the staged session.
- Find and remove unused and duplicate objects.
- Find shadowed rules: rules an earlier, broader rule already covers.
- Read the firewalls' own hit counters to find rules nobody uses.
- Generate new rulesets from the traffic logs of OPNsense.
- Optimize and clean up a configuration in place, with the same Device as source and target.
- Keep every migration as a project with snapshots, several tenants in one installation.

## Supported vendors

Every supported platform, with its form, direction and edition, is listed in [docs/support-matrix.md](docs/support-matrix.md).

## Editions

This repository is the **Community Edition**, complete for what it covers: single firewalls, HA clusters and virtual instances, no rule-count caps, no time limit, no feature nagging. Service providers may use it in client projects free of charge.

The **Enterprise Edition** adds the manager tier (Panorama, FortiManager, Check Point management, Strata Cloud Manager). It is commercial and not part of this repository.

## Verification, liability and intended use

Gateshift is a tool for specialists. It assumes you know the platforms involved and can judge a firewall configuration on its merits. It is not a substitute for that judgment.

Gateshift can and will get things wrong. What it pushes onto a target is a draft, not a finished configuration: review it there, test it, and decide for yourself whether it goes live. Everything the tool does on a Device happens on the operator's authority and remains the operator's responsibility.

Configuration backups and verification are the operator's responsibility and a mandatory part of every migration:

- Back up every system before Gateshift touches it.
- Read Gateshift's own log.
- Review the pushed configuration on the target.
- Test the result for correctness and function before cutover.

To the extent permitted by applicable law, Gateshift and everything it produces are provided "as is", without warranty of any kind and without any acceptance of liability. `LICENSE` is authoritative. It carries the complete warranty disclaimer and the limitation of liability, including what it covers in detail.

Gateshift is an independent project. It is not affiliated with, endorsed by, or supported by any vendor named in this repository. Vendor names are used solely to describe compatibility.

## Transparency and license

Gateshift started as a hand-written project. Its development is now AI-assisted. The product itself contains no model and makes no LLM calls: an AI client only sees what you connect through the MCP endpoint. `SBOM.json` (CycloneDX) lists every dependency and its license.

| Part | License |
|---|---|
| Community Edition (this repository) | Business Source License 1.1 |
| Enterprise Edition | commercial, separate agreement |

BSL 1.1 is source-available, not OSI open source at first. You may read, modify and run it, including commercially and including migration work you perform for clients. What the license excludes is offering a competing product. Every release becomes genuine open source four years after it ships: the conversion to the Mozilla Public License 2.0 is written into the license text itself and happens automatically, the change date is stamped per release. `LICENSE` is authoritative. This table is a summary, not a grant. The name and logo are trademarks and are not licensed with the code.

## Bugs, requests and support

A bug is when Gateshift does not do what the documentation says. What it does not do lives in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md), anything beyond that is a feature request. Bug reports with the vendor, the exact firmware version and the verbatim error text are the most useful thing you can send. There is no support entitlement for the Community Edition, and pull requests are not accepted as a rule, see [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerabilities go to [SECURITY.md](SECURITY.md), never into a public issue.
