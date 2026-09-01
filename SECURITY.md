# Security Policy

Gateshift stores credentials for your firewalls and writes configuration to
connected devices. Security reports get looked at with corresponding
seriousness.

## Reporting a vulnerability

**Please do not report vulnerabilities in public issues.**

Preferred channel: **GitHub private vulnerability reporting** - use
*"Report a vulnerability"* under the repository's Security tab. If you
cannot use GitHub, mail **security@gateshift.org**.

You will receive an acknowledgment within **7 days**. Please include a
reproduction path and the affected version; a proof-of-concept helps, an
exploit chain is not required.

## Supported versions

**Only the latest release is supported.** Security fixes ship in the next
release rather than as backports.

| Version | Supported |
|---|---|
| latest release | yes |
| anything older | no - upgrade |

## Scope notes for operators

These properties matter more than any single patch:

- The web UI binds to loopback by default and has **no authentication of its
  own**. Exposing it beyond a trusted management network without a
  reverse proxy in front is a deployment vulnerability, not a product one.
  (README)
- Set `GATESHIFT_SECRET_KEY`. It encrypts stored device credentials
  (API keys, Gaia passwords, VPN pre-shared keys) at rest; without it, those
  sit in the database unencrypted. The key itself lives in the environment,
  not the database - protect the `.env` file accordingly.
- **Connections to firewalls do not verify the management TLS certificate.**
  Firewall management interfaces almost always ship a self-signed certificate,
  so Gateshift connects without certificate validation - which means it does
  not defend against a man-in-the-middle between the host and a firewall.
  Run it on the trusted management path you would use for any other tool that
  holds those credentials.
- **Working data is not encrypted.** Imported rules, objects, interfaces and
  routes are stored in clear text so the pipeline can process them, and an
  uploaded ASA running-config is kept verbatim. Do not import real production
  configurations - restore a backup onto a lab appliance and connect to that.
  Secrets embedded in a source config (VPN pre-shared keys)
  are never read; Gateshift pushes a placeholder.

## No bounty

There is no bug bounty program. Reports are credited in the release notes
if you wish.
