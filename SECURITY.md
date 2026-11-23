# Security Policy

Gateshift stores credentials for your firewalls and writes configuration to
connected Devices. Security reports get looked at with corresponding
seriousness.

## Reporting a vulnerability

**Please do not report vulnerabilities in public issues.**

Preferred channel: **GitHub private vulnerability reporting**. Use
*"Report a vulnerability"* under the repository's Security tab. If you
cannot use GitHub, mail **security@gateshift.org**.

You will receive an acknowledgment within **7 days**. Please include a
reproduction path and the affected version. A proof-of-concept helps, an
exploit chain is not required.

## Supported versions

**Only the latest release is supported.** Security fixes ship in the next
release rather than as backports.

| Version | Supported |
|---|---|
| latest release | yes |
| anything older | no, upgrade |

## Scope notes for operators

These properties matter more than any single patch:

- The web UI serves HTTPS itself and asks for the login of its one account,
  `admin`, on every visit. It listens on every address of the host: reach it
  over a management network you trust, or restrict it with `WEBUI_BIND` in
  `.env`. Exposing it to untrusted networks is a deployment decision, not a
  product property (docs/install.md, Network exposure).
- The automation API at `/api/v1` and the MCP endpoint at `/mcp`
  authenticate with bearer tokens, never with the login session. A signed-in
  user creates a token on the Automation page and sees it once, Gateshift
  keeps only its hash. A token carries a scope: `read` for the reads,
  `project` to curate a project and build it, `full` to also push, publish
  and discard and to manage Devices, projects and the tunnels' keys. A token
  may expire and may be bound to one tenant, which is then the only tenant
  it sees. Give an AI client a `project` token and revoke a token nobody
  uses any more (docs/API.md, docs/MCP.md).
- Set `GATESHIFT_SECRET_KEY`. It encrypts the stored Device credentials
  (API keys and passwords), the VPN pre-shared keys and the private keys of
  VPN identity certificates at rest. Without it, Device credentials sit in
  the database in clear text, and pre-shared keys and certificate keys
  cannot be stored at all. A value that is set but no Fernet key stops the
  start. The key itself lives in the environment, not the database: protect
  the `.env` file accordingly.
- **Connections to firewalls do not verify the management TLS certificate.**
  Firewall management interfaces almost always ship a self-signed certificate,
  so Gateshift connects without certificate validation, which means it does
  not defend against a man-in-the-middle between the host and a firewall.
  Run it on the trusted management path you would use for any other tool that
  holds those credentials.
- **Working data is not encrypted.** Imported rules, objects, interfaces and
  routes are stored in clear text so the pipeline can process them, and an
  uploaded ASA running-config is kept verbatim. A Gateshift host therefore
  holds the same sensitive material as the firewalls it talks to: run and
  protect it accordingly, and where you do not need the live source, connect
  to a restored backup instead. Secrets embedded in a source config (VPN
  pre-shared keys) are never read. A tunnel's pre-shared key is entered under
  Network > VPN, stored encrypted and never shown again, and without one
  Gateshift pushes a placeholder.

## No bounty

There is no bug bounty program. Reports are credited in the release notes
if you wish.
