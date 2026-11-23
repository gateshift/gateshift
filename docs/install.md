# Installation and updates

## Prerequisites

Docker Engine with the Compose plugin (`docker
compose`, v2) from Docker's own repository, `git` and `openssl`. TCP 443 and
80 and UDP 514 must be free. The first start builds the images and needs
internet access for that.

## Install

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

## The secret key

The installer writes a `GATESHIFT_SECRET_KEY` into the `.env` it generates.
It encrypts the stored Device credentials, the VPN pre-shared keys and the
keys of uploaded VPN certificates. Back up `.env`: losing the key makes the
stored credentials undecryptable, and every Device's credentials have to be entered again.

A key that is set but is no Fernet key (44 characters) stops the start. The
installer refuses such a key in an existing `.env`. A `.env` written by hand
may still carry one, and `docker compose logs webapp` then shows the reason.
`openssl rand 32 | base64 | tr '+/' '-_'` makes a valid key.

## Forgotten password

The password of the one account is set anew from the server, without
touching the data. The command prompts for the new password twice:

```
docker compose exec webapp python reset_admin.py
```

## TLS

The web container serves HTTPS on 443 itself, with no proxy in front
of it, from `certs/gateshift.crt` and `certs/gateshift.key`. `make-cert.sh`,
which the installer runs, writes a self-signed certificate carrying this
host's names and addresses. `./install.sh --renew-cert` replaces it when the
names change or it runs out, and restarts the web container. To use your own
CA instead, put its certificate and key into those two files at any time and
run `docker compose restart webapp`: the web server reads them when it
starts. Nothing else changes.

## Network exposure

The UI listens on every address of the host. Reach it over a management
network you trust, or restrict it with `WEBUI_BIND=<address>` in `.env`. The
automation API (`/api/v1`) and the MCP endpoint (`/mcp`) share port 443 with
the pages. The syslog receiver listens on UDP 514 on every address unless
`SYSLOG_BIND=<address>` in `.env` restricts it.

## Air-gapped hosts

The first start pulls the MariaDB and syslog-ng images and builds the two
others, which downloads a Python base image, Debian packages, Python packages
from PyPI and the Tailwind CLI from GitHub. Install with internet access
first, or through a proxy. The connection can be cut afterwards, but every
update with `--build` needs the same access again for whatever changed.

## Updating

Dump the database first, then pull and rebuild. The MariaDB image names its
client `mariadb-dump`, and the credentials come from the container's own
environment, so nothing is typed:

```
docker compose exec -T mariadb sh -c 'mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" --single-transaction --routines --events "$MARIADB_DATABASE"' > gateshift-before-update.sql
git pull
docker compose up -d --build
```

`--build` is not optional: the code of both images, the SQL jobs included,
is built into them, so `docker compose up -d` alone keeps the old code
running.

Before 1.0 there is no guaranteed database migration path between releases.
The dump is your way back. Each release in CHANGELOG.md lists
what its first start migrates. The dump belongs to the release it was taken
from, so going back needs that release's code as well: stop the web
container, load the dump with the same variables as above, check out the
previous release and rebuild.

```
docker compose stop webapp
docker compose exec -T mariadb sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" "$MARIADB_DATABASE"' < gateshift-before-update.sql
git checkout <previous release tag>
docker compose up -d --build
```

**A fresh install is the shorter path while nothing in the installation is
yours.** Everything Gateshift read from a Device it can read again, so as long
as you hold no projects, renames, per-rule edits, snapshots or traffic
evidence you want to keep:

```
docker compose down -v
./install.sh
```

That drops the database and starts empty, keeping your `.env` and your
certificate. Received syslog files stay in `syslog-ng/logs` and are read again
when you ingest them. Once the installation carries work you want to keep,
dump the database and update in place instead.

## First project

Every step is explicit and under the operator's control:

- Add Devices via API, configuration file, cloud account, or traffic logs.
- Create a project: a source and a target for a migration, or the same Device as both for an in-place optimization.
- Re-map and rename interfaces, physical to virtual and vice versa.
- Filter and consolidate the rules.
- Drop unused and duplicate objects.
- Auto-derive zones and interfaces, auto-assign applications.
- Attach security profiles, log settings and schedules to the rules.
- Review the build before anything is pushed: what the target will receive, every finding, blocker and declared drop, and the rule-by-rule change log against the source.
- Push the network and the policy separately.
- Save a snapshot of the project's edits at any point, restore it later, or branch a second project from it.

Sources come from an API connection, a configuration-file upload, or traffic logs. Migrations run intra-vendor and cross-vendor, appliance to manager and manager to appliance (the manager tier is the Enterprise Edition). With the same Device as source and target, the identical pipeline performs in-place optimization and cleanup. Traffic logs can be turned into rule candidates instead of importing a policy.
