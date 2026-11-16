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

## TLS

The web container serves HTTPS on 443 itself, with no proxy in front
of it, from `certs/gateshift.crt` and `certs/gateshift.key`. `make-cert.sh`,
which the installer runs, writes a self-signed certificate carrying this
host's names and addresses. `./install.sh --renew-cert` replaces it when the
names change or it runs out. To use your own CA instead, put its certificate
and key into those two files at any time and restart the stack. Nothing else
changes.

## Network exposure

The UI listens on every address of the host. Reach it over a management network you trust, or restrict it with `WEBUI_BIND=<address>` in `.env`.

## Air-gapped hosts

The image build downloads the Tailwind CLI from GitHub. Install with internet access first. The connection can be cut afterwards.

## Updating

Dump the database first, then pull and rebuild. The MariaDB image names its
client `mariadb-dump`, and the credentials come from the container's own
environment, so nothing is typed:

```
docker compose exec -T mariadb sh -c 'mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" --single-transaction --routines --events "$MARIADB_DATABASE"' > gateshift-before-update.sql
git pull
docker compose up -d --build
```

`--build` is not optional: the Python code lives in the images, the SQL jobs
are read from the checkout, so `docker compose up -d` alone starts the old
images against the new jobs.

Before 1.0 there is no guaranteed database migration path between releases.
The dump is your way back. Each release in CHANGELOG.md lists
what its first start migrates.

**A fresh install is the shorter path while nothing in the installation is
yours.** Everything Gateshift read from a device it can read again, so as long
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

- Add devices via API, configuration file, cloud account, or traffic logs.
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
