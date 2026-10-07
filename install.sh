#!/usr/bin/env bash
# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
#
# Gateshift installer: checks the prerequisites, generates a .env with
# strong random credentials (never overwriting an existing one), writes a
# self-signed TLS certificate (never overwriting an existing one) and starts
# the stack. Safe to run again - an existing installation is simply
# restarted with its current settings.
#
#   ./install.sh                UI on https://<this server's address>/ - every
#                               address, HTTPS on 443, HTTP on 80 redirects
#   ./install.sh --renew-cert   new self-signed certificate (new names or
#                               addresses, or the old one ran out)
#
# The first visit sets the admin password. To restrict the UI to one
# address put WEBUI_BIND=<address> into .env.

set -euo pipefail
cd "$(dirname "$0")"

RENEW_CERT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --renew-cert) RENEW_CERT=1; shift ;;
        *) echo "unknown option: $1 (supported: --renew-cert)" >&2; exit 2 ;;
    esac
done

fail() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 \
    || fail "docker is not installed - see https://docs.docker.com/engine/install/"
# Distinguish "daemon down" from "no permission" - the latter has a concrete
# fix the user shouldn't have to guess. (Capture instead of piping to grep:
# pipefail would keep docker's exit status even when grep matches.)
if ! _docker_info_err="$(docker info 2>&1)"; then
    if grep -qi 'permission denied' <<<"$_docker_info_err"; then
        fail "cannot talk to the Docker daemon: permission denied.
       Run this installer as root, or add your user to the 'docker' group:
           sudo usermod -aG docker \$USER
       then log out and back in (group membership needs a fresh session)."
    fi
    fail "cannot talk to the Docker daemon - is it running?"
fi
docker compose version >/dev/null 2>&1 \
    || fail "the Docker Compose plugin (v2) is missing - see https://docs.docker.com/compose/install/"
command -v openssl >/dev/null 2>&1 \
    || fail "openssl is required to generate credentials and the certificate"

# The UI publishes 443 and 80; another web server on this host would make
# the stack fail late. Warning only, like the syslog port below.
if command -v ss >/dev/null 2>&1; then
    for p in 443 80; do
        if ss -tln 2>/dev/null | grep -qE ":$p "; then
            echo "WARNING: something on this host already listens on TCP $p;"
            echo "         the web container will fail to start until it is freed."
        fi
    done
fi

# The syslog receiver publishes UDP 514; a host syslog daemon already bound
# there makes the stack fail late, so say it early. Warning only - the port
# may legitimately be free by the time the container starts.
if command -v ss >/dev/null 2>&1 && ss -uln 2>/dev/null | grep -q ':514 '; then
    echo "WARNING: something on this host already listens on UDP 514;"
    echo "         the syslog container will fail to start until it is freed."
fi

if [ -f .env ]; then
    echo "keeping existing .env"
else
    # A database volume from a previous installation holds the credentials
    # of the .env it was first started with - generating a fresh .env next
    # to it yields "Access denied" on every boot. Make the conflict loud.
    PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')}"
    if docker volume inspect "${PROJECT}_mariadb_data" >/dev/null 2>&1; then
        fail "no .env, but the database volume '${PROJECT}_mariadb_data' already exists.
       Its credentials belong to the previous .env. Either restore that .env,
       or reset the installation with 'docker compose down -v' (DELETES ALL
       DATA) and run the installer again."
    fi
    printf 'DB_ROOT_PASSWORD=%s\nDB_PASSWORD=%s\nGATESHIFT_SECRET_KEY=%s\n' \
        "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" \
        "$(openssl rand -base64 32 | tr '+/' '-_')" > .env
    echo "generated .env with random credentials"
fi

# The TLS certificate: self-signed, with this host's names and addresses;
# kept once it exists, replaced on --renew-cert. Your own CA's files go
# into certs/ at any time (docs: OPERATING.md).
if [ "$RENEW_CERT" -eq 1 ]; then
    ./make-cert.sh --force
else
    ./make-cert.sh
fi

# --build: an image from an earlier installation of this directory would
# otherwise be reused and the freshly cloned code never run (found on the
# 0.9.3 re-install test, 2026-10-07). With nothing changed the build is a
# cache hit and costs seconds.
docker compose up -d --build

ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$ADDR" ] || ADDR="<this server's address>"
echo
echo "Gateshift is starting: the first boot builds images and initializes"
echo "the database, which takes a few minutes."
echo "UI: https://$ADDR/   (the browser warns once about the self-signed"
echo "    certificate. The first visit sets the admin password)"
