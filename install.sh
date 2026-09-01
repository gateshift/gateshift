#!/usr/bin/env bash
# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
#
# Gateshift installer: checks the prerequisites, generates a .env with
# strong random credentials (never overwriting an existing one) and starts
# the stack. Safe to run again - an existing installation is simply
# restarted with its current settings.
#
#   ./install.sh                  UI on http://127.0.0.1:8080 (loopback only)
#   ./install.sh --bind 0.0.0.0   reachable from the network - the UI has no
#                                 authentication of its own, so do this only
#                                 behind a reverse proxy or on a trusted
#                                 management network

set -euo pipefail
cd "$(dirname "$0")"

BIND=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bind) BIND="${2:?--bind needs an address}"; shift 2 ;;
        *) echo "unknown option: $1 (supported: --bind <address>)" >&2; exit 2 ;;
    esac
done

fail() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 \
    || fail "docker is not installed - see https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 \
    || fail "cannot talk to the Docker daemon - is it running, and may your user use it?"
docker compose version >/dev/null 2>&1 \
    || fail "the Docker Compose plugin (v2) is missing - see https://docs.docker.com/compose/install/"
command -v openssl >/dev/null 2>&1 \
    || fail "openssl is required to generate credentials"

# The syslog receiver publishes UDP 514; a host syslog daemon already bound
# there makes the stack fail late, so say it early. Warning only - the port
# may legitimately be free by the time the container starts.
if command -v ss >/dev/null 2>&1 && ss -uln 2>/dev/null | grep -q ':514 '; then
    echo "WARNING: something on this host already listens on UDP 514;"
    echo "         the syslog container will fail to start until it is freed."
fi

if [ -f .env ]; then
    echo "keeping existing .env"
    if [ -n "$BIND" ]; then
        if grep -q '^WEBUI_BIND=' .env; then
            sed -i "s/^WEBUI_BIND=.*/WEBUI_BIND=$BIND/" .env
        else
            printf 'WEBUI_BIND=%s\n' "$BIND" >> .env
        fi
        echo "set WEBUI_BIND=$BIND"
    fi
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
    if [ -n "$BIND" ]; then
        printf 'WEBUI_BIND=%s\n' "$BIND" >> .env
    fi
    echo "generated .env with random credentials"
fi

docker compose up -d

echo
echo "Gateshift is starting - the first boot builds images and initializes"
echo "the database, which takes a few minutes."
if [ -z "$BIND" ] || [ "$BIND" = "127.0.0.1" ]; then
    echo "UI: http://127.0.0.1:8080"
else
    echo "UI: http://<this server's address>:8080 (bound to $BIND)"
fi
