#!/usr/bin/env bash
# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
#
# Self-signed TLS certificate for the Gateshift web UI (see docs/OPERATING.md).
#
#   ./make-cert.sh            writes certs/gateshift.key and certs/gateshift.crt
#                             unless both exist (install.sh calls this)
#   ./make-cert.sh --force    replaces them - a renewal, or new host names
#
# The certificate carries localhost and this host's names and addresses, so
# the browser warns once about the unknown issuer and is otherwise content.
# To use a certificate from your own CA, put its certificate and key into
# the two files at any time and restart the stack (docker compose up -d).

set -euo pipefail
cd "$(dirname "$0")"

FORCE=0
case "${1:-}" in
    "") ;;
    --force) FORCE=1 ;;
    *) echo "unknown option: $1 (supported: --force)" >&2; exit 2 ;;
esac

mkdir -p certs
if [ "$FORCE" -eq 0 ] && [ -f certs/gateshift.crt ] && [ -f certs/gateshift.key ]; then
    echo "keeping existing certificate certs/gateshift.crt (./make-cert.sh --force renews it)"
    exit 0
fi
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl is required to create the certificate" >&2; exit 1; }

# Subject alternative names: localhost, the host's names, every address it has.
SAN="DNS:localhost,IP:127.0.0.1"
for n in "$(hostname 2>/dev/null || true)" "$(hostname -f 2>/dev/null || true)"; do
    [ -z "$n" ] && continue
    [ "$n" = "localhost" ] && continue
    case ",$SAN," in *",DNS:$n,"*) ;; *) SAN="$SAN,DNS:$n" ;; esac
done
for ip in $(hostname -I 2>/dev/null || true); do
    case ",$SAN," in *",IP:$ip,"*) ;; *) SAN="$SAN,IP:$ip" ;; esac
done

umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout certs/gateshift.key -out certs/gateshift.crt \
    -subj "/CN=gateshift" \
    -addext "subjectAltName=$SAN" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
chmod 644 certs/gateshift.crt
chmod 600 certs/gateshift.key
echo "certificate written: certs/gateshift.crt, valid 825 days, names: $SAN"
