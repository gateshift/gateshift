#!/bin/sh
# Copyright (c) 2026 Timo Duttine - SPDX-License-Identifier: BUSL-1.1
#
# Web container entry (docs/ACCESS_DESIGN.md, L3): builds the stylesheet,
# then serves HTTPS on 8443 from the certificate mounted at /certs and
# answers plain HTTP on 8080 with a redirect to HTTPS. Compose publishes
# the two as 443 and 80. Extra arguments go to uvicorn (the development
# compose passes --reload).
set -e
tailwindcss -c tailwind.config.js -i ./styles/input.css -o ./static/app.css --minify
if [ ! -f /certs/gateshift.crt ] || [ ! -f /certs/gateshift.key ]; then
    echo "ERROR: no TLS certificate under ./certs - run ./make-cert.sh (install.sh does it)," >&2
    echo "       or put your own gateshift.crt and gateshift.key there, then start again." >&2
    exit 1
fi
python redirect_http.py --port 8080 &
exec uvicorn main:app --host 0.0.0.0 --port 8443 \
    --ssl-certfile /certs/gateshift.crt --ssl-keyfile /certs/gateshift.key "$@"
