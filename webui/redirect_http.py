# Copyright (c) 2026 Timo Duttine - SPDX-License-Identifier: BUSL-1.1
"""The HTTP side of the web UI: every request is sent to HTTPS on the same
host (docs/ACCESS_DESIGN.md, L3). Runs next to uvicorn in the web
container, on the port that compose publishes as 80. Nothing is served
here - not even an error page - so the password never travels in the
clear by accident.

    python redirect_http.py --port 8080
"""
import argparse
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Redirect(BaseHTTPRequestHandler):
    server_version = "gateshift-redirect"
    sys_version = ""

    def _go(self):
        host = (self.headers.get("Host") or "localhost").strip()
        # strip a port - but not the brackets of an IPv6 literal
        if host.startswith("["):
            host = host.split("]")[0] + "]"
        elif host.count(":") == 1:
            host = host.split(":")[0]
        self.send_response(301)
        self.send_header("Location", f"https://{host}{self.path or '/'}")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _go

    def log_message(self, *_args):   # quiet - this server has nothing to say
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="redirect plain HTTP to HTTPS")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), _Redirect)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
