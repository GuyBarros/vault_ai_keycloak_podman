#!/usr/bin/env python3
"""Minimal JWKS proxy server.

Fetches the SPIRE bundle endpoint, strips non-standard fields, and re-serves
only the jwt-svid keys as a standard JWKS on port 19876. Vault points its
jwks_url at this server so it can always re-fetch fresh signing keys.
"""
import json
import ssl
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

SPIRE_BUNDLE_URL = "https://spire-server:8082"
PORT = 19876


def _fetch_jwt_svid_jwks() -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(SPIRE_BUNDLE_URL, context=ctx, timeout=10) as resp:
        bundle = json.loads(resp.read())
    jwt_keys = [k for k in bundle.get("keys", []) if k.get("use") == "jwt-svid"]
    return {"keys": jwt_keys}


class JWKSHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence access log
        pass

    def do_GET(self):
        try:
            jwks = _fetch_jwt_svid_jwks()
            body = json.dumps(jwks).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            print(f"JWKS proxy error: {exc}", file=sys.stderr, flush=True)
            self.send_response(503)
            self.end_headers()


if __name__ == "__main__":
    print(f"JWKS proxy listening on :{PORT}", flush=True)
    server = HTTPServer(("0.0.0.0", PORT), JWKSHandler)
    server.serve_forever()
