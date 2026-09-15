#!/usr/bin/env python3
"""Enable Keycloak SSF transmitter + PUSH stream to the web RP (CAEP)."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

KC = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "demo")
ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
PUSH_URL = os.environ.get(
    "SSF_PUSH_URL", "http://web:8080/api/auth/ssf"
)
CAEP_SESSION_REVOKED = (
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
)
PUSH_METHOD = "urn:ietf:rfc:8935"


def _req(method: str, url: str, token: str | None = None, data: dict | None = None):
    body = None if data is None else json.dumps(data).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"text": raw.decode("utf-8", errors="replace")[:400]}
        return exc.code, parsed


def main() -> int:
    from urllib.parse import urlencode

    body = urlencode(
        {
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
            "grant_type": "password",
        }
    ).encode()
    req = urllib.request.Request(
        f"{KC}/realms/master/protocol/openid-connect/token",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        admin = json.loads(resp.read()).get("access_token") or ""
    if not admin:
        print("ssf-setup: no admin token", file=sys.stderr)
        return 1

    st, realm = _req("GET", f"{KC}/admin/realms/{REALM}", admin)
    if st != 200:
        print(f"ssf-setup: get realm {st} {realm}", file=sys.stderr)
        return 1
    attrs = dict(realm.get("attributes") or {})
    attrs["ssf.transmitterEnabled"] = "true"
    attrs["ssf.defaultSubjects"] = "ALL"
    realm["attributes"] = attrs
    st, _ = _req("PUT", f"{KC}/admin/realms/{REALM}", admin, realm)
    print(f"ssf-setup: realm transmitter {st}")

    st, clients = _req(
        "GET", f"{KC}/admin/realms/{REALM}/clients?clientId=web", admin
    )
    if st != 200 or not clients:
        print(f"ssf-setup: web client missing {st}", file=sys.stderr)
        return 1
    client = clients[0]
    cid = client.get("id")
    cattrs = dict(client.get("attributes") or {})
    cattrs["ssf.enabled"] = "true"
    cattrs["ssf.profile"] = "SSF_1_0"
    cattrs["ssf.defaultSubjects"] = "ALL"
    cattrs["ssf.validPushUrls"] = f"{PUSH_URL}##{PUSH_URL}/"
    cattrs["ssf.allowEmitEvents"] = "true"
    cattrs["ssf.supportedEvents"] = CAEP_SESSION_REVOKED
    cattrs["ssf.allowedDeliveryMethods"] = "push"
    client["attributes"] = cattrs
    st, _ = _req("PUT", f"{KC}/admin/realms/{REALM}/clients/{cid}", admin, client)
    print(f"ssf-setup: web ssf.enabled {st}")

    # Admin SSF routes take the public clientId (see Keycloak admin-ui StreamTab).
    stream_ids = ["web"]
    body = {
        "description": "web RP CAEP session-revoked",
        "events_requested": [CAEP_SESSION_REVOKED],
        "delivery": {"method": PUSH_METHOD, "endpoint_url": PUSH_URL},
    }
    created_ok = False
    last_err: object = None
    for sid in stream_ids:
        base = f"{KC}/admin/realms/{REALM}/ssf/clients/{sid}/stream"
        st, existing = _req("GET", base, admin)
        if st == 200 and existing:
            st2, patched = _req("PATCH", base, admin, body)
            print(f"ssf-setup: stream patch {sid} {st2}")
            created_ok = st2 in (200, 201, 204)
            last_err = patched
            if created_ok:
                break
        st2, created = _req("POST", base, admin, body)
        print(f"ssf-setup: stream create {sid} {st2} {created}")
        last_err = created
        if st2 in (200, 201, 204, 409):
            created_ok = True
            break
    if not created_ok:
        print(f"ssf-setup: stream failed {last_err}", file=sys.stderr)
        return 1
    print("ssf-setup: done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
