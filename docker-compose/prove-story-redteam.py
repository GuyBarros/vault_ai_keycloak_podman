#!/usr/bin/env python3
"""Red-team the demo story: Vault + SPIFFE is the authorization layer
for the agentic ecosystem. Prints HOLD / KILL / NOTE per angle."""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8081"
VAULT = "http://localhost:8200"
TE = "http://localhost:9091"
CLIENT_ID = "token-exchange"
CLIENT_SECRET = "token-exchange-secret"

holds = kills = notes = 0


def hdr(title: str) -> None:
    print(f"\n=== {title} ===")


def hold(msg: str) -> None:
    global holds
    holds += 1
    print(f"HOLD  {msg}")


def kill(msg: str) -> None:
    global kills
    kills += 1
    print(f"KILL  {msg}")


def note(msg: str) -> None:
    global notes
    notes += 1
    print(f"NOTE  {msg}")


def http_json(method: str, url: str, data=None, headers=None, timeout=15):
    body = None
    hdrs = dict(headers or {})
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(data, bytes):
            body = data
        else:
            body = str(data).encode()
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            parsed = json.loads(raw) if raw else {}
            return resp.status, parsed, raw.decode("utf-8", "replace")[:400]
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {}
        return exc.code, parsed, raw.decode("utf-8", "replace")[:400]


def form_post(url: str, fields: dict[str, str]):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode("utf-8", "replace")[:400]}
        return exc.code, parsed


def kc_token(user: str, password: str, scope: str) -> str:
    status, body = form_post(
        f"{KC}/realms/demo/protocol/openid-connect/token",
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "password",
            "username": user,
            "password": password,
            "scope": scope,
        },
    )
    if status != 200 or "access_token" not in body:
        raise SystemExit(f"Keycloak token failed user={user} scope={scope}: {status} {body}")
    return body["access_token"]


def vault_login(path: str, role: str, jwt: str):
    return http_json(
        "POST",
        f"{VAULT}/v1/auth/{path}/login",
        {"role": role, "jwt": jwt},
    )


def vault_get(path: str, token: str):
    return http_json("GET", f"{VAULT}/v1/{path}", headers={"X-Vault-Token": token})


def docker(*args: str) -> str:
    r = subprocess.run(
        ["docker", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    return r.stdout.strip()


def vault_login_mcp(role: str, jwt: str, path: str = "jwt-keycloak"):
    """Login to Vault from inside user-mcp (the CIDR Vault binds tokens to)."""
    code = r"""
import json, os, urllib.error, urllib.request, sys
payload = json.dumps({"role": os.environ["V_ROLE"], "jwt": os.environ["V_JWT"]}).encode()
req = urllib.request.Request(
    "http://vault:8200/v1/auth/%s/login" % os.environ["V_PATH"],
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        print(json.dumps({"status": resp.status, "body": json.loads(raw) if raw else {}}))
except urllib.error.HTTPError as exc:
    raw = exc.read()
    try:
        body = json.loads(raw) if raw else {}
    except Exception:
        body = {}
    print(json.dumps({"status": exc.code, "body": body}))
"""
    r = subprocess.run(
        [
            "docker",
            "exec",
            "-e",
            f"V_JWT={jwt}",
            "-e",
            f"V_ROLE={role}",
            "-e",
            f"V_PATH={path}",
            "user-mcp",
            "/app/.venv/bin/python",
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
    )
    try:
        parsed = json.loads(r.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return 0, {}, r.stdout + r.stderr
    return int(parsed.get("status") or 0), parsed.get("body") or {}, r.stdout[:400]


def vault_get_mcp(path: str, token: str):
    code = r"""
import json, os, urllib.error, urllib.request
req = urllib.request.Request(
    "http://vault:8200/v1/%s" % os.environ["V_PATH"],
    headers={"X-Vault-Token": os.environ["V_TOKEN"]},
    method="GET",
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        print(json.dumps({"status": resp.status, "body": json.loads(raw) if raw else {}}))
except urllib.error.HTTPError as exc:
    raw = exc.read()
    try:
        body = json.loads(raw) if raw else {}
    except Exception:
        body = {}
    print(json.dumps({"status": exc.code, "body": body}))
"""
    r = subprocess.run(
        [
            "docker",
            "exec",
            "-e",
            f"V_PATH={path}",
            "-e",
            f"V_TOKEN={token}",
            "user-mcp",
            "/app/.venv/bin/python",
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
    )
    try:
        parsed = json.loads(r.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return 0, {}, r.stdout + r.stderr
    return int(parsed.get("status") or 0), parsed.get("body") or {}, r.stdout[:400]


def vault_post_mcp(path: str, token: str, payload: dict):
    code = r"""
import json, os, urllib.error, urllib.request
payload = json.loads(os.environ["V_PAYLOAD"])
req = urllib.request.Request(
    "http://vault:8200/v1/%s" % os.environ["V_PATH"],
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json", "X-Vault-Token": os.environ["V_TOKEN"]},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        print(json.dumps({"status": resp.status, "body": json.loads(raw) if raw else {}}))
except urllib.error.HTTPError as exc:
    raw = exc.read()
    try:
        body = json.loads(raw) if raw else {}
    except Exception:
        body = {}
    print(json.dumps({"status": exc.code, "body": body}))
"""
    r = subprocess.run(
        [
            "docker",
            "exec",
            "-e",
            f"V_PATH={path}",
            "-e",
            f"V_TOKEN={token}",
            "-e",
            f"V_PAYLOAD={json.dumps(payload)}",
            "user-mcp",
            "/app/.venv/bin/python",
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
    )
    try:
        parsed = json.loads(r.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return 0, {}, r.stdout + r.stderr
    return int(parsed.get("status") or 0), parsed.get("body") or {}, r.stdout[:400]


def main() -> int:
    print("Red-team: Vault+SPIFFE as authorization for the agentic ecosystem")
    print("KILL = a reviewer can use this to knock the story down")
    print("HOLD = this angle does not land")
    print("NOTE = true, but defense-in-depth / demo-hygiene, not the Guy bug")

    user_read = kc_token("user", "user", "users.read")
    user_write = kc_token("user", "user", "users.write")
    admin_read = kc_token("admin", "admin", "users.read")
    admin_write = kc_token("admin", "admin", "users.write")

    hdr("1. Original Guy test: writer lists users")
    st, body, _ = vault_login_mcp("user-mcp-oidc-read", admin_read)
    if st == 200:
        hold("writer + users.read logs into oidc-read from user-mcp (list users is allowed)")
    else:
        kill(f"writer cannot list users via Vault read role from user-mcp (http {st})")

    hdr("2. Confused deputy: MCP asks write with a reader token")
    st, body, err = vault_login_mcp("user-mcp-oidc-write", user_read)
    if st in (400, 403):
        hold(f"reader token cannot assume oidc-write (http {st})")
    else:
        kill(f"reader token assumed oidc-write (http {st})")

    st, _, _ = vault_login_mcp("user-mcp-oidc-write", user_write)
    if st in (400, 403):
        hold(f"reader + Keycloak-issued users.write still denied by groups bound_claims (http {st})")
    else:
        kill(f"Keycloak will mint users.write for a reader AND Vault accepts write role (http {st})")

    hdr("3. SPIFFE-only must not mint database/creds")
    svid = docker(
        "exec",
        "-e",
        "PYTHONPATH=/app",
        "user-mcp",
        "/app/.venv/bin/python",
        "-c",
        "import asyncio\n"
        "from spiffe_client import SpiffeSvidProvider\n"
        "async def m():\n"
        "    p=SpiffeSvidProvider('/tmp/spire-agent/api.sock','TESTING')\n"
        "    s=await p.get_jwt_svid()\n"
        "    print(s.token)\n"
        "asyncio.run(m())\n",
    )
    if not svid or svid.count(".") != 2:
        kill(f"could not fetch user-mcp JWT-SVID: {svid[:200]!r}")
        svid = None
    else:
        hold("user-mcp JWT-SVID fetched (SPIFFE still works)")

    if svid:
        st, body, _ = vault_login_mcp("user-mcp-spiffe", svid, path="jwt-spiffe")
        token = (body.get("auth") or {}).get("client_token")
        if st != 200 or not token:
            kill(f"workload SPIFFE role login from user-mcp failed http {st}")
        else:
            hold("user-mcp SPIFFE workload login succeeds from the workload CIDR")
            for path in (
                "database/creds/user-mcp-read-role",
                "database/creds/user-mcp-write-role",
            ):
                cr, _, _ = vault_get_mcp(path, token)
                if cr == 200:
                    kill(f"SPIFFE role user-mcp-spiffe minted {path}")
                else:
                    hold(f"SPIFFE role user-mcp-spiffe cannot read {path} (http {cr})")

        st, body, _ = vault_login_mcp("user-mcp-spiffe-transform", svid, path="jwt-spiffe")
        token = (body.get("auth") or {}).get("client_token")
        if st == 200 and token:
            cr, _, _ = vault_get_mcp("database/creds/user-mcp-read-role", token)
            if cr == 200:
                kill("SPIFFE transform role minted read DB creds")
            else:
                hold(f"SPIFFE transform role cannot read DB creds (http {cr})")
            tr, _, _ = vault_post_mcp(
                "transform/encode/user-mcp-transform",
                token,
                {"value": "123-45-6789", "transformation": "mask-ssn"},
            )
            if tr == 200:
                kill("SPIFFE transform role encoded PII without the combined action token")
            else:
                hold(f"SPIFFE transform role cannot encode (http {tr})")
        else:
            note(f"transform SPIFFE login from user-mcp http {st}")

        for role in ("user-mcp-spiffe-read", "user-mcp-spiffe-write"):
            st, _, _ = vault_login_mcp(role, svid, path="jwt-spiffe")
            if st in (400, 403, 404):
                hold(f"legacy SPIFFE DB role {role} is gone (http {st})")
            else:
                kill(f"legacy SPIFFE role {role} still logs in (http {st})")

        st, _, _ = vault_login_mcp("ai-agent-spiffe", svid, path="jwt-spiffe")
        if st in (400, 403):
            hold(f"ai-agent-spiffe rejects user-mcp SVID (bound_subject) http {st}")
        else:
            note(f"ai-agent-spiffe with user-mcp SVID http {st}")

        st, _, _ = vault_login("jwt-spiffe", "user-mcp-spiffe", svid)
        if st in (400, 403):
            hold(f"stolen SVID cannot login jwt-spiffe from the host (http {st})")
        else:
            kill(f"stolen SVID logged into jwt-spiffe from the host (http {st})")

    hdr("4. Stolen OBO from a laptop: jwt-keycloak without SPIFFE")
    st, body, _ = vault_login("jwt-keycloak", "user-mcp-oidc-read", user_read)
    token = (body.get("auth") or {}).get("client_token")
    if st in (400, 403) or not token:
        hold(f"host curl to :8200 with a user JWT is denied at login (http {st})")
    else:
        cr, creds, _ = vault_get("database/creds/user-mcp-read-role", token)
        if cr == 200 and (creds.get("data") or {}).get("username"):
            kill(
                "host curl to :8200 with a user JWT (no SPIFFE) receives "
                f"dynamic DB creds as {(creds.get('data') or {}).get('username')}"
            )
        else:
            hold(f"OBO-only login from host ok but DB creds denied (http {cr})")

    st, body, _ = vault_login_mcp("user-mcp-oidc-read", user_read)
    token = (body.get("auth") or {}).get("client_token")
    if st == 200 and token:
        cr, _, _ = vault_get_mcp("database/creds/user-mcp-read-role", token)
        if cr == 200:
            kill("human jwt-keycloak login token minted DB creds; only the combined action token should")
        else:
            hold(f"human jwt-keycloak login token cannot read database/creds (http {cr})")
        st2, minted, _ = vault_post_mcp(
            "auth/token/create/user-mcp-action-read",
            token,
            {
                "display_name": "user+user-mcp",
                "meta": {
                    "preferred_username": "user",
                    "spiffe_id": "spiffe://example.org/user-mcp",
                },
                "ttl": "60s",
                "renewable": False,
            },
        )
        action = (minted.get("auth") or {}).get("client_token")
        if st2 == 200 and action:
            hold("Vault minted combined user+user-mcp action token")
            cr, creds, _ = vault_get_mcp("database/creds/user-mcp-read-role", action)
            if cr == 200:
                hold("combined action token mints read DB creds")
            else:
                kill(f"combined action token cannot mint read DB creds (http {cr})")
        else:
            kill(f"Vault did not mint combined action token (http {st2})")
    else:
        kill(f"user-mcp OIDC read login failed (http {st})")

    hdr("5. Vault root / Postgres static (demo hygiene)")
    st, creds, _ = vault_get("database/creds/user-mcp-write-role", "root")
    if st == 200:
        note("VAULT_DEV_ROOT_TOKEN_ID=root on :8200 mints write DB creds (dev mode)")
    else:
        hold(f"root token cannot mint write creds (http {st})")

    pg = subprocess.run(
        [
            "docker",
            "exec",
            "postgres",
            "psql",
            "postgresql://postgres:postgres@127.0.0.1:5432/users?sslmode=disable",
            "-tAc",
            "select count(*) from users",
        ],
        capture_output=True,
        text=True,
    )
    if pg.returncode == 0:
        note(f"Postgres :5432 accepts postgres/postgres (count={pg.stdout.strip()})")
    else:
        hold("static postgres superuser is not reachable")

    hdr("6. Token-exchange PEP (not Vault)")
    actor = docker("exec", "vault-agent", "cat", "/vault/secrets/actor-token")
    if not actor:
        note("could not read actor-token; skip token-exchange checks")
    else:
        st, body, err = http_json(
            "POST",
            f"{TE}/v1/identity/obo-token",
            {
                "subject_token": user_read,
                "actor_token": actor,
                "scope": "users.write",
            },
        )
        if st in (401, 403):
            note(
                f"token-exchange denies reader→users.write in Python/Keycloak "
                f"(http {st}) — Vault never sees this request"
            )
        else:
            kill(f"token-exchange issued users.write for a reader (http {st} {err})")

        st, body, err = http_json(
            "POST",
            f"{TE}/v1/identity/obo-token",
            {
                "subject_token": user_read,
                "actor_token": actor,
                "scope": "users.read",
            },
        )
        if st == 200 and body.get("access_token"):
            hold("token-exchange issues users.read for a reader")
        else:
            note(f"token-exchange reader→users.read http {st} {err}")

    hdr("7. Keycloak password grant does not honor groups")
    st, body, _ = vault_login_mcp("user-mcp-oidc-write", user_write)
    if st in (400, 403):
        hold("Vault bound_claims catch Keycloak giving users.write to a reader")
    else:
        kill("Vault accepted write role for a readers-only user")

    hdr("8. Wrong audience / web login token")
    st, web_body = form_post(
        f"{KC}/realms/demo/protocol/openid-connect/token",
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "password",
            "username": "user",
            "password": "user",
            "scope": "openid",
        },
    )
    web_tok = web_body.get("access_token", "")
    if web_tok:
        st, _, _ = vault_login_mcp("user-mcp-oidc-read", web_tok)
        if st in (400, 403):
            hold(f"token without users.read cannot login oidc-read (http {st})")
        else:
            kill(f"openid-only token logged into oidc-read (http {st})")

    hdr("9. OPA fail-open")
    st, body, err = http_json(
        "POST",
        "http://localhost:8181/v1/data/app/security/is_injection",
        {"input": "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw=="},
    )
    if st == 200:
        note(
            "OPA is reachable; ai-agent opa_client fails OPEN if OPA is down "
            "(not a Vault/SPIFFE control)"
        )
    else:
        note(f"OPA query http {st}")

    print("\n--- tally ---")
    print(f"HOLD {holds}   KILL {kills}   NOTE {notes}")
    if kills:
        print(
            "Story does not survive a Vault-savvy reviewer until every KILL "
            "is closed at Vault, not in the app."
        )
        return 1
    print("No KILL findings in this pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
