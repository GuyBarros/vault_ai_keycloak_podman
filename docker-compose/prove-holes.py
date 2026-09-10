#!/usr/bin/env python3
"""Extra hole-hunt for the user+user-mcp action-token story.

KILL = a reviewer can knock the pitch down with this.
HOLD = this angle does not land.
NOTE = true, but not the authorization story.
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8081"
VAULT = "http://localhost:8200"
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


def http_json(method: str, url: str, data=None, headers=None):
    body = None
    hdrs = dict(headers or {})
    if data is not None:
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {}
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
    return http_json("POST", f"{VAULT}/v1/auth/{path}/login", {"role": role, "jwt": jwt})


def vault_get(path: str, token: str):
    return http_json("GET", f"{VAULT}/v1/{path}", headers={"X-Vault-Token": token})


def vault_post(path: str, token: str, payload: dict):
    return http_json(
        "POST",
        f"{VAULT}/v1/{path}",
        payload,
        headers={"X-Vault-Token": token},
    )


def docker_py(env: dict[str, str], code: str) -> tuple[int, dict]:
    args = ["docker", "exec"]
    for k, v in env.items():
        args.extend(["-e", f"{k}={v}"])
    args.extend(["-e", "PYTHONPATH=/app", "user-mcp", "/app/.venv/bin/python", "-c", code])
    r = subprocess.run(args, capture_output=True, text=True)
    try:
        parsed = json.loads(r.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return 0, {"stdout": r.stdout, "stderr": r.stderr}
    return int(parsed.get("status") or 0), parsed


MCP_REQ = r"""
import json, os, urllib.error, urllib.request
payload = json.loads(os.environ.get("V_PAYLOAD") or "null")
headers = {}
data = None
if payload is not None:
    headers["Content-Type"] = "application/json"
    data = json.dumps(payload).encode()
if os.environ.get("V_TOKEN"):
    headers["X-Vault-Token"] = os.environ["V_TOKEN"]
req = urllib.request.Request(
    "http://vault:8200/v1/%s" % os.environ["V_PATH"],
    data=data,
    headers=headers,
    method=os.environ.get("V_METHOD", "GET"),
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


def mcp(method: str, path: str, token: str | None = None, payload=None):
    env = {"V_METHOD": method, "V_PATH": path, "V_PAYLOAD": json.dumps(payload)}
    if token:
        env["V_TOKEN"] = token
    st, parsed = docker_py(env, MCP_REQ)
    return st, parsed.get("body") or {}


def fetch_svid() -> str:
    r = subprocess.run(
        [
            "docker",
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
        ],
        capture_output=True,
        text=True,
    )
    return r.stdout.strip()


def fetch_ai_agent_svid() -> str:
    r = subprocess.run(
        ["docker", "exec", "vault-agent", "cat", "/tmp/spire-jwt/svid.jwt"],
        capture_output=True,
        text=True,
    )
    return (r.stdout or "").strip()


def mint_action(parent: str, role: str, display: str, meta: dict) -> tuple[int, str, dict]:
    st, body = mcp(
        "POST",
        f"auth/token/create/{role}",
        parent,
        {
            "display_name": display,
            "meta": meta,
            "ttl": "60s",
            "renewable": False,
        },
    )
    token = (body.get("auth") or {}).get("client_token") or ""
    return st, token, body


def wrap_info(body: dict) -> tuple[str, str]:
    wrap = body.get("wrap_info") or body.get("data") or {}
    return wrap.get("token") or "", wrap.get("accessor") or ""


def mint_action_with_spiffe(
    obo_jwt: str,
    oidc_role: str,
    action_role: str,
    display: str,
    meta: dict,
    svid: str,
) -> tuple[str, str]:
    """Return ('ok', action_token) or ('fail', reason)."""
    st, body = mcp(
        "POST",
        "auth/jwt-spiffe/login",
        payload={"role": "user-mcp-spiffe", "jwt": svid},
    )
    spiffe_tok = (body.get("auth") or {}).get("client_token") or ""
    if st != 200 or not spiffe_tok:
        return "fail", f"spiffe login http {st}"
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": oidc_role, "jwt": obo_jwt},
    )
    parent = (body.get("auth") or {}).get("client_token") or ""
    if st != 200 or not parent:
        return "fail", f"oidc login http {st}"
    st, token, body = mint_action(parent, action_role, display, meta)
    if token:
        return "direct", token
    wrapping, accessor = wrap_info(body)
    if not wrapping or not accessor:
        return "fail", f"create http {st} no wrap_info"
    ast, abody = mcp(
        "POST",
        "sys/control-group/authorize",
        spiffe_tok,
        {"accessor": accessor},
    )
    if ast >= 400:
        alt = (body.get("wrap_info") or {}).get("wrapped_accessor") or ""
        if alt and alt != accessor:
            ast, abody = mcp(
                "POST",
                "sys/control-group/authorize",
                spiffe_tok,
                {"accessor": alt},
            )
        if ast >= 400:
            err = (abody.get("errors") or [abody])[:1]
            return "fail", f"authorize http {ast} {err}"
    ust, ubody = mcp("POST", "sys/wrapping/unwrap", wrapping, None)
    action = (ubody.get("auth") or {}).get("client_token") or ""
    if ust != 200 or not action:
        err = (ubody.get("errors") or [ubody])[:1]
        return "fail", f"unwrap http {ust} {err}"
    return "ok", action


def main() -> int:
    user_read = kc_token("user", "user", "users.read")
    admin_read = kc_token("admin", "admin", "users.read")
    admin_write = kc_token("admin", "admin", "users.write")
    svid = fetch_svid()
    if svid.count(".") != 2:
        raise SystemExit(f"SVID fetch failed: {svid[:200]!r}")

    hdr("H1. SPIFFE token cannot mint the action identity")
    st, body = mcp("POST", "auth/jwt-spiffe/login", payload={"role": "user-mcp-spiffe", "jwt": svid})
    spiffe_tok = (body.get("auth") or {}).get("client_token")
    if st != 200 or not spiffe_tok:
        kill(f"SPIFFE login from user-mcp failed http {st}")
    else:
        st, token, _ = mint_action(
            spiffe_tok,
            "user-mcp-action-read",
            "spiffe+user-mcp",
            {"preferred_username": "nobody", "spiffe_id": "spiffe://example.org/user-mcp"},
        )
        if st in (400, 403) or not token:
            hold(f"SPIFFE token cannot mint action-read (http {st})")
        else:
            kill("SPIFFE-only token minted the action identity (Guy's bug via token role)")

    hdr("H2. Vault AND: action token without a SPIFFE login")
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": "user-mcp-oidc-read", "jwt": user_read},
    )
    obo_tok = (body.get("auth") or {}).get("client_token")
    if st != 200 or not obo_tok:
        kill(f"oidc-read login failed http {st}")
        obo_tok = ""
    else:
        st, action, body = mint_action(
            obo_tok,
            "user-mcp-action-read",
            "user+user-mcp",
            {"preferred_username": "user", "spiffe_id": "spiffe://forged.example/not-user-mcp"},
        )
        if action:
            cr, _ = mcp("GET", "database/creds/user-mcp-read-role", action)
            if cr == 200:
                kill(
                    "jwt-keycloak login minted the action token and DB creds "
                    "with no SPIFFE approval — Vault did not AND user+agent"
                )
            else:
                hold(f"direct action token minted without SPIFFE but creds denied (http {cr})")
        else:
            wrapping, accessor = wrap_info(body)
            if wrapping and accessor:
                hold("human JWT alone got a control-group wrap, not an action token")
                cr, _ = mcp("GET", "database/creds/user-mcp-read-role", wrapping)
                if cr == 200:
                    kill("wrapping token itself minted DB creds")
                else:
                    hold(f"wrapping token cannot read database/creds (http {cr})")
                ust, _ = mcp("POST", "sys/wrapping/unwrap", wrapping, None)
                if ust == 200:
                    kill("unwrap succeeded without SPIFFE control-group authorize")
                else:
                    hold(f"unwrap without SPIFFE authorize denied (http {ust})")
            else:
                hold(f"action mint without SPIFFE denied (http {st})")

        status, token = mint_action_with_spiffe(
            user_read,
            "user-mcp-oidc-read",
            "user-mcp-action-read",
            "user+user-mcp",
            {"preferred_username": "user", "spiffe_id": "spiffe://forged.example/not-user-mcp"},
            svid,
        )
        if status == "direct":
            kill("control group did not activate; action token issued without SPIFFE approve")
        elif status == "ok":
            cr, _ = mcp("GET", "database/creds/user-mcp-read-role", token)
            if cr == 200:
                hold("human JWT + SPIFFE authorize unwraps the action token and mints read creds")
            else:
                kill(f"AND path minted action token but creds denied (http {cr})")
        else:
            kill(f"human+SPIFFE AND path failed: {token}")

    hdr("H3. Stolen action token from the host (CIDR)")
    status, action = mint_action_with_spiffe(
        user_read,
        "user-mcp-oidc-read",
        "user-mcp-action-read",
        "user+user-mcp",
        {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
        svid,
    )
    if status != "ok":
        kill(f"could not mint action token to test host reuse: {action}")
    else:
        cr, _ = vault_get("database/creds/user-mcp-read-role", action)
        if cr == 200:
            kill("stolen action token used from the host received database/creds")
        else:
            hold(f"stolen action token from the host cannot read database/creds (http {cr})")
        tr, _ = vault_post(
            "transform/encode/user-mcp-transform",
            action,
            {"value": "123-45-6789", "transformation": "mask-ssn"},
        )
        if tr == 200:
            kill("stolen action token from the host encoded PII")
        else:
            hold(f"stolen action token from the host cannot Transform (http {tr})")

    hdr("H4. Read action token cannot mint write DB creds")
    status, action = mint_action_with_spiffe(
        admin_read,
        "user-mcp-oidc-read",
        "user-mcp-action-read",
        "admin+user-mcp",
        {"preferred_username": "admin", "spiffe_id": "spiffe://example.org/user-mcp"},
        svid,
    )
    if status == "ok":
        cr, _ = mcp("GET", "database/creds/user-mcp-write-role", action)
        if cr == 200:
            kill("read action token minted write DB creds")
        else:
            hold(f"read action token cannot read write creds (http {cr})")
        cr, _ = mcp("GET", "database/creds/user-mcp-read-role", action)
        if cr == 200:
            hold("read action token still mints read DB creds")
        else:
            kill(f"read action token lost read creds (http {cr})")
        tr, body = mcp(
            "POST",
            "transform/encode/user-mcp-transform",
            action,
            {"value": "123-45-6789", "transformation": "mask-ssn"},
        )
        if tr == 200 and (body.get("data") or {}).get("encoded_value"):
            hold("read action token can Transform (expected; masking is on the action identity)")
        else:
            kill(f"read action token cannot Transform (http {tr})")
    else:
        kill(f"writer oidc-read could not mint action-read: {action}")

    hdr("H5. Write action token: write creds yes, read creds no")
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": "user-mcp-oidc-write", "jwt": admin_write},
    )
    parent = (body.get("auth") or {}).get("client_token")
    if st != 200 or not parent:
        kill(f"writer oidc-write login failed http {st}")
    else:
        cr, _ = mcp("GET", "database/creds/user-mcp-write-role", parent)
        if cr == 200:
            kill("human jwt-keycloak write login minted write DB creds")
        else:
            hold(f"human write login cannot read write creds (http {cr})")
        status, action = mint_action_with_spiffe(
            admin_write,
            "user-mcp-oidc-write",
            "user-mcp-action-write",
            "admin+user-mcp",
            {"preferred_username": "admin", "spiffe_id": "spiffe://example.org/user-mcp"},
            svid,
        )
        if status == "ok":
            hold("writer minted action-write via SPIFFE control group")
            cr, _ = mcp("GET", "database/creds/user-mcp-write-role", action)
            if cr == 200:
                hold("write action token mints write DB creds")
            else:
                kill(f"write action token cannot mint write creds (http {cr})")
            cr, _ = mcp("GET", "database/creds/user-mcp-read-role", action)
            if cr == 200:
                kill("write action token also minted read DB creds")
            else:
                hold(f"write action token cannot read read-creds (http {cr})")
        else:
            kill(f"writer could not mint action-write: {action}")

    hdr("H6. Reader cannot mint action-write")
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": "user-mcp-oidc-read", "jwt": user_read},
    )
    parent = (body.get("auth") or {}).get("client_token")
    st, token, body = mint_action(
        parent,
        "user-mcp-action-write",
        "user+user-mcp",
        {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
    )
    wrapping, _acc = wrap_info(body)
    if token or wrapping:
        kill("reader started an action-write mint (confused deputy on the token role)")
    elif st in (400, 403):
        hold(f"reader oidc-read cannot mint action-write (http {st})")
    else:
        hold(f"reader oidc-read cannot mint action-write (http {st})")

    hdr("H7. OIDC login cannot Transform")
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": "user-mcp-oidc-read", "jwt": user_read},
    )
    parent = (body.get("auth") or {}).get("client_token")
    tr, _ = mcp(
        "POST",
        "transform/encode/user-mcp-transform",
        parent,
        {"value": "123-45-6789", "transformation": "mask-ssn"},
    )
    if tr == 200:
        kill("human jwt-keycloak login encoded PII")
    else:
        hold(f"human jwt-keycloak login cannot Transform (http {tr})")

    hdr("H8. Action token cannot mint a sibling action token")
    status, action = mint_action_with_spiffe(
        user_read,
        "user-mcp-oidc-read",
        "user-mcp-action-read",
        "user+user-mcp",
        {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
        svid,
    )
    if status == "ok":
        st2, child, _ = mint_action(
            action,
            "user-mcp-action-read",
            "escalated",
            {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
        )
        if st2 == 200 and child:
            kill("action token minted another action token (policy recursion)")
        else:
            hold(f"action token cannot mint another action token (http {st2})")
    else:
        kill(f"could not mint action token to test sibling mint: {action}")

    hdr("H9. Host cannot login oidc-write (CIDR)")
    st, body = vault_login("jwt-keycloak", "user-mcp-oidc-write", admin_write)
    if st in (400, 403):
        hold(f"host cannot login oidc-write (http {st})")
    else:
        kill(f"host logged into oidc-write (http {st})")

    hdr("H10. Human JWT cannot authorize its own wrap (Vault AND)")
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": "user-mcp-oidc-read", "jwt": user_read},
    )
    parent = (body.get("auth") or {}).get("client_token")
    st, action, body = mint_action(
        parent,
        "user-mcp-action-read",
        "user+user-mcp",
        {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
    )
    wrapping, accessor = wrap_info(body)
    if action:
        kill("human JWT minted action token without wrap (control group off)")
    elif not wrapping or not accessor:
        kill(f"human JWT mint did not wrap (http {st})")
    else:
        ast, abody = mcp(
            "POST",
            "sys/control-group/authorize",
            parent,
            {"accessor": accessor},
        )
        if ast < 400:
            kill("human JWT authorized its own control-group request")
        else:
            hold(f"human JWT cannot authorize the wrap (http {ast})")
        ust, _ = mcp("POST", "sys/wrapping/unwrap", wrapping, None)
        if ust == 200:
            kill("unwrap succeeded after human self-authorize attempt")
        else:
            hold(f"wrap still sealed after human authorize attempt (http {ust})")

    hdr("H11. Stolen wrapping token from the host cannot unwrap")
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": "user-mcp-oidc-read", "jwt": user_read},
    )
    parent = (body.get("auth") or {}).get("client_token")
    _, action, body = mint_action(
        parent,
        "user-mcp-action-read",
        "user+user-mcp",
        {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
    )
    wrapping, accessor = wrap_info(body)
    if action or not wrapping:
        kill("could not obtain a wrapping token to steal")
    else:
        ust, _ = vault_post("sys/wrapping/unwrap", wrapping, {})
        if ust == 200:
            kill("stolen wrapping token unwrapped from the host without SPIFFE")
        else:
            hold(f"stolen wrapping token cannot unwrap from the host (http {ust})")

    hdr("H12. After SPIFFE authorize, action token still CIDR-bound on the host")
    status, maybe = mint_action_with_spiffe(
        user_read,
        "user-mcp-oidc-read",
        "user-mcp-action-read",
        "user+user-mcp",
        {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
        svid,
    )
    if status != "ok":
        kill(f"AND path failed while testing host CIDR after unwrap: {maybe}")
    else:
        cr, _ = vault_get("database/creds/user-mcp-read-role", maybe)
        if cr == 200:
            kill("unwrapped action token used from the host received database/creds")
        else:
            hold(f"unwrapped action token from the host cannot read creds (http {cr})")

    hdr("H13. Wrong workload: ai-agent SPIFFE cannot authorize user-mcp wrap")
    ai_svid = fetch_ai_agent_svid()
    st, body = mcp(
        "POST",
        "auth/jwt-keycloak/login",
        payload={"role": "user-mcp-oidc-read", "jwt": user_read},
    )
    parent = (body.get("auth") or {}).get("client_token")
    _, action, body = mint_action(
        parent,
        "user-mcp-action-read",
        "user+user-mcp",
        {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
    )
    wrapping, accessor = wrap_info(body)
    if action or not accessor:
        kill("could not wrap a mint to test wrong-workload authorize")
    elif not ai_svid or ai_svid.count(".") != 2:
        note(f"could not read ai-agent SVID ({(ai_svid or '')[:80]!r}); skip wrong-workload")
    else:
        via = "host"
        st, body = vault_login("jwt-spiffe", "ai-agent-spiffe", ai_svid)
        ai_tok = (body.get("auth") or {}).get("client_token")
        if st != 200 or not ai_tok:
            via = "mcp"
            st, body = mcp(
                "POST",
                "auth/jwt-spiffe/login",
                payload={"role": "ai-agent-spiffe", "jwt": ai_svid},
            )
            ai_tok = (body.get("auth") or {}).get("client_token")
        if not ai_tok:
            note(f"ai-agent SPIFFE login failed (http {st}); skip wrong-workload")
        else:
            if via == "host":
                ast, _ = vault_post(
                    "sys/control-group/authorize",
                    ai_tok,
                    {"accessor": accessor},
                )
            else:
                ast, _ = mcp(
                    "POST",
                    "sys/control-group/authorize",
                    ai_tok,
                    {"accessor": accessor},
                )
            if ast < 400:
                kill("ai-agent SPIFFE authorized a user-mcp action-token wrap")
            else:
                hold(f"ai-agent SPIFFE cannot authorize user-mcp wrap (http {ast})")

    hdr("H14. SPIFFE token still has no secrets after authorize")
    st, body = mcp(
        "POST",
        "auth/jwt-spiffe/login",
        payload={"role": "user-mcp-spiffe", "jwt": svid},
    )
    spiffe_tok = (body.get("auth") or {}).get("client_token")
    cr, _ = mcp("GET", "database/creds/user-mcp-read-role", spiffe_tok)
    if cr == 200:
        kill("SPIFFE token minted DB creds after the control-group path existed")
    else:
        hold(f"SPIFFE token still cannot read database/creds (http {cr})")
    ast, _ = mcp(
        "POST",
        "sys/control-group/authorize",
        spiffe_tok,
        {"accessor": "00000000-0000-0000-0000-000000000000"},
    )
    if ast == 200:
        kill("SPIFFE authorize accepted a forged accessor")
    else:
        hold(f"SPIFFE authorize rejects a forged accessor (http {ast})")

    print("\n--- tally ---")
    print(f"HOLD {holds}   KILL {kills}   NOTE {notes}")
    return 1 if kills else 0


if __name__ == "__main__":
    sys.exit(main())
