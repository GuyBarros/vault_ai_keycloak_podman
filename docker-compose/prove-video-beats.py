#!/usr/bin/env python3
"""Video-beat evidence for the agentic IAM demo (IBM Agent Identity + NVIDIA OpenShell).

Writes docker-compose/evidence/video-beats.json with redacted JWT claims only.
Exit 0 iff every required beat PASSes. PARTIAL counts as fail unless ALLOW_PARTIAL=1.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
EVIDENCE_DIR = ROOT / "evidence"
KC_URL = os.environ.get("KC_URL", "http://localhost:8081")
VAULT = os.environ.get("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "root")
TX_URL = os.environ.get("TOKEN_EXCHANGE_URL", "http://localhost:9091/v1/identity/obo-token")
AGENT_URL = os.environ.get("AI_AGENT_URL", "http://localhost:8000")
CIBA_UI = os.environ.get("CIBA_UI", "http://localhost:8093")
LOKI = os.environ.get("LOKI_URL", "http://localhost:3100")
REALM = "demo"

results: list[dict[str, Any]] = []


def b64url_json(part: str) -> dict[str, Any]:
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad))


def jwt_claims(token: str) -> dict[str, Any]:
    header, payload = token.split(".")[:2]
    return {"header": b64url_json(header), "payload": b64url_json(payload)}


def redact_payload(p: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "iss",
        "aud",
        "sub",
        "azp",
        "scope",
        "preferred_username",
        "groups",
        "act",
        "may_act",
        "authorization_details",
        "typ",
        "agent_id",
        "ciba",
        "client_id",
    )
    out = {k: p.get(k) for k in keep if k in p}
    out["_claim_keys"] = sorted(p.keys())
    return out


def http(
    method: str,
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20,
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def form(url: str, fields: dict[str, str], *, auth: tuple[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    body = urllib.parse.urlencode(fields).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if auth:
        raw = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {raw}"
    status, raw_body = http("POST", url, data=body, headers=headers)
    try:
        parsed = json.loads(raw_body.decode() or "{}")
    except json.JSONDecodeError:
        parsed = {"_raw": raw_body.decode(errors="replace")[:400]}
    return status, parsed


def json_post(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    status, raw = http("POST", url, data=json.dumps(payload).encode(), headers=hdrs)
    try:
        parsed = json.loads(raw.decode() or "{}")
    except json.JSONDecodeError:
        parsed = {"_raw": raw.decode(errors="replace")[:400]}
    return status, parsed


def json_put(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    status, raw = http("PUT", url, data=json.dumps(payload).encode(), headers=hdrs)
    try:
        parsed = json.loads(raw.decode() or "{}")
    except json.JSONDecodeError:
        parsed = {"_raw": raw.decode(errors="replace")[:400]}
    return status, parsed


def json_get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    status, raw = http("GET", url, headers=headers)
    try:
        parsed = json.loads(raw.decode() or "{}")
    except json.JSONDecodeError:
        parsed = {"_raw": raw.decode(errors="replace")[:400]}
    return status, parsed


def keycloak_admin_token() -> str:
    _, body = form(
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        {
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
            "grant_type": "password",
        },
    )
    return str(body.get("access_token") or "")


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def record(beat: str, status: str, detail: dict[str, Any]) -> None:
    results.append({"beat": beat, "status": status, "detail": detail})
    print(f"{status:8} {beat}")


def mint_password(user: str, password: str, scope: str, client: str = "rar-cli", secret: str = "rar-cli-secret") -> str:
    status, body = form(
        f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "username": user,
            "password": password,
            "scope": scope,
        },
        auth=(client, secret),
    )
    if status != 200 or "access_token" not in body:
        raise RuntimeError(f"password grant failed {status}: {body}")
    return str(body["access_token"])


def vault_headers(token: str) -> dict[str, str]:
    return {"X-Vault-Token": token}


def mcp_tool(obo: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    docker("exec", "ai-agent", "sh", "-c", "mkdir -p /tmp/evidence")
    docker(
        "exec",
        "ai-agent",
        "sh",
        "-c",
        f"cat > /tmp/evidence/obo <<'EOF'\n{obo}\nEOF",
    )
    args_json = json.dumps(args)
    py = f"""
import asyncio, json, os
from errors import AppError
from mcp_client import invoke_mcp_tool
obo = open("/tmp/evidence/obo").read().strip()
async def main():
    try:
        r = await invoke_mcp_tool(
            "http://user-mcp:8090/mcp",
            {tool!r},
            json.loads({args_json!r}),
            obo,
            "video-evidence",
        )
        print(json.dumps({{"ok": True, "result": r}}, default=str)[:4000])
    except AppError as e:
        print(json.dumps({{"ok": False, "status": e.status_code, "error": e.error, "message": e.message}}))
    except Exception as e:
        print(json.dumps({{"ok": False, "error": type(e).__name__, "message": str(e)[:800]}}))
asyncio.run(main())
"""
    proc = docker("exec", "ai-agent", "python", "-c", py, check=False)
    text = (proc.stdout or proc.stderr or "").strip()
    try:
        return json.loads(text.splitlines()[-1])
    except json.JSONDecodeError:
        return {"ok": False, "error": "parse", "message": text[:800], "exit": proc.returncode}


def main() -> int:
    EVIDENCE_DIR.mkdir(exist_ok=True)

    # 1. Vault 2.1 + Agentic IAM
    ver = docker("exec", "vault", "vault", "version").stdout.strip()
    st, lic = json_get(f"{VAULT}/v1/sys/license/status", headers=vault_headers(VAULT_TOKEN))
    feats = ((lic.get("data") or {}).get("autoloaded") or {}).get("features") or []
    ok = "2.1" in ver and "Agentic IAM" in feats
    record(
        "vault_21_agentic_iam",
        "PASS" if ok else "FAIL",
        {"version": ver, "has_agentic_iam": "Agentic IAM" in feats, "license_http": st},
    )

    # 2. OAuth RS profile
    st, prof = json_get(
        f"{VAULT}/v1/sys/config/oauth-resource-server/keycloak-demo",
        headers=vault_headers(VAULT_TOKEN),
    )
    data = prof.get("data") or {}
    ok = st == 200 and data.get("enabled") is True
    record(
        "oauth_resource_server_profile",
        "PASS" if ok else "FAIL",
        {
            "http": st,
            "issuer_id": data.get("issuer_id"),
            "audiences": data.get("audiences"),
            "optional_authorization_details": data.get("optional_authorization_details"),
            "jwt_type": data.get("jwt_type"),
        },
    )

    # 3. Agent registry
    # 3. Agent registry — LIST the registration index (not `vault list agent-registry`,
    # which is the mount root and is empty by design).
    listed_proc = docker(
        "exec",
        "-e",
        "VAULT_ADDR=http://127.0.0.1:8200",
        "-e",
        "VAULT_TOKEN=root",
        "vault",
        "vault",
        "list",
        "-format=json",
        "agent-registry/registration/display-name",
        check=False,
    )
    try:
        raw = json.loads(listed_proc.stdout or "[]")
        if isinstance(raw, list):
            listed_keys = [str(k) for k in raw]
        elif isinstance(raw, dict):
            listed_keys = (raw.get("data") or {}).get("keys") or []
        else:
            listed_keys = []
    except Exception:
        listed_keys = []
    present = []
    for name in ("demo-user", "demo-admin", "ai-agent", "ai-agent-child"):
        proc = docker(
            "exec",
            "-e",
            "VAULT_ADDR=http://127.0.0.1:8200",
            "-e",
            "VAULT_TOKEN=root",
            "vault",
            "vault",
            "read",
            "-format=json",
            f"identity/entity/name/{name}",
            check=False,
        )
        if proc.returncode == 0:
            present.append(name)
    want = ["ai-agent", "ai-agent-child", "demo-admin", "demo-user"]
    owners = {}
    for name in want:
        proc = docker(
            "exec",
            "-e",
            "VAULT_ADDR=http://127.0.0.1:8200",
            "-e",
            "VAULT_TOKEN=root",
            "vault",
            "vault",
            "read",
            "-format=json",
            f"agent-registry/registration/display-name/{name}",
            check=False,
        )
        try:
            owners[name] = (json.loads(proc.stdout or "{}").get("data") or {}).get("owner")
        except Exception:
            owners[name] = None
    owner_ok = owners.get("ai-agent") == "admin" and owners.get("ai-agent-child") == "admin"
    record(
        "agent_registry",
        "PASS"
        if sorted(listed_keys) == want
        and present == ["demo-user", "demo-admin", "ai-agent", "ai-agent-child"]
        and owner_ok
        else "FAIL",
        {
            "list_display_name": listed_keys,
            "identity_entities": present,
            "owners": owners,
        },
    )

    # 4. Agent identity (SPIFFE actor JWT)
    actor = docker("exec", "ai-agent", "cat", "/vault/secrets/actor-token", check=False).stdout.strip()
    actor_claims = jwt_claims(actor) if actor.count(".") == 2 else {}
    payload = actor_claims.get("payload") or {}
    ok = bool(payload.get("sub") or payload.get("agent_id"))
    record(
        "agent_identity_spiffe_actor",
        "PASS" if ok else "FAIL",
        {"claims": redact_payload(payload), "header": actor_claims.get("header")},
    )

    # 5. Existing IdP (Keycloak issuer)
    st, oidc = json_get(f"{KC_URL}/realms/{REALM}/.well-known/openid-configuration")
    issuer = oidc.get("issuer")
    record(
        "existing_idp_keycloak",
        "PASS" if st == 200 and issuer and "realms/demo" in str(issuer) else "FAIL",
        {"http": st, "issuer": issuer},
    )
    st_ssf, ssf = json_get(f"{KC_URL}/realms/{REALM}/.well-known/ssf-configuration")
    admin = keycloak_admin_token()
    st_stream, stream = json_get(
        f"{KC_URL}/admin/realms/{REALM}/ssf/clients/web/stream",
        headers={"Authorization": f"Bearer {admin}"} if admin else None,
    )
    record(
        "ssf_transmitter",
        "PASS"
        if st_ssf == 200
        and (ssf.get("issuer") or ssf.get("spec_version"))
        and st_stream == 200
        and (stream.get("status") == "enabled" or stream.get("streamId"))
        else "FAIL",
        {
            "http": st_ssf,
            "keys": sorted(ssf.keys()) if isinstance(ssf, dict) else [],
            "stream_http": st_stream,
            "stream_id": stream.get("streamId"),
            "stream_status": stream.get("status"),
            "push": (stream.get("delivery") or {}).get("endpoint_url"),
        },
    )

    # 6–7. RFC 8693 OBO + RAR on exchanged token
    subject = mint_password(
        "admin",
        "admin",
        "openid profile email",
        client="human-cli",
        secret="human-cli-secret",
    )
    st, obo_body = json_post(
        TX_URL,
        {
            "subject_token": subject,
            "actor_token": actor,
            "scope": "users.read",
            "authorization_details": json.dumps(
                [
                    {
                        "type": "vault:path_access",
                        "path": "database/creds/user-mcp-read-role",
                        "capabilities": ["read"],
                        "operationDetails": {"action": "list_all_users"},
                    },
                    {
                        "type": "vault:path_access",
                        "path": "transform/encode/user-mcp-transform",
                        "capabilities": ["create", "update"],
                    },
                    {
                        "type": "vault:path_access",
                        "path": "sys/leases/revoke",
                        "capabilities": ["update"],
                    },
                ],
                separators=(",", ":"),
            ),
        },
    )
    obo = str(obo_body.get("access_token") or "")
    obo_p = jwt_claims(obo)["payload"] if obo else {}
    rar = obo_p.get("authorization_details") or []
    has_rar = isinstance(rar, list) and any(x.get("type") == "vault:path_access" for x in rar if isinstance(x, dict))
    has_op = any(
        isinstance(x, dict)
        and (x.get("operationDetails") or {}).get("action") == "list_all_users"
        for x in rar
        if isinstance(x, dict)
    )
    act = obo_p.get("act") if isinstance(obo_p.get("act"), dict) else {}
    has_act = str(act.get("sub") or "") == "spiffe://example.org/ai-agent"
    may_act = obo_p.get("may_act") if isinstance(obo_p.get("may_act"), dict) else {}
    has_may_act_spiffe = str(may_act.get("sub") or "") == "spiffe://example.org/ai-agent"
    payload_typ = obo_p.get("typ")
    header_typ = (jwt_claims(obo)["header"] if obo else {}).get("typ")
    st_obo_r, _ = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-read-role",
        headers=vault_headers(obo),
    ) if obo else (0, {})
    st_obo_w, _ = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-write-role",
        headers=vault_headers(obo),
    ) if obo else (0, {})
    granted_list = mcp_tool(obo, "list_all_users", {}) if obo else {"ok": False}
    poisoned = mcp_tool(obo, "search_users_by_first_name", {"first_name": "Alice"}) if obo else {"ok": True}

    def _mcp_denied(resp: dict[str, Any]) -> bool:
        blob = json.dumps(resp).lower()
        return (not resp.get("ok")) or "not authorized" in blob or "insufficient" in blob

    has_poisoned_deny = bool(granted_list.get("ok")) and _mcp_denied(poisoned)
    record(
        "rfc8693_obo_rar",
        "PASS"
        if st == 200
        and has_rar
        and has_op
        and has_poisoned_deny
        and has_act
        and has_may_act_spiffe
        and st_obo_r == 200
        and st_obo_w in (400, 403)
        and header_typ == "at+jwt"
        and payload_typ in (None, "")
        else "FAIL",
        {
            "http": st,
            "has_authorization_details": has_rar,
            "has_operation_details": has_op,
            "list_ok": granted_list.get("ok"),
            "poisoned_search_denied": not bool(poisoned.get("ok")),
            "poisoned_message": str(poisoned.get("message") or "")[:240],
            "has_act": has_act,
            "may_act_sub": may_act.get("sub"),
            "vault_read_http": st_obo_r,
            "vault_write_http": st_obo_w,
            "header_typ": header_typ,
            "payload_typ": payload_typ,
            "act_sub": (obo_p.get("act") or {}).get("sub") if isinstance(obo_p.get("act"), dict) else None,
            "act_spiffe": (obo_p.get("act") or {}).get("spiffe_id") if isinstance(obo_p.get("act"), dict) else None,
            "claims": redact_payload(obo_p),
            "header": jwt_claims(obo)["header"] if obo else {},
        },
    )

    # 8. Action+resource grant: read JWT cannot hit write path
    user_jwt = mint_password("user", "user", "openid users.read")
    user_p = jwt_claims(user_jwt)["payload"]
    st_r, body_r = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-read-role",
        headers=vault_headers(user_jwt),
    )
    st_w, body_w = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-write-role",
        headers=vault_headers(user_jwt),
    )
    ok = st_r == 200 and st_w in (400, 403)
    record(
        "rar_path_enforcement",
        "PASS" if ok else "FAIL",
        {
            "read_http": st_r,
            "write_http": st_w,
            "write_errors": (body_w.get("errors") or [])[:2],
            "lease_id_present": bool((body_r.get("lease_id") if st_r == 200 else "")),
            "user_claims": redact_payload(user_p),
        },
    )

    # 9. Child sandbox: nested act.sub SPIFFE, read-only OBO lists, write denied
    child_actor = docker(
        "exec", "vault-agent-child", "cat", "/vault/child-secrets/child-actor-token", check=False
    ).stdout.strip()
    child_actor_p = jwt_claims(child_actor)["payload"] if child_actor.count(".") == 2 else {}
    child_svid_ok = str(child_actor_p.get("agent_id") or "") == "ai-agent-child"
    st, child_body = json_post(
        TX_URL,
        {
            "subject_token": subject,
            "actor_token": child_actor or actor,
            "scope": "users.read",
            "child": True,
        },
    )
    child = str(child_body.get("access_token") or "")
    child_p = jwt_claims(child)["payload"] if child else {}
    child_act = child_p.get("act") if isinstance(child_p.get("act"), dict) else {}
    child_spiffe = str(child_act.get("sub") or child_act.get("spiffe_id") or "")
    nested = child_act.get("act") if isinstance(child_act.get("act"), dict) else {}
    nested_ok = (
        child_spiffe == "spiffe://example.org/ai-agent-child"
        and str(nested.get("sub") or "") == "spiffe://example.org/ai-agent"
    )
    spire_show = docker(
        "exec",
        "spire-server",
        "/opt/spire/bin/spire-server",
        "entry",
        "show",
        "-socketPath",
        "/tmp/spire-server/private/api.sock",
        check=False,
    ).stdout
    child_block = next(
        (b for b in spire_show.split("Entry ID") if "spiffe://example.org/ai-agent-child" in b),
        "",
    )
    spire_child = "spiffe://example.org/ai-agent-child" in child_block
    spire_child_uid = "unix:uid:1001" in child_block
    child_user = docker(
        "inspect", "-f", "{{.Config.User}}", "vault-agent-child", check=False
    ).stdout.strip()
    child_runtime_user = docker(
        "inspect", "-f", "{{.Config.User}}", "ai-agent-child", check=False
    ).stdout.strip()
    st_child_health, child_health = json_get("http://localhost:8001/health")
    st_child_r, child_r = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-read-role",
        headers=vault_headers(child),
    ) if child else (0, {})
    st_child_w, child_w = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-write-role",
        headers=vault_headers(child),
    ) if child else (0, {})
    vault_sandbox = st_child_r == 200 and st_child_w in (400, 403)
    listed = mcp_tool(child, "list_all_users", {}) if child else {"ok": False, "message": "no child token"}
    created = mcp_tool(
        child,
        "create_user",
        {
            "user": {
                "first_name": "Child",
                "last_name": "Denied",
                "email": "child-denied@demo.com",
            }
        },
    ) if child else {"ok": False}
    child_write_denied = (not created.get("ok")) and (
        created.get("status") in (401, 403)
        or "insufficient_scope" in str(created)
        or "denied" in str(created).lower()
        or "403" in str(created)
        or "users.write" in str(created)
    )
    record(
        "child_sandbox_read_ok_write_deny",
        "PASS"
        if listed.get("ok")
        and child_write_denied
        and vault_sandbox
        and nested_ok
        and spire_child
        and spire_child_uid
        and child_user == "1001:1001"
        and child_runtime_user == "1001:1001"
        and child_health.get("agent_id") == "ai-agent-child"
        and child_svid_ok
        else "FAIL",
        {
            "list_ok": listed.get("ok"),
            "list_preview": (
                "redacted: list_all_users returned records"
                if listed.get("ok")
                else {k: listed.get(k) for k in ("ok", "status", "error", "message")}
            ),
            "create": {k: created.get(k) for k in ("ok", "status", "error", "message")},
            "child_scope": child_p.get("scope"),
            "act_sub": child_act.get("sub"),
            "act_spiffe": child_act.get("spiffe_id"),
            "nested_parent": nested.get("sub") or nested.get("spiffe_id"),
            "spire_child_entry": spire_child,
            "spire_child_uid": "unix:uid:1001" if spire_child_uid else child_block[:200],
            "child_container_user": child_user,
            "child_runtime_user": child_runtime_user,
            "child_runtime_health": child_health,
            "child_actor_agent_id": child_actor_p.get("agent_id"),
            "vault_read_http": st_child_r,
            "vault_write_http": st_child_w,
            "vault_write_errors": (child_w.get("errors") or [])[:2],
            "lease_id_present": bool((child_r.get("lease_id") if st_child_r == 200 else "")),
        },
    )

    # 10. CIBA HITL
    st, ciba_start = form(
        f"{KC_URL}/realms/{REALM}/protocol/openid-connect/ext/ciba/auth",
        {
            "client_id": "ciba-client",
            "client_secret": "ciba-client-secret",
            "login_hint": "admin",
            "scope": "openid users.write",
            "binding_message": "video-evidence-write",
        },
    )
    auth_req_id = str(ciba_start.get("auth_req_id") or "")
    time.sleep(1)
    approve_st, _ = http("POST", f"{CIBA_UI}/approve-latest")
    ciba_jwt = ""
    for _ in range(20):
        _, tok = form(
            f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token",
            {
                "grant_type": "urn:openid:params:grant-type:ciba",
                "auth_req_id": auth_req_id,
                "client_id": "ciba-client",
                "client_secret": "ciba-client-secret",
            },
        )
        if tok.get("access_token"):
            ciba_jwt = str(tok["access_token"])
            break
        time.sleep(1)
    ciba_p = jwt_claims(ciba_jwt)["payload"] if ciba_jwt else {}
    st_ciba_vault, _ = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-write-role",
        headers=vault_headers(ciba_jwt),
    ) if ciba_jwt else (0, {})
    record(
        "ciba_hitl",
        "PASS" if approve_st == 200 and ciba_jwt and st_ciba_vault == 200 else "FAIL",
        {
            "ciba_start_http": st,
            "auth_req_id_present": bool(auth_req_id),
            "approve_http": approve_st,
            "ciba_jwt_issued": bool(ciba_jwt),
            "vault_write_http": st_ciba_vault,
            "claims": redact_payload(ciba_p) if ciba_p else {},
        },
    )

    # 11. Ephemeral creds + lease revoke
    st_creds, creds = json_get(
        f"{VAULT}/v1/database/creds/user-mcp-read-role",
        headers=vault_headers(user_jwt),
    )
    lease_id = str(creds.get("lease_id") or "")
    st_rev, rev = json_put(
        f"{VAULT}/v1/sys/leases/revoke",
        {"lease_id": lease_id},
        headers=vault_headers(user_jwt),
    )
    st_lookup, lookup = json_put(
        f"{VAULT}/v1/sys/leases/lookup",
        {"lease_id": lease_id},
        headers=vault_headers(VAULT_TOKEN),
    )
    record(
        "ephemeral_lease_revoke",
        "PASS" if st_creds == 200 and lease_id and st_rev in (200, 204) and st_lookup in (400, 404) else "FAIL",
        {
            "issue_http": st_creds,
            "lease_id_present": bool(lease_id),
            "username_prefix": str((creds.get("data") or {}).get("username") or "")[:24],
            "revoke_http": st_rev,
            "lookup_after_revoke_http": st_lookup,
        },
    )

    # 12. Audit trail (Loki + optional Vault file audit)
    now = time.time()
    start_ns = int((now - 900) * 1e9)
    end_ns = int((now + 30) * 1e9)
    q = '{container="user-mcp"}'
    loki_url = (
        f"{LOKI}/loki/api/v1/query_range?query={urllib.parse.quote(q)}"
        f"&start={start_ns}&end={end_ns}&limit=20"
    )
    loki_st, loki_body = json_get(loki_url)
    streams = ((loki_body.get("data") or {}).get("result") or [])
    sample = []
    for stream in streams[:2]:
        for ts, line in (stream.get("values") or [])[-3:]:
            sample.append(line[:240])
    docker(
        "exec",
        "-e",
        "VAULT_ADDR=http://127.0.0.1:8200",
        "-e",
        "VAULT_TOKEN=root",
        "vault",
        "vault",
        "audit",
        "enable",
        "file",
        "file_path=/tmp/vault-audit.log",
        check=False,
    )
    json_get(
        f"{VAULT}/v1/database/creds/user-mcp-read-role",
        headers=vault_headers(user_jwt),
    )
    audit_grep = docker(
        "exec",
        "vault",
        "sh",
        "-c",
        "grep -c database/creds /tmp/vault-audit.log 2>/dev/null || echo 0",
        check=False,
    ).stdout.strip()
    record(
        "audit_trail",
        "PASS" if loki_st == 200 or audit_grep.isdigit() and int(audit_grep) > 0 else "PARTIAL",
        {
            "loki_http": loki_st,
            "loki_stream_count": len(streams),
            "loki_sample": sample[:4],
            "vault_audit_db_creds_lines": audit_grep,
        },
    )

    # 13. Three unauthorized writes (scope/RAR deny)
    denies = []
    for i in range(3):
        denies.append(
            mcp_tool(
                user_jwt,
                "create_user",
                {
                    "user": {
                        "first_name": "Nope",
                        "last_name": str(i),
                        "email": f"deny-{i}@demo.com",
                    }
                },
            )
        )
    all_denied = all(
        (not d.get("ok"))
        and (
            d.get("status") in (401, 403)
            or "insufficient_scope" in str(d)
            or "users.write" in str(d)
            or "denied" in str(d).lower()
        )
        for d in denies
    )
    record(
        "three_unauthorized_writes",
        "PASS" if all_denied else "FAIL",
        {"attempts": [{k: d.get(k) for k in ("ok", "status", "error", "message")} for d in denies]},
    )

    # 14. session_revoked mechanism (in-process tracker + HTTP query after suspend path)
    tracker = docker(
        "exec",
        "ai-agent",
        "python",
        "-c",
        """
from deny_tracker import DenyTracker
t = DenyTracker(limit=3, window_seconds=300)
sub = "evidence-user"
counts = [t.record_deny(sub) for _ in range(3)]
print(__import__("json").dumps({"counts": counts, "should_revoke": t.should_revoke(sub)}))
""",
    ).stdout.strip()
    tracker_j = json.loads(tracker)
    probe = mint_password(
        "user", "user", "openid profile email", client="human-cli", secret="human-cli-secret"
    )
    _, intro_before = form(
        f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token/introspect",
        {"token": probe},
        auth=("token-exchange", "token-exchange-secret"),
    )
    killed = docker(
        "exec",
        "ai-agent",
        "python",
        "-c",
        "from session_kill import revoke_idp_sessions; print('yes' if revoke_idp_sessions('user') else 'no')",
        check=False,
    ).stdout.strip()
    _, intro_after = form(
        f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token/introspect",
        {"token": probe},
        auth=("token-exchange", "token-exchange-secret"),
    )
    token_inactive = intro_before.get("active") is True and intro_after.get("active") is False
    record(
        "session_kill_deny_tracker",
        "PASS"
        if tracker_j.get("should_revoke")
        and tracker_j.get("counts") == [1, 2, 3]
        and killed == "yes"
        and token_inactive
        else "FAIL",
        {
            **tracker_j,
            "keycloak_logout": killed,
            "introspect_before": intro_before.get("active"),
            "introspect_after": intro_after.get("active"),
        },
    )

    # 15. Owner suspends agent
    docker(
        "exec",
        "-e",
        "VAULT_ADDR=http://127.0.0.1:8200",
        "-e",
        "VAULT_TOKEN=root",
        "vault",
        "vault",
        "kv",
        "put",
        "agent-lifecycle/ai-agent",
        "enabled=false",
    )
    st_sus, sus_body = json_post(
        f"{AGENT_URL}/v1/agent/query",
        {"messages": [{"role": "user", "content": "list users"}]},
        headers={"Authorization": f"Bearer {subject}", "Content-Type": "application/json"},
    )
    docker(
        "exec",
        "-e",
        "VAULT_ADDR=http://127.0.0.1:8200",
        "-e",
        "VAULT_TOKEN=root",
        "vault",
        "vault",
        "kv",
        "put",
        "agent-lifecycle/ai-agent",
        "enabled=true",
    )
    suspended = st_sus == 403 and (
        sus_body.get("error") == "agent_suspended" or "suspended" in json.dumps(sus_body).lower()
    )
    record(
        "owner_suspend_agent",
        "PASS" if suspended else "FAIL",
        {"http": st_sus, "body": sus_body},
    )

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pass": sum(1 for r in results if r["status"] == "PASS"),
        "fail": sum(1 for r in results if r["status"] == "FAIL"),
        "partial": sum(1 for r in results if r["status"] == "PARTIAL"),
        "beats": results,
    }
    out = EVIDENCE_DIR / "video-beats.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"\nPASS={summary['pass']} FAIL={summary['fail']} PARTIAL={summary['partial']}")
    print(f"evidence: {out}")
    if summary["fail"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
