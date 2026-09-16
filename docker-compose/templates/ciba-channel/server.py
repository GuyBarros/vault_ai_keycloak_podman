#!/usr/bin/env python3
"""Keycloak CIBA authentication-channel + approve UI.

Keycloak POSTs each backchannel request here (201). A human approves or
denies on http://localhost:8093. Approve callbacks Keycloak with SUCCEED
using the bearer token Keycloak sent on the original request.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HOST = os.environ.get("CIBA_CHANNEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("CIBA_CHANNEL_PORT", "8093"))
CALLBACK_URL = os.environ.get(
    "CIBA_CALLBACK_URL",
    "http://keycloak:8080/realms/demo/protocol/openid-connect/ext/ciba/auth/callback",
)

_LOCK = threading.Lock()
_PENDING: dict[str, dict] = {}


def _field(body: dict, *names: str) -> str:
    for name in names:
        value = body.get(name)
        if value:
            return str(value)
    extra = body.get("additionalParameters") or body.get("additional_parameters") or {}
    if isinstance(extra, dict):
        for name in names:
            value = extra.get(name)
            if value:
                return str(value)
    return ""


def _callback(bearer: str, status: str) -> tuple[int, str]:
    payload = json.dumps({"status": status}).encode()
    req = Request(
        CALLBACK_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")[:300]
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")[:300]
    except URLError as exc:
        return 502, str(exc)


def _pending_public() -> list[dict]:
    with _LOCK:
        return [
            {
                "id": item["id"],
                "login_hint": item["login_hint"],
                "binding_message": item["binding_message"],
                "scope": item["scope"],
                "status": item["status"],
            }
            for item in _PENDING.values()
            if item["status"] == "pending"
        ]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        sys_stderr = __import__("sys").stderr
        sys_stderr.write("[ciba-channel] " + (fmt % args) + "\n")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/pending"):
            self._send(
                200,
                json.dumps(_pending_public()).encode(),
                "application/json",
            )
            return
        if self.path in ("/", "/index.html"):
            self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if self.path in ("/ciba/authn", "/ciba/authn/"):
            body = self._read_json()
            bearer = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            item_id = str(uuid.uuid4())
            item = {
                "id": item_id,
                "login_hint": _field(body, "login_hint", "loginHint"),
                "binding_message": _field(
                    body, "binding_message", "bindingMessage"
                ),
                "scope": _field(body, "scope"),
                "bearer": bearer,
                "status": "pending",
            }
            with _LOCK:
                _PENDING[item_id] = item
            self.log_message(
                "pending CIBA login_hint=%s binding=%s",
                item["login_hint"],
                item["binding_message"],
            )
            self._send(201, json.dumps({"id": item_id}).encode(), "application/json")
            return

        if self.path in ("/approve-latest", "/approve-latest/"):
            with _LOCK:
                pending = [i for i in _PENDING.values() if i["status"] == "pending"]
            if not pending:
                self._send(404, b'{"error":"none pending"}', "application/json")
                return
            self._finish(pending[-1], "SUCCEED")
            return

        if self.path.startswith("/approve/") or self.path.startswith("/deny/"):
            action, _, item_id = self.path.strip("/").partition("/")
            item_id = item_id.strip("/")
            with _LOCK:
                item = _PENDING.get(item_id)
            if item is None:
                self._send(404, b'{"error":"unknown id"}', "application/json")
                return
            status = "SUCCEED" if action == "approve" else "CANCELLED"
            self._finish(item, status)
            return

        self._send(404, b"not found", "text/plain")

    def _finish(self, item: dict, kc_status: str) -> None:
        code, detail = _callback(item["bearer"], kc_status)
        ok = 200 <= code < 300
        with _LOCK:
            item["status"] = "approved" if ok and kc_status == "SUCCEED" else (
                "denied" if kc_status != "SUCCEED" else f"callback-{code}"
            )
        body = json.dumps(
            {"id": item["id"], "callback_status": code, "detail": detail, "ok": ok}
        ).encode()
        self._send(200 if ok else 502, body, "application/json")


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CIBA approval</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 1.25rem; max-width: 40rem; }
    h1 { font-size: 1.25rem; }
    .card { border: 1px solid #ccc; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    button { min-height: 44px; min-width: 44%; margin: 0 .5rem .5rem 0; padding: .6rem 1rem; font-size: 1rem; }
    .muted { color: #555; }
  </style>
</head>
<body>
  <h1>Approve the agent action</h1>
  <p class="muted">Vault will not mint database credentials until you approve.
     On the Android emulator this page is <code>http://10.0.2.2:8093</code>.
     Ask the agent to <b>create a user</b> (HITL). Updating a normal
     email is silent OBO; <code>admin@demo.com</code> is the sensitive
     record and waits here. Same mechanic as OpenShell refund vs Jira read.</p>
  <div id="list"><p class="muted">Waiting for a CIBA request…</p></div>
  <script>
    async function load() {
      const res = await fetch("/pending");
      const items = await res.json();
      const root = document.getElementById("list");
      if (!items.length) {
        root.innerHTML = "<p class='muted'>Waiting for a CIBA request…</p>";
        return;
      }
      root.innerHTML = items.map(i => `
        <div class="card">
          <div><b>${i.login_hint || "(user)"}</b></div>
          <div>${i.binding_message || "(no binding message)"}</div>
          <div class="muted">scope: ${i.scope || ""}</div>
          <p>
            <button onclick="act('approve','${i.id}')">Approve</button>
            <button onclick="act('deny','${i.id}')">Deny</button>
          </p>
        </div>`).join("");
    }
    async function act(kind, id) {
      await fetch("/" + kind + "/" + id, {method: "POST"});
      load();
    }
    load();
    setInterval(load, 1000);
  </script>
</body>
</html>
"""


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ciba-channel listening on {HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
