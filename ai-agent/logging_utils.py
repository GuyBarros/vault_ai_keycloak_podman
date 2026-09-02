from __future__ import annotations

import inspect
import json
import logging
import os
import queue
import socket
import sys
import threading
import urllib.request
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Any

_LOG_CONTEXT: ContextVar[dict[str, Any]] = ContextVar("log_context", default={})


def _resolve_host_ip(hostname: str) -> str | None:
    try:
        addresses = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return None

    resolved_ips: list[str] = []
    for address in addresses:
        ip_address = address[4][0]
        if ip_address not in resolved_ips:
            resolved_ips.append(ip_address)

    for ip_address in resolved_ips:
        if not ip_address.startswith("127.") and ip_address != "::1":
            return ip_address

    return resolved_ips[0] if resolved_ips else None


_HOSTNAME = socket.gethostname()
_HOST_IP = _resolve_host_ip(_HOSTNAME)


_NOISY_THIRD_PARTY_LOGGERS = (
    "httpx",
    "httpcore",
    "mcp",
    "mcp.client",
    "mcp.client.streamable_http",
    "anyio",
)


def configure_logging(log_level: str) -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(_resolve_log_level_value(log_level))

    formatter = JsonLogFormatter()
    existing_handler = next(
        (
            handler
            for handler in root_logger.handlers
            if getattr(handler, "_agent_json_handler", False)
        ),
        None,
    )
    if existing_handler is None:
        existing_handler = logging.StreamHandler(sys.stderr)
        existing_handler._agent_json_handler = True
        root_logger.addHandler(existing_handler)

    existing_handler.setFormatter(formatter)

    for logger_name in _NOISY_THIRD_PARTY_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    loki_url = os.environ.get("LOKI_URL", "").strip()
    if loki_url:
        loki_handler = LokiHandler(loki_url=loki_url, service="ai-agent")
        loki_handler.setFormatter(formatter)
        root_logger.addHandler(loki_handler)


def build_uvicorn_log_config(log_level: str) -> dict[str, Any]:
    normalized_log_level = _resolve_log_level(log_level)
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": "logging_utils.JsonLogFormatter",
            },
            "access_json": {
                "()": "logging_utils.UvicornAccessJsonFormatter",
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "class": "logging.StreamHandler",
                "formatter": "access_json",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn": {
                "handlers": ["default"],
                "level": normalized_log_level,
                "propagate": False,
            },
            "uvicorn.error": {
                "level": normalized_log_level,
            },
            "uvicorn.access": {
                "handlers": ["access"],
                "level": normalized_log_level,
                "propagate": False,
            },
        },
    }


def bind_log_context(**fields: Any) -> Token[dict[str, Any]]:
    merged_context = dict(_LOG_CONTEXT.get())
    merged_context.update(fields)
    return _LOG_CONTEXT.set(merged_context)


def reset_log_context(token: Token[dict[str, Any]]) -> None:
    _LOG_CONTEXT.reset(token)


def _resolve_log_level(log_level: str) -> str:
    return logging.getLevelName(_resolve_log_level_value(log_level))


def _resolve_log_level_value(log_level: str) -> int:
    normalized_log_level = log_level.upper()
    resolved_level = getattr(logging, normalized_log_level, logging.INFO)
    return resolved_level if isinstance(resolved_level, int) else logging.INFO


def _try_parse_json_object(message: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(message)
    except json.JSONDecodeError:
        return None

    return payload if isinstance(payload, dict) else None


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = self._build_message_payload(record)
        payload.setdefault(
            "timestamp",
            datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
        )
        payload.setdefault("level", record.levelname)
        payload.setdefault("logger", record.name)
        payload.setdefault("hostname", _HOSTNAME)
        payload.setdefault("host_ip", _HOST_IP)
        payload.setdefault("process_id", record.process)
        payload.setdefault("module", record.module)
        payload.setdefault("function", record.funcName)
        payload.setdefault("method_name", record.funcName)
        payload.setdefault("line_number", record.lineno)

        if record.exc_info and "exception" not in payload:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info and "stack" not in payload:
            payload["stack"] = self.formatStack(record.stack_info)

        return json.dumps(payload, ensure_ascii=True, sort_keys=True)

    def _build_message_payload(self, record: logging.LogRecord) -> dict[str, Any]:
        message = record.getMessage()
        payload = _try_parse_json_object(message)
        if payload is not None:
            return payload
        return {"message": message}


class UvicornAccessJsonFormatter(JsonLogFormatter):
    def _build_message_payload(self, record: logging.LogRecord) -> dict[str, Any]:
        if isinstance(record.args, tuple) and len(record.args) == 5:
            client_addr, method, full_path, http_version, status_code = record.args
            payload = {
                "event": "http_access",
                "client_addr": client_addr,
                "http_method": method,
                "path": full_path,
                "http_version": http_version,
                "status_code": _coerce_status_code(status_code),
            }
            payload["message"] = (
                f'{client_addr} - "{method} {full_path} HTTP/{http_version}" '
                f'{payload["status_code"]}'
            )
            return payload

        return super()._build_message_payload(record)


def _coerce_status_code(status_code: Any) -> int | Any:
    try:
        return int(status_code)
    except (TypeError, ValueError):
        return status_code


def _build_caller_fields() -> dict[str, Any]:
    frame = inspect.currentframe()
    caller_frame = frame.f_back.f_back if frame and frame.f_back and frame.f_back.f_back else None

    if caller_frame is None:
        return {
            "module": None,
            "function": None,
            "method_name": None,
            "line_number": None,
        }

    module_name = caller_frame.f_globals.get("__name__")
    function_name = caller_frame.f_code.co_name
    method_name = function_name
    instance = caller_frame.f_locals.get("self")
    if instance is not None:
        method_name = f"{instance.__class__.__name__}.{function_name}"

    return {
        "module": module_name,
        "function": function_name,
        "method_name": method_name,
        "line_number": caller_frame.f_lineno,
    }


def log_event(
    logger: logging.Logger,
    event: str,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    context_fields = dict(_LOG_CONTEXT.get())
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level),
        "logger": logger.name,
        "event": event,
        "hostname": _HOSTNAME,
        "host_ip": _HOST_IP,
        "process_id": os.getpid(),
        **_build_caller_fields(),
        **context_fields,
        **fields,
    }
    _apply_identity_message_prefix(payload)
    logger.log(level, json.dumps(payload, ensure_ascii=True, sort_keys=True))


def _apply_identity_message_prefix(payload: dict[str, Any]) -> None:
    preferred_username = payload.get("preferred_username")
    actor_agent_id = payload.get("actor_agent_id")
    message = payload.get("message")
    if not isinstance(message, str):
        return
    identity_parts: list[str] = []
    if preferred_username:
        identity_parts.append(f"user={preferred_username}")
    if actor_agent_id:
        identity_parts.append(f"agent={actor_agent_id}")
    if identity_parts:
        payload["message"] = f"[{' '.join(identity_parts)}] {message}"


class LokiHandler(logging.Handler):
    """Async logging handler that ships JSON log lines to Loki's push API.

    Each log record is formatted by the attached formatter (JsonLogFormatter),
    then queued and sent in a background daemon thread so the hot path is
    never blocked by network I/O.  Failures are silently swallowed to avoid
    log-handler recursion.
    """

    def __init__(self, loki_url: str, service: str, batch_size: int = 20) -> None:
        super().__init__()
        # Normalise: strip trailing slash and ensure we target the push endpoint.
        base = loki_url.rstrip("/")
        if not base.endswith("/loki/api/v1/push"):
            base = f"{base}/loki/api/v1/push"
        self._url = base
        self._labels = f'{{container="{service}"}}'
        self._queue: queue.Queue[tuple[str, str] | None] = queue.Queue(maxsize=1000)
        self._batch_size = batch_size
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # nanosecond timestamp string Loki requires
            ts_ns = str(int(record.created * 1_000_000_000))
            line = self.format(record)
            self._queue.put_nowait((ts_ns, line))
        except Exception:  # noqa: BLE001
            pass

    def _worker(self) -> None:
        while True:
            entries: list[tuple[str, str]] = []
            try:
                item = self._queue.get(timeout=2)
                if item is None:
                    break
                entries.append(item)
                # Drain up to batch_size - 1 more without blocking
                while len(entries) < self._batch_size:
                    try:
                        more = self._queue.get_nowait()
                        if more is None:
                            break
                        entries.append(more)
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            if not entries:
                continue

            payload = json.dumps({
                "streams": [{
                    "stream": {"container": self._labels.strip("{}").split("=")[1].strip('"')},
                    "values": [[ts, line] for ts, line in entries],
                }]
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    self._url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=3)
            except Exception:  # noqa: BLE001
                pass
