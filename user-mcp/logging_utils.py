from __future__ import annotations

import inspect
import json
import logging
import os
import socket
import sys
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
    _ensure_mcp_noise_filter(existing_handler)


def _ensure_mcp_noise_filter(handler: logging.Handler) -> None:
    if any(isinstance(f, MCPNoiseDowngradeFilter) for f in handler.filters):
        return
    handler.addFilter(MCPNoiseDowngradeFilter())


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
        "filters": {
            "mcp_noise_downgrade": {
                "()": "logging_utils.MCPNoiseDowngradeFilter",
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "filters": ["mcp_noise_downgrade"],
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

        for context_key, context_value in _LOG_CONTEXT.get().items():
            payload.setdefault(context_key, context_value)

        if record.exc_info and "exception" not in payload:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info and "stack" not in payload:
            payload["stack"] = self.formatStack(record.stack_info)

        _apply_identity_message_prefix(payload)

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
    logger.log(level, json.dumps(payload, ensure_ascii=True, sort_keys=True))


_NOISE_PREFIXES_BY_LOGGER: dict[str, tuple[str, ...]] = {
    "mcp.server.lowlevel.server": (
        "Processing request of type ",
        "Created new transport with session ID",
        "Terminating session",
    ),
    "mcp.server.streamable_http": (
        "Processing request of type ",
        "Created new transport with session ID",
        "Terminating session",
    ),
    "mcp.server.streamable_http_manager": (
        "Processing request of type ",
        "Created new transport with session ID",
        "Terminating session",
    ),
    "httpx": ("HTTP Request: ",),
}


class MCPNoiseDowngradeFilter(logging.Filter):
    """Demote routine MCP transport and httpx request INFO chatter to DEBUG.

    Records that match known lifecycle/request messages are rewritten to DEBUG
    so they only surface when the root logger is itself at DEBUG. Any
    non-matching record passes through unchanged.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        prefixes = _NOISE_PREFIXES_BY_LOGGER.get(record.name)
        if prefixes is None:
            return True
        message = record.getMessage()
        if not any(message.startswith(p) for p in prefixes):
            return True
        record.levelno = logging.DEBUG
        record.levelname = "DEBUG"
        return record.levelno >= logging.getLogger().getEffectiveLevel()


def _apply_identity_message_prefix(payload: dict[str, Any]) -> None:
    preferred_username = payload.get("preferred_username")
    agent_id = payload.pop("agent_id", None)
    message = payload.get("message")
    if not isinstance(message, str):
        return
    identity_parts: list[str] = []
    if preferred_username:
        identity_parts.append(f"user={preferred_username}")
    if agent_id:
        identity_parts.append(f"agent={agent_id}")
    if identity_parts:
        payload["message"] = f"{' '.join(identity_parts)} {message}"
