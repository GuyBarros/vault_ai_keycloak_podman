from __future__ import annotations

from typing import Iterable

from auth.context import current_obo_scope
from errors import AppError


class InsufficientScopeError(AppError):
    """Raised when the current OBO token lacks a tool's required scope(s).

    Maps to HTTP 403 with body {"error": "insufficient_scope", ...} when
    surfaced through the FastAPI / FastMCP error path.
    """

    def __init__(self, *, tool: str, required: list[str], granted: list[str]):
        message = (
            f"Tool '{tool}' requires scope(s) {sorted(required)} "
            f"but the OBO token grants {sorted(granted)}."
        )
        super().__init__(403, "insufficient_scope", message)
        self.tool = tool
        self.required = sorted(required)
        self.granted = sorted(granted)


_TOOL_SCOPES: dict[str, frozenset[str]] = {}
_BYPASS = False


def configure_bypass(enabled: bool) -> None:
    """Toggle scope enforcement off (for bypass-auth dev mode and unit tests)."""
    global _BYPASS
    _BYPASS = enabled


def register_tool_scopes(tool_name: str, scopes: Iterable[str]) -> None:
    """Declare the OBO scopes a tool requires. Called once at tool registration."""
    _TOOL_SCOPES[tool_name] = frozenset(scopes)


def get_required_scopes(tool_name: str) -> frozenset[str]:
    return _TOOL_SCOPES.get(tool_name, frozenset())


def require_scopes(tool_name: str) -> None:
    """Raise InsufficientScopeError if the bound OBO scope doesn't satisfy the tool.

    Tools that haven't been registered are denied by default — every tool must
    declare its scope contract explicitly.
    """
    if _BYPASS:
        return

    if tool_name not in _TOOL_SCOPES:
        raise InsufficientScopeError(
            tool=tool_name,
            required=["<undeclared>"],
            granted=[],
        )

    required = _TOOL_SCOPES[tool_name]
    granted_str = current_obo_scope.get() or ""
    granted = {tok for tok in granted_str.split() if tok}

    if not required.issubset(granted):
        raise InsufficientScopeError(
            tool=tool_name,
            required=list(required),
            granted=list(granted),
        )
