"""Local authorization gate for Keycloak token exchange (RFC 8693).

Reads group membership from the ``groups`` claim embedded in ``subject_token``
— a flat string array populated by Keycloak's group membership protocol mapper.
Raises :class:`OBOAuthorizationError` (mapped to HTTP 403 in the API layer) when
the caller's groups do not entitle every requested scope. The check fails closed:
missing/malformed claims and unknown scopes both deny.
"""
import jwt

from exceptions.errors import OBOAuthorizationError
from config.settings import settings

# Scope → set of groups that satisfy it.  At least one group in the set
# must appear in the ``groups`` claim for the scope to be granted.
SCOPE_REQUIREMENTS: dict[str, frozenset[str]] = {
    "users.read": frozenset({settings.readonly_group, settings.admin_group}),
    "users.write": frozenset({settings.admin_group}),
    "delegation:ai-agent": frozenset({settings.readonly_group, settings.admin_group}),
}


def _groups_from_token(token: str) -> list[str] | None:
    """Return the ``groups`` claim from *token*.

    Keycloak populates a flat string array via the group membership mapper::

        { "groups": ["/readers", "/writers", ...] }

    Returns ``None`` when the claim is absent or malformed.
    """
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    groups = payload.get("groups")
    if isinstance(groups, list) and all(isinstance(g, str) for g in groups):
        return groups
    return None


def _claim_summary_from_token(token: str) -> dict[str, str | list[str] | int | None]:
    """Return a small non-sensitive claim summary for debugging authorization failures."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return {}

    if not isinstance(payload, dict):
        return {}

    summary: dict[str, str | list[str] | int | None] = {}
    for claim_name in ("azp", "aud", "scope", "sub", "preferred_username", "groups"):
        value = payload.get(claim_name)
        if isinstance(value, (str, int)):
            summary[claim_name] = value
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            summary[claim_name] = value
    return summary


def authorize_scope(subject_token: str, scope: str) -> None:
    """Raise :class:`OBOAuthorizationError` if *subject_token*'s groups don't entitle *scope*.

    *scope* is the space-separated string from the request. Every scope token
    must be present in :data:`SCOPE_REQUIREMENTS` and at least one of the user's
    groups must satisfy each scope's required-groups set.
    """
    groups = _groups_from_token(subject_token)
    if not groups:
        claim_summary = _claim_summary_from_token(subject_token)
        raise OBOAuthorizationError(
            "subject_token missing or malformed 'groups' claim; "
            f"claims_present={sorted(claim_summary.keys())}; "
            f"claim_summary={claim_summary}"
        )

    user_groups = set(groups)
    requested = [s for s in scope.split() if s]
    for requested_scope in requested:
        required = SCOPE_REQUIREMENTS.get(requested_scope)
        if required is None:
            raise OBOAuthorizationError(
                f"scope '{requested_scope}' is not permitted by policy"
            )
        if user_groups.isdisjoint(required):
            raise OBOAuthorizationError(
                f"user groups {sorted(user_groups)} are not authorized for scope "
                f"'{requested_scope}' (requires one of {sorted(required)})"
            )
