from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import asyncpg

from auth.context import current_obo_scope, current_obo_token
from errors import AppError
from logging_utils import bind_log_context, log_event
from models import UserRecord
from storage.base import UserRepository
from vault_client import VaultClient

LOGGER = logging.getLogger("user_mcp.storage.postgres")

_COLUMNS = (
    "email",
    "first_name",
    "last_name",
    "ssn",
    "phone",
    "credit_card_number",
    "ip_address",
)
_SELECT = ", ".join(_COLUMNS)

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS users (
        email              TEXT PRIMARY KEY,
        first_name         TEXT,
        last_name          TEXT,
        ssn                TEXT,
        phone              TEXT,
        credit_card_number TEXT,
        ip_address         TEXT
    );
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uidx ON users (lower(email));",
    "CREATE INDEX IF NOT EXISTS users_first_name_lower_idx ON users (lower(first_name));",
)

_SCOPE_WRITE = "users.write"
_SCOPE_READ = "users.read"


class PostgresUserRepository(UserRepository):
    """Postgres-backed user repository with two credential modes:

    - ``direct``: a long-lived asyncpg pool authenticated with static
      USER_MCP_DB_USER / USER_MCP_DB_PASSWORD. Intended only for connectivity
      testing.
    - ``vault``: every request mints short-lived Postgres credentials from
      Vault using the request's OBO token. Each tool call opens a fresh
      asyncpg connection bound to the validated identity, then closes it.
    """

    def __init__(
        self,
        pg_url: str,
        auth_mode: str,
        auto_migrate: bool = False,
        # direct mode
        db_user: str = "",
        db_password: str = "",
        # vault mode
        vault_client: VaultClient | None = None,
        vault_jwt_read_role: str = "",
        vault_jwt_write_role: str = "",
        vault_db_read_path: str = "",
        vault_db_write_path: str = "",
    ):
        if not pg_url:
            raise AppError(
                500,
                "configuration_error",
                "USER_MCP_PG_URL is required when USER_BACKEND=postgres.",
            )
        if auth_mode not in ("direct", "vault"):
            raise AppError(
                500,
                "configuration_error",
                f"Unsupported USER_MCP_DB_AUTH_MODE: {auth_mode}",
            )
        if auth_mode == "direct" and (not db_user or not db_password):
            raise AppError(
                500,
                "configuration_error",
                "USER_MCP_DB_USER and USER_MCP_DB_PASSWORD are required when "
                "USER_MCP_DB_AUTH_MODE=direct.",
            )
        if auth_mode == "vault":
            if vault_client is None:
                raise AppError(
                    500,
                    "configuration_error",
                    "Vault client is required when USER_MCP_DB_AUTH_MODE=vault.",
                )
            if not vault_jwt_read_role or not vault_jwt_write_role:
                raise AppError(
                    500,
                    "configuration_error",
                    "Vault JWT read/write role names are required.",
                )
            if not vault_db_read_path or not vault_db_write_path:
                raise AppError(
                    500,
                    "configuration_error",
                    "Vault DB credential paths are required.",
                )

        self._pg_url = pg_url
        self._auth_mode = auth_mode
        self._auto_migrate = auto_migrate
        self._db_user = db_user
        self._db_password = db_password
        self._vault = vault_client
        self._jwt_read_role = vault_jwt_read_role
        self._jwt_write_role = vault_jwt_write_role
        self._db_read_path = vault_db_read_path
        self._db_write_path = vault_db_write_path
        self._pool: asyncpg.Pool | None = None

    async def startup(self) -> None:
        if self._auth_mode == "direct":
            log_event(
                LOGGER,
                "postgres_pool_init",
                message="Initializing Postgres connection pool (direct mode)",
            )
            self._pool = await asyncpg.create_pool(
                dsn=self._pg_url,
                user=self._db_user,
                password=self._db_password,
                min_size=1,
                max_size=10,
            )
            if self._auto_migrate:
                async with self._pool.acquire() as conn:
                    async with conn.transaction():
                        for statement in _DDL:
                            await conn.execute(statement)
        else:
            log_event(
                LOGGER,
                "postgres_vault_mode_ready",
                message="Postgres repository ready (vault mode, per-request creds)",
            )

    async def shutdown(self) -> None:
        if self._pool is not None:
            log_event(
                LOGGER,
                "postgres_pool_close",
                message="Closing Postgres connection pool",
            )
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[asyncpg.Connection]:
        if self._auth_mode == "direct":
            if self._pool is None:
                raise AppError(500, "agent_error", "Postgres pool not initialized.")
            async with self._pool.acquire() as conn:
                bind_log_context(db_username=self._db_user)
                log_event(
                    LOGGER,
                    "db_call",
                    level=logging.DEBUG,
                    message="Postgres connection ready (direct mode)",
                    auth_mode="direct",
                    db_username=self._db_user,
                )
                yield conn
            return

        # vault mode: fetch fresh creds bound to the OBO identity
        obo = current_obo_token.get(None)
        scope = current_obo_scope.get(None) or ""
        if not obo:
            raise AppError(
                401,
                "invalid_request",
                "OBO token is required to obtain database credentials in vault mode.",
            )
        jwt_role, db_creds_path = self._select_vault_targets(scope)

        assert self._vault is not None
        client_token = await self._vault.login_with_jwt(obo, jwt_role)
        creds = await self._vault.read_database_creds(client_token, db_creds_path)

        try:
            conn = await asyncpg.connect(
                dsn=self._pg_url,
                user=creds.username,
                password=creds.password,
            )
        except (OSError, asyncpg.PostgresError) as exc:
            log_event(
                LOGGER,
                "db_connection_failed",
                level=logging.ERROR,
                message=f"Postgres connection failed: {exc}",
                auth_mode="vault",
                connection_status="failed",
                db_username=creds.username,
            )
            raise AppError(
                502,
                "agent_error",
                f"Failed to connect to Postgres with Vault-issued credentials: {exc}",
            ) from exc

        bind_log_context(db_username=creds.username)
        log_event(
            LOGGER,
            "db_call",
            level=logging.DEBUG,
            message="Postgres connection ready (vault mode)",
            auth_mode="vault",
            db_username=creds.username,
            jwt_role=jwt_role,
            db_creds_path=db_creds_path,
            lease_id=creds.lease_id,
            lease_duration=creds.lease_duration,
        )
        try:
            yield conn
        finally:
            await conn.close()

    def _select_vault_targets(self, scope: str) -> tuple[str, str]:
        scopes = {part for part in scope.split() if part}
        if _SCOPE_WRITE in scopes:
            return self._jwt_write_role, self._db_write_path
        if _SCOPE_READ in scopes:
            return self._jwt_read_role, self._db_read_path
        raise AppError(
            403,
            "invalid_request",
            f"OBO token scope must include '{_SCOPE_READ}' or '{_SCOPE_WRITE}' "
            f"to obtain database credentials.",
        )

    async def list_all(self) -> list[UserRecord]:
        async with self._acquire() as conn:
            rows = await conn.fetch(f"SELECT {_SELECT} FROM users ORDER BY email")
        return [UserRecord.model_validate(_row_to_dict(r)) for r in rows]

    async def search_by_first_name(self, first_name: str) -> list[UserRecord]:
        async with self._acquire() as conn:
            rows = await conn.fetch(
                f"SELECT {_SELECT} FROM users WHERE lower(first_name) = lower($1) ORDER BY email",
                first_name.strip(),
            )
        return [UserRecord.model_validate(_row_to_dict(r)) for r in rows]

    async def create(self, user: UserRecord) -> UserRecord:
        params = _user_to_params(user)
        try:
            async with self._acquire() as conn:
                row = await conn.fetchrow(
                    f"""
                    INSERT INTO users ({_SELECT})
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING {_SELECT}
                    """,
                    *params,
                )
        except asyncpg.UniqueViolationError as exc:
            raise AppError(
                400,
                "invalid_request",
                f"User already exists for email: {user.email}",
            ) from exc
        return UserRecord.model_validate(_row_to_dict(row))

    async def delete_by_email(self, email: str) -> UserRecord:
        async with self._acquire() as conn:
            row = await conn.fetchrow(
                f"DELETE FROM users WHERE lower(email) = lower($1) RETURNING {_SELECT}",
                email.strip(),
            )
        if row is None:
            raise AppError(404, "invalid_request", f"User not found for email: {email}")
        return UserRecord.model_validate(_row_to_dict(row))

    async def update_by_email(self, email: str, user: UserRecord) -> UserRecord:
        # Partial update: only touch columns the caller actually provided
        # with a non-null value. The users table declares every column NOT
        # NULL, and LLM tool callers routinely emit explicit `null` for
        # unchanged fields — so exclude_unset alone is not enough; we must
        # also drop None values to avoid wiping NOT NULL columns.
        updates = user.model_dump(exclude_none=True)
        params: list[Any] = [email.strip()]
        set_clauses: list[str] = []
        for col in _COLUMNS:
            if col in updates:
                params.append(updates[col])
                set_clauses.append(f"{col} = ${len(params)}")

        if not set_clauses:
            async with self._acquire() as conn:
                row = await conn.fetchrow(
                    f"SELECT {_SELECT} FROM users WHERE lower(email) = lower($1)",
                    email.strip(),
                )
            if row is None:
                raise AppError(404, "invalid_request", f"User not found for email: {email}")
            return UserRecord.model_validate(_row_to_dict(row))

        sql = (
            f"UPDATE users SET {', '.join(set_clauses)} "
            f"WHERE lower(email) = lower($1) "
            f"RETURNING {_SELECT}"
        )
        try:
            async with self._acquire() as conn:
                row = await conn.fetchrow(sql, *params)
        except asyncpg.UniqueViolationError as exc:
            raise AppError(
                400,
                "invalid_request",
                f"User already exists for email: {user.email}",
            ) from exc
        if row is None:
            raise AppError(404, "invalid_request", f"User not found for email: {email}")
        return UserRecord.model_validate(_row_to_dict(row))


def _user_to_params(user: UserRecord) -> tuple[Any, ...]:
    return (
        user.email,
        user.first_name,
        user.last_name,
        user.ssn,
        user.phone,
        user.credit_card_number,
        user.ip_address,
    )


def _row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    return {col: row[col] for col in _COLUMNS}
