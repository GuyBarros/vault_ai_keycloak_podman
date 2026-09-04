from __future__ import annotations

from config import Settings
from storage.base import UserRepository
from storage.file_repo import FileUserRepository
from storage.postgres_repo import PostgresUserRepository
from vault_client import VaultClient


def build_repository(settings: Settings) -> UserRepository:
    if settings.user_backend != "postgres":
        return FileUserRepository(file_path=settings.users_file)

    vault_client: VaultClient | None = None
    if settings.db_auth_mode == "vault":
        vault_tls_verify: bool | str = (
            settings.vault_ca_bundle.strip() or settings.vault_verify_tls
        )
        vault_client = VaultClient(
            addr=settings.vault_addr,
            namespace=settings.vault_namespace or None,
            verify_tls=vault_tls_verify,
            timeout_seconds=settings.vault_request_timeout_seconds,
        )

    return PostgresUserRepository(
        pg_url=settings.pg_url,
        auth_mode=settings.db_auth_mode,
        auto_migrate=settings.pg_auto_migrate and settings.db_auth_mode == "direct",
        db_user=settings.db_user,
        db_password=settings.db_password,
        vault_client=vault_client,
        vault_ceiling_policy_read=settings.vault_ceiling_policy_read,
        vault_ceiling_policy_write=settings.vault_ceiling_policy_write,
        vault_db_read_path=settings.vault_db_read_path,
        vault_db_write_path=settings.vault_db_write_path,
    )
