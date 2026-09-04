from __future__ import annotations

from config import Settings
from spiffe_client import SpiffeSvidProvider
from storage.base import UserRepository
from storage.file_repo import FileUserRepository
from storage.postgres_repo import PostgresUserRepository
from vault_client import VaultClient


def build_repository(settings: Settings) -> UserRepository:
    if settings.user_backend != "postgres":
        return FileUserRepository(file_path=settings.users_file)

    vault_client: VaultClient | None = None
    spiffe_provider: SpiffeSvidProvider | None = None
    if settings.db_auth_mode == "vault":
        vault_tls_verify: bool | str = (
            settings.vault_ca_bundle.strip() or settings.vault_verify_tls
        )
        vault_client = VaultClient(
            addr=settings.vault_addr,
            jwt_path=settings.vault_jwt_path,
            namespace=settings.vault_namespace or None,
            verify_tls=vault_tls_verify,
            timeout_seconds=settings.vault_request_timeout_seconds,
        )
        spiffe_provider = SpiffeSvidProvider(
            socket_path=settings.spiffe_socket,
            audience=settings.spiffe_jwt_audience,
        )

    return PostgresUserRepository(
        pg_url=settings.pg_url,
        auth_mode=settings.db_auth_mode,
        auto_migrate=settings.pg_auto_migrate and settings.db_auth_mode == "direct",
        db_user=settings.db_user,
        db_password=settings.db_password,
        vault_client=vault_client,
        spiffe_provider=spiffe_provider,
        vault_jwt_read_role=settings.vault_jwt_read_role,
        vault_jwt_write_role=settings.vault_jwt_write_role,
        vault_db_read_path=settings.vault_db_read_path,
        vault_db_write_path=settings.vault_db_write_path,
        vault_spiffe_jwt_path=settings.vault_spiffe_jwt_path,
        vault_spiffe_workload_role=settings.vault_spiffe_workload_role,
        vault_action_read_role=settings.vault_action_read_role,
        vault_action_write_role=settings.vault_action_write_role,
    )
