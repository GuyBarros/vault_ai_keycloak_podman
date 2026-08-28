from __future__ import annotations

from abc import ABC, abstractmethod

from models import UserRecord


class UserRepository(ABC):
    """Async user repository abstraction. Implementations may persist to a
    JSON file (in-memory) or to Postgres."""

    @abstractmethod
    async def list_all(self) -> list[UserRecord]: ...

    @abstractmethod
    async def search_by_first_name(self, first_name: str) -> list[UserRecord]: ...

    @abstractmethod
    async def create(self, user: UserRecord) -> UserRecord: ...

    @abstractmethod
    async def delete_by_email(self, email: str) -> UserRecord: ...

    @abstractmethod
    async def update_by_email(self, email: str, user: UserRecord) -> UserRecord: ...

    async def startup(self) -> None:  # pragma: no cover - default no-op
        return None

    async def shutdown(self) -> None:  # pragma: no cover - default no-op
        return None


def normalize_email(email: str) -> str:
    return email.strip().lower()
