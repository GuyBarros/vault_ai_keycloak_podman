from __future__ import annotations

import asyncio
import json
from pathlib import Path

from errors import AppError
from models import UserRecord
from storage.base import UserRepository, normalize_email


class FileUserRepository(UserRepository):
    """JSON-file backed user repository.

    Loads the seed file once on startup and keeps a mutable in-memory list.
    Mutations are NOT written back to disk; the file is read-only seed data,
    matching the behavior of the original ai-agent implementation.
    """

    def __init__(self, file_path: str | Path):
        self._file_path = Path(file_path)
        self._lock = asyncio.Lock()
        self._users: list[dict] | None = None

    async def startup(self) -> None:
        async with self._lock:
            if self._users is None:
                self._users = self._read_from_disk()

    def _read_from_disk(self) -> list[dict]:
        if not self._file_path.exists():
            raise AppError(
                status_code=500,
                error="agent_error",
                message=f"User repository not found at {self._file_path}",
            )

        with self._file_path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)

        if not isinstance(data, list):
            raise AppError(
                status_code=500,
                error="agent_error",
                message="User repository must contain a list.",
            )

        users: list[dict] = []
        for index, user in enumerate(data):
            if not isinstance(user, dict):
                raise AppError(
                    status_code=500,
                    error="agent_error",
                    message=f"User repository entry at index {index} must be an object.",
                )
            users.append(dict(user))
        return users

    async def _ensure_loaded(self) -> list[dict]:
        if self._users is None:
            await self.startup()
        assert self._users is not None
        return self._users

    async def list_all(self) -> list[UserRecord]:
        async with self._lock:
            users = await self._ensure_loaded()
            return [UserRecord.model_validate(u) for u in users]

    async def search_by_first_name(self, first_name: str) -> list[UserRecord]:
        async with self._lock:
            users = await self._ensure_loaded()
            target = first_name.strip().lower()
            return [
                UserRecord.model_validate(u)
                for u in users
                if str(u.get("first_name", "")).strip().lower() == target
            ]

    async def create(self, user: UserRecord) -> UserRecord:
        async with self._lock:
            users = await self._ensure_loaded()
            new_email = normalize_email(user.email)
            for existing in users:
                if normalize_email(str(existing.get("email", ""))) == new_email:
                    raise AppError(
                        status_code=400,
                        error="invalid_request",
                        message=f"User already exists for email: {user.email}",
                    )
            payload = user.to_dict()
            users.append(payload)
            return UserRecord.model_validate(payload)

    async def delete_by_email(self, email: str) -> UserRecord:
        async with self._lock:
            users = await self._ensure_loaded()
            index = self._find_index(email, users)
            removed = users.pop(index)
            return UserRecord.model_validate(removed)

    async def update_by_email(self, email: str, user: UserRecord) -> UserRecord:
        async with self._lock:
            users = await self._ensure_loaded()
            index = self._find_index(email, users)
            new_email = normalize_email(user.email)
            for other_index, existing in enumerate(users):
                if other_index == index:
                    continue
                if normalize_email(str(existing.get("email", ""))) == new_email:
                    raise AppError(
                        status_code=400,
                        error="invalid_request",
                        message=f"User already exists for email: {user.email}",
                    )
            payload = user.to_dict()
            users[index] = payload
            return UserRecord.model_validate(payload)

    @staticmethod
    def _find_index(email: str, users: list[dict]) -> int:
        normalized = normalize_email(email)
        for index, user in enumerate(users):
            if normalize_email(str(user.get("email", ""))) == normalized:
                return index
        raise AppError(
            status_code=404,
            error="invalid_request",
            message=f"User not found for email: {email}",
        )
