from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRecord(BaseModel):
    """A user record. Extra fields are preserved so callers can pass through
    arbitrary attributes that do not have a first-class field here."""

    model_config = ConfigDict(extra="allow")

    email: EmailStr = Field(..., description="Primary unique identifier for the user.")
    first_name: str | None = None
    last_name: str | None = None
    ssn: str | None = None
    phone: str | None = None
    credit_card_number: str | None = None
    ip_address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=False, mode="json")


class UserListResult(BaseModel):
    users: list[UserRecord]
    count: int


def to_user_list_result(users: list[UserRecord]) -> UserListResult:
    return UserListResult(users=users, count=len(users))
