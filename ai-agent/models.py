from typing import List

from pydantic import BaseModel


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[Message]


class AgentTokensResponse(BaseModel):
    actor_token: str
    obo_token: str | None = None
    child_obo_token: str | None = None
