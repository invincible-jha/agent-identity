"""Pydantic request/response models for the agent-identity HTTP server."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class CreateIdentityRequest(BaseModel):
    """Request body for POST /identities."""

    agent_id: str
    display_name: str
    organization: str
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    did: str = ""


class IdentityResponse(BaseModel):
    """Response body representing a single identity record."""

    agent_id: str
    display_name: str
    organization: str
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)
    did: str = ""
    registered_at: str
    updated_at: str
    active: bool


class VerifyRequest(BaseModel):
    """Request body for POST /verify."""

    agent_id: str
    claimed_capabilities: list[str] = Field(default_factory=list)
    context: dict[str, str] = Field(default_factory=dict)


class VerifyResponse(BaseModel):
    """Response body for POST /verify."""

    agent_id: str
    verified: bool
    active: bool
    capabilities_valid: bool
    missing_capabilities: list[str] = Field(default_factory=list)
    trust_score: Optional[float] = None
    message: str = ""


class TrustResponse(BaseModel):
    """Response body for GET /trust/{id}."""

    agent_id: str
    composite: float
    level: str
    dimensions: dict[str, float] = Field(default_factory=dict)
    timestamp: str


class HealthResponse(BaseModel):
    """Response body for GET /health."""

    status: str = "ok"
    service: str = "agent-identity"
    version: str = "0.1.0"
    identity_count: int = 0


class ErrorResponse(BaseModel):
    """Standard error response body."""

    error: str
    detail: str = ""


__all__ = [
    "CreateIdentityRequest",
    "IdentityResponse",
    "VerifyRequest",
    "VerifyResponse",
    "TrustResponse",
    "HealthResponse",
    "ErrorResponse",
]
