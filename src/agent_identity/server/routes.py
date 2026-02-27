"""Route handler functions for the agent-identity HTTP server.

Each function accepts parsed request data and returns a tuple of
(status_code, response_dict). The HTTP handler in app.py calls these
functions and serializes the results to JSON.
"""
from __future__ import annotations

import datetime

from agent_identity.registry.identity_registry import (
    AgentAlreadyRegisteredError,
    AgentNotFoundError,
    IdentityRegistry,
)
from agent_identity.trust.dimensions import TrustDimension
from agent_identity.trust.scorer import TrustScorer
from agent_identity.server.models import (
    CreateIdentityRequest,
    ErrorResponse,
    HealthResponse,
    IdentityResponse,
    TrustResponse,
    VerifyRequest,
    VerifyResponse,
)


# Module-level shared state
_registry: IdentityRegistry = IdentityRegistry()
_trust_scorer: TrustScorer = TrustScorer()


def reset_state() -> None:
    """Reset all shared state — used in tests and for clean restarts."""
    global _registry, _trust_scorer
    _registry = IdentityRegistry()
    _trust_scorer = TrustScorer()


def _record_to_response(record: object) -> IdentityResponse:
    """Convert an AgentIdentityRecord to an IdentityResponse."""
    return IdentityResponse(
        agent_id=record.agent_id,  # type: ignore[attr-defined]
        display_name=record.display_name,  # type: ignore[attr-defined]
        organization=record.organization,  # type: ignore[attr-defined]
        capabilities=list(record.capabilities),  # type: ignore[attr-defined]
        metadata=dict(record.metadata),  # type: ignore[attr-defined]
        did=record.did,  # type: ignore[attr-defined]
        registered_at=record.registered_at.isoformat(),  # type: ignore[attr-defined]
        updated_at=record.updated_at.isoformat(),  # type: ignore[attr-defined]
        active=record.active,  # type: ignore[attr-defined]
    )


def handle_create_identity(body: dict[str, object]) -> tuple[int, dict[str, object]]:
    """Handle POST /identities.

    Parameters
    ----------
    body:
        Parsed JSON request body.

    Returns
    -------
    tuple[int, dict[str, object]]
        HTTP status code and response dictionary.
    """
    try:
        request = CreateIdentityRequest.model_validate(body)
    except Exception as exc:
        return 422, ErrorResponse(error="Validation error", detail=str(exc)).model_dump()

    if not request.agent_id.strip():
        return 422, ErrorResponse(
            error="Validation error", detail="agent_id must not be empty."
        ).model_dump()

    try:
        record = _registry.register(
            agent_id=request.agent_id,
            display_name=request.display_name,
            organization=request.organization,
            capabilities=request.capabilities,
            metadata={k: v for k, v in request.metadata.items()},
            did=request.did,
        )
    except AgentAlreadyRegisteredError as exc:
        return 409, ErrorResponse(error="Conflict", detail=str(exc)).model_dump()

    return 201, _record_to_response(record).model_dump()


def handle_verify(body: dict[str, object]) -> tuple[int, dict[str, object]]:
    """Handle POST /verify.

    Checks if an agent is registered, active, and has the claimed capabilities.

    Parameters
    ----------
    body:
        Parsed JSON request body.

    Returns
    -------
    tuple[int, dict[str, object]]
        HTTP status code and response dictionary.
    """
    try:
        request = VerifyRequest.model_validate(body)
    except Exception as exc:
        return 422, ErrorResponse(error="Validation error", detail=str(exc)).model_dump()

    try:
        record = _registry.get(request.agent_id)
    except AgentNotFoundError:
        response = VerifyResponse(
            agent_id=request.agent_id,
            verified=False,
            active=False,
            capabilities_valid=False,
            message=f"Agent {request.agent_id!r} is not registered.",
        )
        return 200, response.model_dump()

    if not record.active:
        response = VerifyResponse(
            agent_id=request.agent_id,
            verified=False,
            active=False,
            capabilities_valid=False,
            message=f"Agent {request.agent_id!r} is deregistered.",
        )
        return 200, response.model_dump()

    # Check claimed capabilities against registered capabilities
    missing: list[str] = []
    if request.claimed_capabilities:
        registered_caps = set(record.capabilities)
        missing = [cap for cap in request.claimed_capabilities if cap not in registered_caps]

    capabilities_valid = len(missing) == 0
    verified = record.active and capabilities_valid

    response = VerifyResponse(
        agent_id=request.agent_id,
        verified=verified,
        active=record.active,
        capabilities_valid=capabilities_valid,
        missing_capabilities=missing,
        message="Verification successful." if verified else "Capability mismatch.",
    )
    return 200, response.model_dump()


def handle_get_trust(agent_id: str) -> tuple[int, dict[str, object]]:
    """Handle GET /trust/{id}.

    Computes and returns a trust score for the agent.

    Parameters
    ----------
    agent_id:
        The agent identifier from the URL path.

    Returns
    -------
    tuple[int, dict[str, object]]
        HTTP status code and response dictionary.
    """
    try:
        record = _registry.get(agent_id)
    except AgentNotFoundError:
        return 404, ErrorResponse(
            error="Not found",
            detail=f"Agent {agent_id!r} is not registered.",
        ).model_dump()

    # Compute a basic trust score based on registration status
    # Competence: 70 if active, 0 if not; Reliability: 70 base; Integrity: 70 base
    base_score = 70.0 if record.active else 0.0
    dimensions = {
        TrustDimension.COMPETENCE: base_score,
        TrustDimension.RELIABILITY: base_score,
        TrustDimension.INTEGRITY: base_score,
    }

    trust_score = _trust_scorer.score(agent_id=agent_id, dimensions=dimensions)

    response = TrustResponse(
        agent_id=agent_id,
        composite=trust_score.composite,
        level=trust_score.level.name,
        dimensions={dim.value: score for dim, score in trust_score.dimensions.items()},
        timestamp=trust_score.timestamp.isoformat(),
    )
    return 200, response.model_dump()


def handle_health() -> tuple[int, dict[str, object]]:
    """Handle GET /health.

    Returns
    -------
    tuple[int, dict[str, object]]
        HTTP status code and response dictionary.
    """
    response = HealthResponse(identity_count=len(_registry))
    return 200, response.model_dump()


__all__ = [
    "reset_state",
    "handle_create_identity",
    "handle_verify",
    "handle_get_trust",
    "handle_health",
]
