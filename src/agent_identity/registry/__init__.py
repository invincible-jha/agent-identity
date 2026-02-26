"""Agent identity registry.

Provides a central IdentityRegistry for storing and querying agent identity
records, and a DIDProvider for managing Decentralized Identifiers.

Quick start
-----------
::

    from agent_identity.registry import IdentityRegistry, DIDProvider

    registry = IdentityRegistry()
    did_provider = DIDProvider()

    record = registry.register(
        agent_id="agent-001",
        display_name="My Agent",
        organization="AumOS",
    )
    did = did_provider.create_did(record.agent_id)
    registry.update(record.agent_id, did=did)
"""
from __future__ import annotations

from agent_identity.registry.did import DIDDocument, DIDProvider, DIDResolutionError
from agent_identity.registry.identity_registry import (
    AgentAlreadyRegisteredError,
    AgentIdentityRecord,
    AgentNotFoundError,
    IdentityRegistry,
)

__all__ = [
    "AgentAlreadyRegisteredError",
    "AgentIdentityRecord",
    "AgentNotFoundError",
    "DIDDocument",
    "DIDProvider",
    "DIDResolutionError",
    "IdentityRegistry",
]
