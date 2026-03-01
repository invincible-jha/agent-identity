#!/usr/bin/env python3
"""Example: Registry and Delegation

Demonstrates registering agent identities, creating delegation
tokens, and verifying delegation chains.

Usage:
    python examples/03_registry_delegation.py

Requirements:
    pip install agent-identity
"""
from __future__ import annotations

import agent_identity
from agent_identity import (
    IdentityRegistry,
    AgentIdentityRecord,
    DelegationToken,
    DelegationChain,
    DelegationRevocation,
    AgentNotFoundError,
)
import datetime


def main() -> None:
    print(f"agent-identity version: {agent_identity.__version__}")

    # Step 1: Create and populate an identity registry
    registry = IdentityRegistry()

    agents = [
        AgentIdentityRecord(agent_id="orchestrator", role="admin", capabilities=["delegate", "manage"]),
        AgentIdentityRecord(agent_id="sub-agent-1", role="worker", capabilities=["search", "summarise"]),
        AgentIdentityRecord(agent_id="sub-agent-2", role="worker", capabilities=["analyse", "report"]),
    ]

    for agent in agents:
        registry.register(agent)

    print(f"Registry: {registry.count()} agents registered.")

    # Step 2: Retrieve agent records
    try:
        record = registry.get("orchestrator")
        print(f"\nOrchestrator: role={record.role} | caps={record.capabilities}")
    except AgentNotFoundError as error:
        print(f"Agent not found: {error}")

    # Step 3: Create a delegation token from orchestrator to sub-agent-1
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    token = DelegationToken(
        delegator_id="orchestrator",
        delegate_id="sub-agent-1",
        permissions=["search", "summarise"],
        expires_at=expiry,
        metadata={"purpose": "Q4 research task"},
    )
    print(f"\nDelegation token created:")
    print(f"  From: {token.delegator_id} -> To: {token.delegate_id}")
    print(f"  Permissions: {token.permissions}")
    print(f"  Expires: {token.expires_at.isoformat()}")
    print(f"  Is expired: {token.is_expired()}")

    # Step 4: Build a delegation chain
    chain = DelegationChain(tokens=[token])
    is_valid = chain.verify()
    print(f"\nDelegation chain valid: {is_valid}")
    print(f"  Chain depth: {chain.depth}")

    # Step 5: Revoke a delegation
    revocation = DelegationRevocation(
        token_id=token.token_id,
        revoked_by="orchestrator",
        reason="Task completed early",
    )
    print(f"\nRevocation created: {revocation.token_id[:12]}... revoked by {revocation.revoked_by}")
    print(f"  Is revoked: {revocation.is_revoked(token)}")


if __name__ == "__main__":
    main()
