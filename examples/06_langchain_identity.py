#!/usr/bin/env python3
"""Example: LangChain Identity Integration

Demonstrates attaching agent-identity trust scores and RBAC
to LangChain chain execution.

Usage:
    python examples/06_langchain_identity.py

Requirements:
    pip install agent-identity langchain
"""
from __future__ import annotations

try:
    from langchain.schema import HumanMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

import agent_identity
from agent_identity import (
    IdentityRegistry,
    AgentIdentityRecord,
    RBACMiddleware,
    TrustScorer,
    TrustHistory,
    TrustDimension,
    derive_level,
    TrustLevel,
)


def identity_gated_chain(
    agent_id: str,
    question: str,
    registry: IdentityRegistry,
    rbac: RBACMiddleware,
    min_trust: TrustLevel = TrustLevel.MEDIUM,
) -> str:
    """Execute a chain only if the agent has sufficient identity trust."""
    # Check agent is registered
    try:
        record = registry.get(agent_id)
    except Exception:
        return f"[DENIED] Agent '{agent_id}' not registered."

    # Check RBAC permission
    if not rbac.check_permission(agent_id=agent_id, permission="read"):
        return f"[DENIED] Agent '{agent_id}' lacks read permission."

    # Simulate trust score check
    history = TrustHistory(agent_id=agent_id)
    history.record_positive(dimension=TrustDimension.RELIABILITY)
    history.record_positive(dimension=TrustDimension.ACCURACY)
    scorer = TrustScorer()
    trust_score = scorer.score(history)
    level = derive_level(trust_score.overall)

    if level.value < min_trust.value:
        return f"[DENIED] Trust level {level.name} below required {min_trust.name}."

    # Execute the chain
    if _LANGCHAIN_AVAILABLE:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        response = llm.invoke([HumanMessage(content=question)])
        return response.content
    return f"[stub] Answer to: {question[:50]}"


def main() -> None:
    print(f"agent-identity version: {agent_identity.__version__}")

    if not _LANGCHAIN_AVAILABLE:
        print("LangChain not installed — using stub responses.")
        print("Install with: pip install langchain")

    # Step 1: Set up registry and RBAC
    registry = IdentityRegistry()
    registry.register(AgentIdentityRecord(agent_id="trusted-agent", role="operator", capabilities=["read"]))
    registry.register(AgentIdentityRecord(agent_id="unknown-agent", role="guest", capabilities=[]))

    rbac = RBACMiddleware()
    rbac.assign_role("trusted-agent", "operator")
    # unknown-agent has no role

    # Step 2: Test identity-gated chains
    test_cases: list[tuple[str, str]] = [
        ("trusted-agent", "What are the benefits of AI governance?"),
        ("unknown-agent", "What is the capital of France?"),
        ("unregistered-agent", "Explain quantum computing briefly."),
    ]

    print("\nIdentity-gated LangChain calls:")
    for agent_id, question in test_cases:
        result = identity_gated_chain(agent_id, question, registry, rbac)
        print(f"  [{agent_id}] -> {result[:80]}")


if __name__ == "__main__":
    main()
