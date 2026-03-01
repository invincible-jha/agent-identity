#!/usr/bin/env python3
"""Example: Trust Scoring

Demonstrates multi-dimensional trust scoring using TrustScorer,
TrustHistory, and TrustPolicy.

Usage:
    python examples/02_trust_scoring.py

Requirements:
    pip install agent-identity
"""
from __future__ import annotations

import agent_identity
from agent_identity import (
    TrustScorer,
    TrustHistory,
    TrustLevel,
    TrustPolicy,
    TrustDimension,
    derive_level,
)


def main() -> None:
    print(f"agent-identity version: {agent_identity.__version__}")

    # Step 1: Create a trust scorer
    scorer = TrustScorer()
    agent_id = "analytics-agent-v2"

    # Step 2: Build trust history from past interactions
    history = TrustHistory(agent_id=agent_id)
    history.record_positive(dimension=TrustDimension.RELIABILITY, notes="Delivered report on time")
    history.record_positive(dimension=TrustDimension.ACCURACY, notes="Fact-checked results verified")
    history.record_negative(dimension=TrustDimension.SECURITY, notes="Attempted access to restricted path")
    history.record_positive(dimension=TrustDimension.RELIABILITY, notes="Completed task within budget")
    history.record_positive(dimension=TrustDimension.TRANSPARENCY, notes="Cited all sources correctly")

    print(f"\nTrust history for '{agent_id}':")
    print(f"  Total events: {history.total_events}")
    print(f"  Positive: {history.positive_count}")
    print(f"  Negative: {history.negative_count}")

    # Step 3: Compute trust scores
    trust_score = scorer.score(history)
    print(f"\nTrust score: {trust_score.overall:.3f}")
    for dimension, score in trust_score.by_dimension.items():
        print(f"  {dimension.value}: {score:.3f}")

    # Step 4: Derive trust level
    level = derive_level(trust_score.overall)
    print(f"\nDerived trust level: {level.name}")

    # Step 5: Evaluate against a policy
    policy = TrustPolicy(
        min_trust_score=0.6,
        required_level=TrustLevel.MEDIUM,
        blocked_dimensions=[],
    )
    policy_result = policy.evaluate(trust_score)
    print(f"\nPolicy evaluation:")
    print(f"  Passes policy: {policy_result.passes}")
    if not policy_result.passes:
        print(f"  Reason: {policy_result.reason}")


if __name__ == "__main__":
    main()
