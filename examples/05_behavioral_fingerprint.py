#!/usr/bin/env python3
"""Example: Behavioral Fingerprinting

Demonstrates building a behavioral fingerprint from agent observations
to detect anomalous behaviour patterns.

Usage:
    python examples/05_behavioral_fingerprint.py

Requirements:
    pip install agent-identity
"""
from __future__ import annotations

import agent_identity
from agent_identity import (
    BehavioralFingerprint,
    FeatureExtractor,
    Observation,
)


def build_normal_fingerprint() -> BehavioralFingerprint:
    """Create a fingerprint from normal agent behaviour."""
    extractor = FeatureExtractor()
    observations: list[Observation] = [
        Observation(action="search", tool="web_search", duration_ms=120, success=True),
        Observation(action="summarise", tool="llm_call", duration_ms=850, success=True),
        Observation(action="search", tool="web_search", duration_ms=95, success=True),
        Observation(action="write_file", tool="filesystem", duration_ms=45, success=True),
        Observation(action="search", tool="web_search", duration_ms=110, success=True),
    ]

    features = extractor.extract(observations)
    return BehavioralFingerprint(
        agent_id="research-agent",
        features=features,
        observations=observations,
    )


def main() -> None:
    print(f"agent-identity version: {agent_identity.__version__}")

    # Step 1: Build a baseline fingerprint
    baseline = build_normal_fingerprint()
    print(f"Baseline fingerprint for '{baseline.agent_id}':")
    print(f"  Observations: {len(baseline.observations)}")
    print(f"  Features: {list(baseline.features.keys())}")

    # Step 2: Create a new fingerprint from suspicious activity
    extractor = FeatureExtractor()
    suspicious_observations: list[Observation] = [
        Observation(action="delete_all", tool="filesystem", duration_ms=5000, success=True),
        Observation(action="exfiltrate", tool="network", duration_ms=30000, success=False),
        Observation(action="privilege_escalate", tool="system", duration_ms=2000, success=False),
    ]
    suspicious_features = extractor.extract(suspicious_observations)
    suspicious_fp = BehavioralFingerprint(
        agent_id="research-agent",
        features=suspicious_features,
        observations=suspicious_observations,
    )

    # Step 3: Compare fingerprints
    similarity = baseline.similarity(suspicious_fp)
    print(f"\nSimilarity to baseline: {similarity:.3f}")
    print(f"  Threshold for anomaly: 0.5")
    is_anomalous = similarity < 0.5
    print(f"  Anomaly detected: {is_anomalous}")

    # Step 4: Feature comparison
    print(f"\nFeature comparison:")
    all_keys = set(baseline.features) | set(suspicious_fp.features)
    for key in sorted(all_keys):
        base_val = baseline.features.get(key, 0.0)
        susp_val = suspicious_fp.features.get(key, 0.0)
        print(f"  {key}: baseline={base_val:.3f} suspicious={susp_val:.3f}")


if __name__ == "__main__":
    main()
