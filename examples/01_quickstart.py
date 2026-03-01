#!/usr/bin/env python3
"""Example: Quickstart

Demonstrates the minimal setup for agent-identity using the Identity
convenience class to create and verify an agent identity.

Usage:
    python examples/01_quickstart.py

Requirements:
    pip install agent-identity
"""
from __future__ import annotations

import agent_identity
from agent_identity import Identity, TrustLevel


def main() -> None:
    print(f"agent-identity version: {agent_identity.__version__}")

    # Step 1: Create an agent identity
    identity = Identity(agent_id="quickstart-agent", metadata={"role": "assistant", "version": "1.0"})
    print(f"Identity created: agent_id={identity.agent_id}")

    # Step 2: Check trust level
    trust = identity.trust_level()
    print(f"Initial trust level: {trust.value if hasattr(trust, 'value') else trust}")

    # Step 3: Verify identity
    is_valid = identity.verify()
    print(f"Identity valid: {is_valid}")

    # Step 4: Show DID document
    did_doc = identity.did_document()
    print(f"DID: {did_doc.did[:40]}...")

    print("\nQuickstart complete.")


if __name__ == "__main__":
    main()
