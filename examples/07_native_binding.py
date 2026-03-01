#!/usr/bin/env python3
"""Example: Native Identity Binding

Demonstrates binding agent identities to native runtime environments
using NativeIdentityBinder and resolve_binding.

Usage:
    python examples/07_native_binding.py

Requirements:
    pip install agent-identity
"""
from __future__ import annotations

import agent_identity
from agent_identity import (
    NativeIdentityBinder,
    IdentityBinding,
    BindingMethod,
    BindingStore,
    resolve_binding,
    ResolutionResult,
)


def main() -> None:
    print(f"agent-identity version: {agent_identity.__version__}")

    # Step 1: Create a native identity binder
    binder = NativeIdentityBinder()
    print(f"NativeIdentityBinder created.")

    # Step 2: Create bindings for different agent runtimes
    binding_store = BindingStore()
    bindings: list[IdentityBinding] = [
        IdentityBinding(
            agent_id="docker-agent",
            method=BindingMethod.CONTAINER_ID,
            binding_value="sha256:abc123def456",
            metadata={"image": "aumos-agent:1.0"},
        ),
        IdentityBinding(
            agent_id="process-agent",
            method=BindingMethod.PROCESS_ID,
            binding_value="12345",
            metadata={"host": "worker-node-01"},
        ),
        IdentityBinding(
            agent_id="k8s-agent",
            method=BindingMethod.SERVICE_ACCOUNT,
            binding_value="aumos-agent-sa",
            metadata={"namespace": "production", "cluster": "main"},
        ),
    ]

    for binding in bindings:
        binding_store.add(binding)
        print(f"  Bound '{binding.agent_id}' via {binding.method.value}: {binding.binding_value[:20]}")

    print(f"\nBinding store: {binding_store.count()} bindings")

    # Step 3: Resolve bindings
    print("\nBinding resolution:")
    for binding in bindings:
        result: ResolutionResult = resolve_binding(
            method=binding.method,
            binding_value=binding.binding_value,
            store=binding_store,
        )
        status = "RESOLVED" if result.found else "NOT FOUND"
        print(f"  [{status}] {binding.method.value}:{binding.binding_value[:15]} -> {result.agent_id}")

    # Step 4: Verify a binding
    test_binding = bindings[0]
    is_valid = binder.verify(test_binding)
    print(f"\nBinding verification for '{test_binding.agent_id}': valid={is_valid}")

    # Step 5: Show binding metadata
    for binding in bindings[:2]:
        print(f"\nBinding metadata for '{binding.agent_id}':")
        for key, value in binding.metadata.items():
            print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
