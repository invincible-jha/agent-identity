"""Capability-based access control for agent identity."""

from __future__ import annotations

from agent_identity.capabilities.capability import (
    Capability,
    CapabilityChecker,
    CapabilityGrant,
    CheckResult,
)

__all__ = ["Capability", "CapabilityChecker", "CapabilityGrant", "CheckResult"]
