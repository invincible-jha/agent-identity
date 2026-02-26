"""Multi-dimensional trust scoring for AI agents.

Trust is computed across three dimensions — competence, reliability, and
integrity — and aggregated into a composite score that maps to one of five
trust levels (UNTRUSTED through FULL).
"""
from __future__ import annotations

from agent_identity.trust.dimensions import TrustDimension
from agent_identity.trust.history import TrustHistory
from agent_identity.trust.level import TrustLevel, derive_level
from agent_identity.trust.policy import TrustPolicy
from agent_identity.trust.scorer import TrustScore, TrustScorer

__all__ = [
    "TrustDimension",
    "TrustHistory",
    "TrustLevel",
    "TrustPolicy",
    "TrustScore",
    "TrustScorer",
    "derive_level",
]
