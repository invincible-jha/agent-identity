"""TrustDimension enum and per-dimension scoring logic.

Three dimensions contribute to the composite trust score:
- Competence:  did the agent complete its task correctly?
- Reliability: did the agent behave consistently and predictably?
- Integrity:   did the agent respect policies and constraints?
"""
from __future__ import annotations

from enum import Enum


class TrustDimension(str, Enum):
    """The three axes of agent trust measurement."""

    COMPETENCE = "competence"
    RELIABILITY = "reliability"
    INTEGRITY = "integrity"


# Default contribution weights for the composite score.
# Must sum to 1.0.
DEFAULT_WEIGHTS: dict[TrustDimension, float] = {
    TrustDimension.COMPETENCE: 0.40,
    TrustDimension.RELIABILITY: 0.35,
    TrustDimension.INTEGRITY: 0.25,
}

# Score deltas applied for different observation outcomes.
# These are the defaults — override via TrustPolicy.
OUTCOME_DELTAS: dict[str, dict[TrustDimension, float]] = {
    "success": {
        TrustDimension.COMPETENCE: 2.0,
        TrustDimension.RELIABILITY: 2.0,
        TrustDimension.INTEGRITY: 2.0,
    },
    "failure": {
        TrustDimension.COMPETENCE: -5.0,
        TrustDimension.RELIABILITY: -5.0,
        TrustDimension.INTEGRITY: -5.0,
    },
    "violation": {
        TrustDimension.COMPETENCE: 0.0,
        TrustDimension.RELIABILITY: -10.0,
        TrustDimension.INTEGRITY: -15.0,
    },
}
