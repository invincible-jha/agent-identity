"""TrustLevel enumeration and level derivation from composite scores.

Five trust levels are defined. Level boundaries use half-open intervals
so that each score maps to exactly one level.
"""
from __future__ import annotations

from enum import IntEnum


class TrustLevel(IntEnum):
    """Enumerated trust tiers for an agent.

    Values are ordered so that higher integers represent higher trust.

    UNTRUSTED (0):
        Agent has not yet demonstrated reliable behaviour or has had
        violations recorded. No privileged actions permitted.
    BASIC (1):
        Minimal trust established — limited read-only or low-risk actions.
    STANDARD (2):
        Moderate trust — most everyday agent tasks are permitted.
    ELEVATED (3):
        High trust — agent may perform consequential or sensitive actions.
    FULL (4):
        Maximum trust — unrestricted within organizational policy.
    """

    UNTRUSTED = 0
    BASIC = 1
    STANDARD = 2
    ELEVATED = 3
    FULL = 4


# Minimum composite score required to reach each level.
# Scores below LEVEL_THRESHOLDS[BASIC] map to UNTRUSTED.
LEVEL_THRESHOLDS: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: float("-inf"),
    TrustLevel.BASIC: 20.0,
    TrustLevel.STANDARD: 40.0,
    TrustLevel.ELEVATED: 65.0,
    TrustLevel.FULL: 85.0,
}


def derive_level(composite_score: float) -> TrustLevel:
    """Map a composite trust score to a TrustLevel.

    Uses the LEVEL_THRESHOLDS table. The highest level whose threshold
    does not exceed *composite_score* is returned.

    Parameters
    ----------
    composite_score:
        Composite trust score (typically 0 – 100).

    Returns
    -------
    TrustLevel
        The corresponding trust level.
    """
    level = TrustLevel.UNTRUSTED
    for candidate, threshold in sorted(LEVEL_THRESHOLDS.items(), key=lambda kv: kv[1]):
        if composite_score >= threshold:
            level = candidate
    return level
