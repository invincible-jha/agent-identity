"""TrustPolicy — configurable thresholds, weights, and decay rates.

Policies allow operators to tune trust dynamics for their deployment.
Sensible defaults are provided for all parameters.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from agent_identity.trust.dimensions import TrustDimension


class TrustPolicy(BaseModel):
    """Configurable trust scoring policy.

    Parameters
    ----------
    dimension_weights:
        Fractional weight for each trust dimension in the composite score.
        Values must sum to 1.0.
    success_delta:
        Score increase applied per dimension on a successful outcome.
    failure_delta:
        Score decrease applied per dimension on a failure outcome.
    violation_delta:
        Per-dimension score decreases on a policy violation.
    decay_rate:
        Multiplicative decay applied to dimension scores on each update
        (1.0 = no decay, 0.99 = 1% decay per observation).
    min_score:
        Floor for any individual dimension score.
    max_score:
        Ceiling for any individual dimension score.
    """

    dimension_weights: dict[TrustDimension, float] = Field(
        default_factory=lambda: {
            TrustDimension.COMPETENCE: 0.40,
            TrustDimension.RELIABILITY: 0.35,
            TrustDimension.INTEGRITY: 0.25,
        }
    )
    success_delta: float = 2.0
    failure_delta: float = -5.0
    violation_deltas: dict[TrustDimension, float] = Field(
        default_factory=lambda: {
            TrustDimension.COMPETENCE: 0.0,
            TrustDimension.RELIABILITY: -10.0,
            TrustDimension.INTEGRITY: -15.0,
        }
    )
    decay_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    min_score: float = 0.0
    max_score: float = 100.0

    model_config = {"arbitrary_types_allowed": True}

    def validate_weights(self) -> None:
        """Raise ValueError if dimension weights do not sum to 1.0."""
        total = sum(self.dimension_weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Dimension weights must sum to 1.0, got {total:.6f}"
            )
