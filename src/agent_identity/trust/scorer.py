"""TrustScorer — multi-dimensional trust scoring for AI agents.

Computes a weighted composite trust score from three dimensions:
competence, reliability, and integrity. The composite maps to a
TrustLevel via the thresholds defined in trust.level.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from agent_identity.trust.dimensions import DEFAULT_WEIGHTS, TrustDimension
from agent_identity.trust.level import TrustLevel, derive_level
from agent_identity.trust.policy import TrustPolicy


@dataclass
class TrustScore:
    """Computed trust score for a single agent at a point in time.

    Parameters
    ----------
    agent_id:
        The agent whose trust is being measured.
    dimensions:
        Per-dimension scores keyed by TrustDimension (0 – 100 each).
    composite:
        Weighted composite score derived from dimension scores and policy weights.
    level:
        TrustLevel derived from the composite score.
    timestamp:
        UTC datetime when this score was computed.
    """

    agent_id: str
    dimensions: dict[TrustDimension, float]
    composite: float
    level: TrustLevel
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "agent_id": self.agent_id,
            "dimensions": {dim.value: score for dim, score in self.dimensions.items()},
            "composite": self.composite,
            "level": self.level.name,
            "timestamp": self.timestamp.isoformat(),
        }


class TrustScorer:
    """Multi-dimensional trust scorer.

    Computes weighted composite trust scores from per-dimension scores.
    An optional TrustPolicy configures the dimension weights and score bounds.

    Parameters
    ----------
    policy:
        Trust policy defining weights, score bounds, and decay rates.
        Defaults to the standard policy with no customization.
    """

    def __init__(self, policy: TrustPolicy | None = None) -> None:
        self._policy: TrustPolicy = policy if policy is not None else TrustPolicy()
        self._policy.validate_weights()

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(
        self,
        agent_id: str,
        dimensions: dict[TrustDimension, float],
    ) -> TrustScore:
        """Compute a TrustScore for an agent from per-dimension scores.

        Dimensions not provided in ``dimensions`` default to 0.0.
        Each raw dimension score is clamped to [min_score, max_score] before
        weighting. The composite is also clamped to the same range.

        Parameters
        ----------
        agent_id:
            Identifier of the agent being scored.
        dimensions:
            Mapping of TrustDimension to its raw score (0 – 100).

        Returns
        -------
        TrustScore
            Fully computed trust score with composite and level.
        """
        weights = self._policy.dimension_weights
        min_s = self._policy.min_score
        max_s = self._policy.max_score

        clamped: dict[TrustDimension, float] = {}
        for dim in TrustDimension:
            raw = dimensions.get(dim, 0.0)
            clamped[dim] = max(min_s, min(max_s, raw))

        composite = sum(
            clamped[dim] * weights.get(dim, DEFAULT_WEIGHTS[dim])
            for dim in TrustDimension
        )
        composite = max(min_s, min(max_s, composite))
        level = derive_level(composite)

        return TrustScore(
            agent_id=agent_id,
            dimensions=clamped,
            composite=composite,
            level=level,
        )

    def apply_outcome(
        self,
        current_dimensions: dict[TrustDimension, float],
        outcome: str,
    ) -> dict[TrustDimension, float]:
        """Return updated dimension scores after applying an outcome delta.

        The outcome string must be one of "success", "failure", or "violation".
        Decay is applied before the delta, then scores are clamped to policy bounds.

        Parameters
        ----------
        current_dimensions:
            The current per-dimension scores.
        outcome:
            The observed outcome string.

        Returns
        -------
        dict[TrustDimension, float]
            Updated per-dimension scores after applying the outcome.

        Raises
        ------
        ValueError
            If ``outcome`` is not a recognised outcome string.
        """
        policy = self._policy
        min_s = policy.min_score
        max_s = policy.max_score
        decay = policy.decay_rate

        if outcome == "success":
            deltas: dict[TrustDimension, float] = {
                dim: policy.success_delta for dim in TrustDimension
            }
        elif outcome == "failure":
            deltas = {dim: policy.failure_delta for dim in TrustDimension}
        elif outcome == "violation":
            deltas = policy.violation_deltas
        else:
            raise ValueError(
                f"Unrecognised outcome {outcome!r}. "
                "Expected 'success', 'failure', or 'violation'."
            )

        updated: dict[TrustDimension, float] = {}
        for dim in TrustDimension:
            current = current_dimensions.get(dim, 0.0)
            decayed = current * decay
            new_score = decayed + deltas.get(dim, 0.0)
            updated[dim] = max(min_s, min(max_s, new_score))

        return updated
