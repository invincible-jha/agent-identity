"""BehavioralTrustScorer — dynamic trust scoring from agent behavior history.

Tracks task completions, failures, and policy violations per agent.
Computes a dynamic trust score using configurable weighted factors.
Trust decays on violations and grows on consecutive successes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    """Categories of behavioral events."""

    TASK_COMPLETION = "task_completion"
    TASK_FAILURE = "task_failure"
    POLICY_VIOLATION = "policy_violation"
    SECURITY_INCIDENT = "security_incident"
    HELPFUL_ACTION = "helpful_action"


@dataclass(frozen=True)
class ScorerConfig:
    """Configuration for BehavioralTrustScorer.

    Parameters
    ----------
    initial_score:
        Starting trust score for new agents (0 – 100).
    completion_delta:
        Score increase per task completion.
    failure_delta:
        Score decrease per task failure (should be negative).
    violation_delta:
        Score decrease per policy violation (should be negative).
    security_incident_delta:
        Score decrease per security incident (should be negative).
    helpful_action_delta:
        Score increase per helpful action.
    min_score:
        Minimum trust score (floor). Default 0.
    max_score:
        Maximum trust score (ceiling). Default 100.
    violation_decay_factor:
        Multiplier applied to score on violation (0 – 1). Compounded with delta.
    decay_per_hour:
        Passive score decay per hour of inactivity (0 – 1 fraction of score).
    consecutive_success_bonus:
        Additional bonus per consecutive successful task after the 3rd.
    """

    initial_score: float = 50.0
    completion_delta: float = 2.0
    failure_delta: float = -3.0
    violation_delta: float = -10.0
    security_incident_delta: float = -20.0
    helpful_action_delta: float = 1.0
    min_score: float = 0.0
    max_score: float = 100.0
    violation_decay_factor: float = 0.9
    decay_per_hour: float = 0.001
    consecutive_success_bonus: float = 0.5

    def __post_init__(self) -> None:
        if self.min_score >= self.max_score:
            raise ValueError(
                f"min_score ({self.min_score}) must be < max_score ({self.max_score})"
            )
        if not 0.0 <= self.violation_decay_factor <= 1.0:
            raise ValueError(
                f"violation_decay_factor must be in [0, 1], got {self.violation_decay_factor}"
            )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class BehaviorEvent:
    """A single behavioral event recorded for an agent.

    Parameters
    ----------
    event_type:
        The type of behavioral event.
    agent_id:
        The agent this event belongs to.
    description:
        Optional human-readable description.
    metadata:
        Optional additional context.
    timestamp:
        UTC datetime when the event occurred.
    """

    event_type: EventType
    agent_id: str
    description: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "description": self.description,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class BehavioralTrustScore:
    """A computed behavioral trust score for an agent.

    Parameters
    ----------
    agent_id:
        The scored agent.
    score:
        Trust score in [min_score, max_score].
    total_completions:
        Lifetime count of task completions.
    total_failures:
        Lifetime count of task failures.
    total_violations:
        Lifetime count of policy violations.
    consecutive_successes:
        Current run of consecutive task completions without failure.
    computed_at:
        UTC datetime when this score was computed.
    """

    agent_id: str
    score: float
    total_completions: int
    total_failures: int
    total_violations: int
    consecutive_successes: int
    computed_at: datetime

    @property
    def success_rate(self) -> float:
        """Ratio of completions to total task events (0 – 1)."""
        total_tasks = self.total_completions + self.total_failures
        if total_tasks == 0:
            return 0.0
        return self.total_completions / total_tasks

    @property
    def trust_level(self) -> str:
        """Qualitative trust level derived from score."""
        if self.score >= 80:
            return "high"
        if self.score >= 60:
            return "moderate"
        if self.score >= 40:
            return "low"
        if self.score >= 20:
            return "minimal"
        return "untrusted"

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "agent_id": self.agent_id,
            "score": round(self.score, 4),
            "trust_level": self.trust_level,
            "total_completions": self.total_completions,
            "total_failures": self.total_failures,
            "total_violations": self.total_violations,
            "consecutive_successes": self.consecutive_successes,
            "success_rate": round(self.success_rate, 4),
            "computed_at": self.computed_at.isoformat(),
        }


@dataclass
class _AgentState:
    """Internal mutable state for a single agent."""

    agent_id: str
    score: float
    total_completions: int = 0
    total_failures: int = 0
    total_violations: int = 0
    total_security_incidents: int = 0
    total_helpful_actions: int = 0
    consecutive_successes: int = 0
    last_event_at: datetime = field(default_factory=_utcnow)
    events: list[BehaviorEvent] = field(default_factory=list)


class BehavioralTrustScorer:
    """Dynamic trust scorer based on agent behavior history.

    Records behavioral events (task completions, failures, violations) and
    computes a trust score using configurable weighted deltas. Score decays
    passively over time and reacts strongly to violations.

    Parameters
    ----------
    config:
        Scoring configuration. Defaults to standard configuration.
    """

    def __init__(self, config: Optional[ScorerConfig] = None) -> None:
        self._config = config or ScorerConfig()
        self._agents: dict[str, _AgentState] = {}

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------

    def register_agent(self, agent_id: str, initial_score: Optional[float] = None) -> None:
        """Register an agent for behavioral trust tracking.

        Parameters
        ----------
        agent_id:
            Unique agent identifier.
        initial_score:
            Starting score. Defaults to ``config.initial_score``.

        Raises
        ------
        ValueError
            If the agent is already registered.
        """
        if agent_id in self._agents:
            raise ValueError(f"Agent {agent_id!r} is already registered.")
        starting_score = initial_score if initial_score is not None else self._config.initial_score
        clamped = max(self._config.min_score, min(self._config.max_score, starting_score))
        self._agents[agent_id] = _AgentState(agent_id=agent_id, score=clamped)

    def is_registered(self, agent_id: str) -> bool:
        """Return True if the agent is registered."""
        return agent_id in self._agents

    # ------------------------------------------------------------------
    # Event recording
    # ------------------------------------------------------------------

    def record_event(self, event: BehaviorEvent) -> BehavioralTrustScore:
        """Record a behavioral event and return the updated trust score.

        The agent is auto-registered if not already known.

        Parameters
        ----------
        event:
            The behavioral event to record.

        Returns
        -------
        BehavioralTrustScore
            Updated trust score after processing the event.
        """
        if event.agent_id not in self._agents:
            self.register_agent(event.agent_id)

        state = self._agents[event.agent_id]

        # Apply passive time-based decay first
        self._apply_time_decay(state, event.timestamp)

        # Apply event delta
        self._apply_event(state, event)

        # Store event
        state.events.append(event)
        state.last_event_at = event.timestamp

        return self._compute_score(state)

    def record_completion(
        self,
        agent_id: str,
        description: str = "",
        metadata: Optional[dict[str, str]] = None,
    ) -> BehavioralTrustScore:
        """Shorthand to record a task completion event."""
        return self.record_event(
            BehaviorEvent(
                event_type=EventType.TASK_COMPLETION,
                agent_id=agent_id,
                description=description,
                metadata=metadata or {},
            )
        )

    def record_failure(
        self,
        agent_id: str,
        description: str = "",
        metadata: Optional[dict[str, str]] = None,
    ) -> BehavioralTrustScore:
        """Shorthand to record a task failure event."""
        return self.record_event(
            BehaviorEvent(
                event_type=EventType.TASK_FAILURE,
                agent_id=agent_id,
                description=description,
                metadata=metadata or {},
            )
        )

    def record_violation(
        self,
        agent_id: str,
        description: str = "",
        metadata: Optional[dict[str, str]] = None,
    ) -> BehavioralTrustScore:
        """Shorthand to record a policy violation event."""
        return self.record_event(
            BehaviorEvent(
                event_type=EventType.POLICY_VIOLATION,
                agent_id=agent_id,
                description=description,
                metadata=metadata or {},
            )
        )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_score(self, agent_id: str, now: Optional[datetime] = None) -> Optional[BehavioralTrustScore]:
        """Return the current trust score for an agent.

        Parameters
        ----------
        agent_id:
            The agent to query.
        now:
            Reference time for passive decay (defaults to UTC now).

        Returns
        -------
        BehavioralTrustScore | None
            Current score, or None if agent is not registered.
        """
        state = self._agents.get(agent_id)
        if state is None:
            return None
        reference = now or _utcnow()
        self._apply_time_decay(state, reference)
        return self._compute_score(state)

    def get_history(self, agent_id: str) -> list[BehaviorEvent]:
        """Return all recorded events for an agent.

        Parameters
        ----------
        agent_id:
            The agent to query.

        Returns
        -------
        list[BehaviorEvent]
            Events in chronological order. Empty if agent not found.
        """
        state = self._agents.get(agent_id)
        if state is None:
            return []
        return list(state.events)

    def all_agents(self) -> list[str]:
        """Return all registered agent IDs."""
        return sorted(self._agents.keys())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_event(self, state: _AgentState, event: BehaviorEvent) -> None:
        """Apply the event's delta to the agent's state."""
        config = self._config

        if event.event_type == EventType.TASK_COMPLETION:
            state.total_completions += 1
            state.consecutive_successes += 1
            bonus = 0.0
            if state.consecutive_successes > 3:
                bonus = config.consecutive_success_bonus * (state.consecutive_successes - 3)
            state.score += config.completion_delta + bonus

        elif event.event_type == EventType.TASK_FAILURE:
            state.total_failures += 1
            state.consecutive_successes = 0
            state.score += config.failure_delta

        elif event.event_type == EventType.POLICY_VIOLATION:
            state.total_violations += 1
            state.consecutive_successes = 0
            # Apply multiplicative decay then additive penalty
            state.score = state.score * config.violation_decay_factor + config.violation_delta

        elif event.event_type == EventType.SECURITY_INCIDENT:
            state.total_security_incidents += 1
            state.consecutive_successes = 0
            state.score = state.score * config.violation_decay_factor + config.security_incident_delta

        elif event.event_type == EventType.HELPFUL_ACTION:
            state.total_helpful_actions += 1
            state.score += config.helpful_action_delta

        # Clamp score
        state.score = max(config.min_score, min(config.max_score, state.score))

    def _apply_time_decay(self, state: _AgentState, now: datetime) -> None:
        """Apply passive time-based score decay since last event."""
        if self._config.decay_per_hour <= 0.0:
            return
        elapsed = (now - state.last_event_at).total_seconds() / 3600.0
        if elapsed <= 0.0:
            return
        decay = self._config.decay_per_hour * elapsed
        state.score = max(
            self._config.min_score,
            state.score * (1.0 - min(1.0, decay)),
        )

    def _compute_score(self, state: _AgentState) -> BehavioralTrustScore:
        """Build a BehavioralTrustScore from current state."""
        return BehavioralTrustScore(
            agent_id=state.agent_id,
            score=round(state.score, 4),
            total_completions=state.total_completions,
            total_failures=state.total_failures,
            total_violations=state.total_violations,
            consecutive_successes=state.consecutive_successes,
            computed_at=_utcnow(),
        )


__all__ = [
    "BehavioralTrustScorer",
    "BehavioralTrustScore",
    "BehaviorEvent",
    "EventType",
    "ScorerConfig",
]
