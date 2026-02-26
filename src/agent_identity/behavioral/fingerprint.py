"""BehavioralFingerprint — snapshot of an agent's behavioral characteristics.

A fingerprint is a lightweight, serializable summary of behavioral metrics
captured at a point in time. It is used as a baseline for anomaly detection.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field


@dataclass
class BehavioralFingerprint:
    """Snapshot of behavioral metrics for an agent.

    Parameters
    ----------
    agent_id:
        The agent this fingerprint describes.
    tool_freq:
        Mapping of tool name to observed call count.
    avg_latency:
        Mean call latency in seconds across all tools.
    latency_stddev:
        Standard deviation of call latency in seconds.
    error_rate:
        Fraction of calls that resulted in errors (0.0 – 1.0).
    response_pattern:
        Arbitrary key-value metrics capturing response shape (e.g.,
        output token counts, structured vs. unstructured ratio).
    sample_count:
        Total number of observations used to build this fingerprint.
    captured_at:
        Timestamp when the fingerprint was created.
    """

    agent_id: str
    tool_freq: dict[str, int] = field(default_factory=dict)
    avg_latency: float = 0.0
    latency_stddev: float = 0.0
    error_rate: float = 0.0
    response_pattern: dict[str, float] = field(default_factory=dict)
    sample_count: int = 0
    captured_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary for storage."""
        return {
            "agent_id": self.agent_id,
            "tool_freq": self.tool_freq,
            "avg_latency": self.avg_latency,
            "latency_stddev": self.latency_stddev,
            "error_rate": self.error_rate,
            "response_pattern": self.response_pattern,
            "sample_count": self.sample_count,
            "captured_at": self.captured_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "BehavioralFingerprint":
        """Reconstruct from a plain dictionary."""
        return cls(
            agent_id=str(data["agent_id"]),
            tool_freq={str(k): int(v) for k, v in (data.get("tool_freq") or {}).items()},  # type: ignore[union-attr]
            avg_latency=float(data.get("avg_latency", 0.0)),
            latency_stddev=float(data.get("latency_stddev", 0.0)),
            error_rate=float(data.get("error_rate", 0.0)),
            response_pattern={
                str(k): float(v)
                for k, v in (data.get("response_pattern") or {}).items()  # type: ignore[union-attr]
            },
            sample_count=int(data.get("sample_count", 0)),
            captured_at=datetime.datetime.fromisoformat(str(data.get("captured_at", datetime.datetime.now(datetime.timezone.utc).isoformat()))),
        )
