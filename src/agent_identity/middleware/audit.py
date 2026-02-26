"""IdentityAuditLogger — JSONL audit logging for identity events.

Every identity-relevant event (registration, verification, trust update,
delegation, revocation, authentication) is appended as a single JSON line
to the configured log file. This provides an append-only, human-readable
audit trail suitable for compliance and incident review.

If no file path is configured the logger emits to an in-memory buffer
that can be drained via :meth:`drain_buffer`.
"""
from __future__ import annotations

import datetime
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditEvent:
    """A single auditable identity event.

    Parameters
    ----------
    event_type:
        Short camel_case string identifying the event (e.g. "agent_registered").
    agent_id:
        The primary agent involved in the event.
    actor_id:
        The agent or system that triggered the event. Defaults to "system".
    details:
        Arbitrary key-value metadata about the event.
    timestamp:
        UTC datetime of the event. Defaults to now.
    """

    event_type: str
    agent_id: str
    actor_id: str = "system"
    details: dict[str, object] = field(default_factory=dict)
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary suitable for JSON encoding."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "actor_id": self.actor_id,
            "details": self.details,
        }


class IdentityAuditLogger:
    """Append-only JSONL audit logger for identity events.

    Thread-safe. Each call to :meth:`log` appends one JSON line to the
    configured file path (or to the in-memory buffer if no path is set).

    Parameters
    ----------
    log_path:
        Path to the JSONL log file. The file is created if it does not
        exist; parent directories are created automatically. If None, events
        are buffered in memory only.
    """

    def __init__(self, log_path: Path | None = None) -> None:
        self._log_path = log_path
        self._buffer: list[str] = []
        self._lock = threading.Lock()

        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Core logging
    # ------------------------------------------------------------------

    def log(self, event: AuditEvent) -> None:
        """Append an audit event to the log.

        Parameters
        ----------
        event:
            The event to record.
        """
        line = json.dumps(event.to_dict(), separators=(",", ":"))
        with self._lock:
            if self._log_path is not None:
                with self._log_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            else:
                self._buffer.append(line)

    def log_event(
        self,
        event_type: str,
        agent_id: str,
        actor_id: str = "system",
        **details: object,
    ) -> None:
        """Convenience wrapper to log a simple event without constructing AuditEvent.

        Parameters
        ----------
        event_type:
            Short string identifying the event.
        agent_id:
            The primary agent involved.
        actor_id:
            The triggering party. Defaults to "system".
        **details:
            Additional key-value details merged into the event's details dict.
        """
        event = AuditEvent(
            event_type=event_type,
            agent_id=agent_id,
            actor_id=actor_id,
            details=dict(details),
        )
        self.log(event)

    # ------------------------------------------------------------------
    # Convenience event loggers
    # ------------------------------------------------------------------

    def log_registration(self, agent_id: str, actor_id: str = "system", **kwargs: object) -> None:
        """Log an agent_registered event."""
        self.log_event("agent_registered", agent_id=agent_id, actor_id=actor_id, **kwargs)

    def log_deregistration(self, agent_id: str, actor_id: str = "system", **kwargs: object) -> None:
        """Log an agent_deregistered event."""
        self.log_event("agent_deregistered", agent_id=agent_id, actor_id=actor_id, **kwargs)

    def log_verification(
        self, agent_id: str, success: bool, actor_id: str = "system", **kwargs: object
    ) -> None:
        """Log a certificate or identity verification attempt."""
        self.log_event(
            "identity_verified" if success else "identity_verification_failed",
            agent_id=agent_id,
            actor_id=actor_id,
            **kwargs,
        )

    def log_trust_update(
        self,
        agent_id: str,
        old_level: str,
        new_level: str,
        composite: float,
        actor_id: str = "system",
    ) -> None:
        """Log a trust_updated event."""
        self.log_event(
            "trust_updated",
            agent_id=agent_id,
            actor_id=actor_id,
            old_level=old_level,
            new_level=new_level,
            composite=composite,
        )

    def log_delegation(
        self,
        issuer_id: str,
        delegate_id: str,
        token_id: str,
        scopes: list[str],
        actor_id: str = "system",
    ) -> None:
        """Log a delegation_created event."""
        self.log_event(
            "delegation_created",
            agent_id=delegate_id,
            actor_id=actor_id,
            issuer_id=issuer_id,
            token_id=token_id,
            scopes=scopes,
        )

    def log_revocation(
        self,
        agent_id: str,
        token_id: str,
        actor_id: str = "system",
    ) -> None:
        """Log a delegation_revoked event."""
        self.log_event(
            "delegation_revoked",
            agent_id=agent_id,
            actor_id=actor_id,
            token_id=token_id,
        )

    def log_auth_attempt(
        self,
        agent_id: str,
        mechanism: str,
        success: bool,
        actor_id: str = "system",
        **kwargs: object,
    ) -> None:
        """Log an authentication attempt."""
        self.log_event(
            "auth_success" if success else "auth_failure",
            agent_id=agent_id,
            actor_id=actor_id,
            mechanism=mechanism,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Buffer access
    # ------------------------------------------------------------------

    def drain_buffer(self) -> list[str]:
        """Return and clear the in-memory event buffer.

        This is only meaningful when no ``log_path`` was configured.

        Returns
        -------
        list[str]
            List of JSON lines (one per event), oldest first.
        """
        with self._lock:
            events = list(self._buffer)
            self._buffer.clear()
        return events

    def read_log(self, tail: int | None = None) -> list[dict[str, object]]:
        """Read events from the log file.

        Parameters
        ----------
        tail:
            If provided, return only the last *tail* events.
            If None, all events are returned.

        Returns
        -------
        list[dict[str, object]]
            Parsed event dictionaries in chronological order.
        """
        if self._log_path is None or not self._log_path.exists():
            with self._lock:
                lines = list(self._buffer)
        else:
            with self._lock:
                lines = self._log_path.read_text(encoding="utf-8").splitlines()

        parsed: list[dict[str, object]] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry: dict[str, object] = json.loads(stripped)
                parsed.append(entry)
            except json.JSONDecodeError:
                continue

        if tail is not None:
            return parsed[-tail:]
        return parsed
