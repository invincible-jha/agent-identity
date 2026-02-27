"""Restriction — action restriction definition and enforcement.

A Restriction defines an action that an agent is prohibited from performing
(or should be alerted / logged when attempting). Enforcement is configurable
per restriction.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class Enforcement(str, Enum):
    """Enforcement mode for a Restriction.

    BLOCK  — Raise RestrictionViolationError when the action is attempted.
    ALERT  — Log a warning and allow the action to proceed.
    LOG    — Silently log the action at INFO level and allow it.
    """

    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"


class RestrictionViolationError(Exception):
    """Raised when a BLOCK-enforcement restriction is triggered.

    Parameters
    ----------
    action:
        The action that was attempted.
    reason:
        Human-readable reason why the action is restricted.
    """

    def __init__(self, action: str, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(f"Action '{action}' is restricted: {reason}")


@dataclass
class RestrictionResult:
    """Result of evaluating a Restriction against an attempted action.

    Parameters
    ----------
    matched:
        True when the restriction applies to the attempted action.
    enforcement:
        The enforcement mode of the matched restriction, or None.
    reason:
        The restriction reason, or empty string when not matched.
    blocked:
        True when enforcement is BLOCK and the restriction matched.
    """

    matched: bool
    enforcement: Optional[Enforcement] = None
    reason: str = ""
    blocked: bool = False


@dataclass
class Restriction:
    """A single action restriction with configurable enforcement.

    Parameters
    ----------
    action:
        The action being restricted. Use ``"*"`` to restrict all actions.
    enforcement:
        How the restriction is enforced when triggered (default BLOCK).
    reason:
        Human-readable explanation of why this action is restricted.
    metadata:
        Optional extra metadata (audit ticket ID, policy reference, etc.).

    Examples
    --------
    >>> restriction = Restriction(action="delete", reason="No deletions allowed")
    >>> result = restriction.evaluate("delete")
    >>> result.blocked
    True
    """

    action: str
    enforcement: Enforcement = Enforcement.BLOCK
    reason: str = ""
    metadata: dict[str, object] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def applies_to(self, attempted_action: str) -> bool:
        """Return True when this restriction applies to *attempted_action*.

        Wildcard ``"*"`` matches any action.
        """
        return self.action == "*" or self.action == attempted_action

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------

    def evaluate(self, attempted_action: str) -> RestrictionResult:
        """Evaluate this restriction against *attempted_action*.

        When the restriction applies:
        - BLOCK: returns a result with ``blocked=True`` (caller should
          raise ``RestrictionViolationError``).
        - ALERT: logs a warning and returns ``blocked=False``.
        - LOG: logs at INFO level and returns ``blocked=False``.

        Parameters
        ----------
        attempted_action:
            The action the agent is attempting.

        Returns
        -------
        RestrictionResult
        """
        if not self.applies_to(attempted_action):
            return RestrictionResult(matched=False)

        if self.enforcement == Enforcement.BLOCK:
            return RestrictionResult(
                matched=True,
                enforcement=self.enforcement,
                reason=self.reason,
                blocked=True,
            )

        if self.enforcement == Enforcement.ALERT:
            logger.warning(
                "Restriction ALERT: action '%s' is restricted. Reason: %s",
                attempted_action,
                self.reason,
            )
        else:  # LOG
            logger.info(
                "Restriction LOG: action '%s' observed. Reason: %s",
                attempted_action,
                self.reason,
            )

        return RestrictionResult(
            matched=True,
            enforcement=self.enforcement,
            reason=self.reason,
            blocked=False,
        )

    def enforce(self, attempted_action: str) -> None:
        """Evaluate and raise RestrictionViolationError for BLOCK violations.

        Parameters
        ----------
        attempted_action:
            The action the agent is attempting.

        Raises
        ------
        RestrictionViolationError
            When this restriction is BLOCK enforcement and the action matches.
        """
        result = self.evaluate(attempted_action)
        if result.blocked:
            raise RestrictionViolationError(attempted_action, self.reason)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "action": self.action,
            "enforcement": self.enforcement.value,
            "reason": self.reason,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Restriction":
        """Reconstruct a Restriction from a plain dictionary."""
        return cls(
            action=str(data["action"]),
            enforcement=Enforcement(str(data.get("enforcement", "block"))),
            reason=str(data.get("reason", "")),
            metadata=dict(data.get("metadata") or {}),
        )

    def __repr__(self) -> str:
        return (
            f"Restriction(action={self.action!r}, "
            f"enforcement={self.enforcement.value!r}, "
            f"reason={self.reason!r})"
        )
