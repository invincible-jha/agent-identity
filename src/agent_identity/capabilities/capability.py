"""Capability-based access control for AI agents.

A Capability grants an agent the right to perform specific actions on a
resource. CapabilityChecker evaluates whether an agent holds the required
capability for a requested action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Capability:
    """A capability grants the right to perform actions on a resource.

    Parameters
    ----------
    resource:
        The resource this capability applies to (e.g. ``"database:users"``,
        ``"api:payment"``, ``"tool:web_search"``).
    actions:
        List of permitted action strings (e.g. ``["read"]``,
        ``["read", "write", "delete"]``).
    expiry:
        Optional UTC datetime after which this capability is no longer valid.
        If None, the capability does not expire.
    conditions:
        Optional dict of additional conditions that must be satisfied.
        Keys and values are application-defined strings (e.g.
        ``{"ip_range": "10.0.0.0/8"}``). Conditions are stored but
        their evaluation is delegated to the caller.
    granted_at:
        UTC datetime when this capability was issued.
    capability_id:
        Optional unique identifier for this capability grant.
    """

    resource: str
    actions: list[str]
    expiry: Optional[datetime] = None
    conditions: dict[str, str] = field(default_factory=dict)
    granted_at: datetime = field(default_factory=_utcnow)
    capability_id: str = ""

    def __post_init__(self) -> None:
        if not self.resource:
            raise ValueError("Capability.resource must not be empty.")
        if not self.actions:
            raise ValueError("Capability.actions must contain at least one action.")
        for action in self.actions:
            if not action:
                raise ValueError("Capability.actions must not contain empty strings.")

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Return True if this capability has expired.

        Parameters
        ----------
        now:
            Reference time (defaults to UTC now).

        Returns
        -------
        bool
            True if expired, False if still valid or no expiry set.
        """
        if self.expiry is None:
            return False
        reference = now or _utcnow()
        return reference >= self.expiry

    def allows(self, action: str) -> bool:
        """Return True if this capability permits the given action.

        Does not check expiry — call ``is_expired()`` separately.

        Parameters
        ----------
        action:
            The action string to check against this capability's actions list.

        Returns
        -------
        bool
            True if the action is listed, False otherwise.
        """
        return action in self.actions

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "capability_id": self.capability_id,
            "resource": self.resource,
            "actions": list(self.actions),
            "expiry": self.expiry.isoformat() if self.expiry else None,
            "conditions": dict(self.conditions),
            "granted_at": self.granted_at.isoformat(),
        }


@dataclass(frozen=True)
class CheckResult:
    """Result of a capability check.

    Parameters
    ----------
    allowed:
        Whether the action is permitted.
    reason:
        Human-readable explanation of the decision.
    capability:
        The matching capability if allowed, else None.
    """

    allowed: bool
    reason: str
    capability: Optional[Capability] = None

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "capability": self.capability.to_dict() if self.capability else None,
        }


@dataclass
class CapabilityGrant:
    """Tracks all capabilities granted to a specific agent.

    Parameters
    ----------
    agent_id:
        Identifier of the agent holding these capabilities.
    """

    agent_id: str
    _capabilities: list[Capability] = field(default_factory=list, init=False)

    def grant(self, capability: Capability) -> None:
        """Grant a new capability to this agent.

        Parameters
        ----------
        capability:
            The capability to add.
        """
        self._capabilities.append(capability)

    def revoke(self, resource: str, action: Optional[str] = None) -> int:
        """Revoke capabilities matching a resource (and optionally an action).

        Parameters
        ----------
        resource:
            The resource identifier to match.
        action:
            If provided, only revoke capabilities that include this action.
            If None, revoke all capabilities for the resource.

        Returns
        -------
        int
            Number of capabilities removed.
        """
        before = len(self._capabilities)
        if action is None:
            self._capabilities = [
                cap for cap in self._capabilities if cap.resource != resource
            ]
        else:
            self._capabilities = [
                cap for cap in self._capabilities
                if not (cap.resource == resource and action in cap.actions)
            ]
        return before - len(self._capabilities)

    def active_capabilities(
        self,
        now: Optional[datetime] = None,
    ) -> list[Capability]:
        """Return non-expired capabilities.

        Parameters
        ----------
        now:
            Reference time (defaults to UTC now).

        Returns
        -------
        list[Capability]
            Capabilities that have not yet expired.
        """
        reference = now or _utcnow()
        return [cap for cap in self._capabilities if not cap.is_expired(now=reference)]

    def all_capabilities(self) -> list[Capability]:
        """Return all capabilities (including expired)."""
        return list(self._capabilities)


class CapabilityChecker:
    """Evaluates whether an agent has the required capability for an action.

    Parameters
    ----------
    strict_expiry:
        If True (default), expired capabilities are treated as denied.
    """

    def __init__(self, strict_expiry: bool = True) -> None:
        self._strict_expiry = strict_expiry
        self._grants: dict[str, CapabilityGrant] = {}

    # ------------------------------------------------------------------
    # Grant management
    # ------------------------------------------------------------------

    def register_agent(self, agent_id: str) -> None:
        """Register an agent with the checker.

        Parameters
        ----------
        agent_id:
            Unique agent identifier.

        Raises
        ------
        ValueError
            If the agent is already registered.
        """
        if agent_id in self._grants:
            raise ValueError(f"Agent {agent_id!r} is already registered.")
        self._grants[agent_id] = CapabilityGrant(agent_id=agent_id)

    def grant_capability(self, agent_id: str, capability: Capability) -> None:
        """Grant a capability to an agent, registering the agent if needed.

        Parameters
        ----------
        agent_id:
            Identifier of the agent to grant to.
        capability:
            The capability to grant.
        """
        if agent_id not in self._grants:
            self._grants[agent_id] = CapabilityGrant(agent_id=agent_id)
        self._grants[agent_id].grant(capability)

    def revoke_capability(
        self,
        agent_id: str,
        resource: str,
        action: Optional[str] = None,
    ) -> int:
        """Revoke capabilities for an agent.

        Parameters
        ----------
        agent_id:
            The agent to revoke from.
        resource:
            Resource to match.
        action:
            If provided, only revoke for this action.

        Returns
        -------
        int
            Number of capabilities revoked (0 if agent not found).
        """
        grant = self._grants.get(agent_id)
        if grant is None:
            return 0
        return grant.revoke(resource=resource, action=action)

    # ------------------------------------------------------------------
    # Checking
    # ------------------------------------------------------------------

    def check(
        self,
        agent_id: str,
        resource: str,
        action: str,
        now: Optional[datetime] = None,
    ) -> CheckResult:
        """Check whether an agent is permitted to perform an action on a resource.

        Parameters
        ----------
        agent_id:
            The agent requesting the action.
        resource:
            The target resource.
        action:
            The action being requested.
        now:
            Reference time for expiry checks (defaults to UTC now).

        Returns
        -------
        CheckResult
            Contains ``allowed`` flag, explanation, and matching capability.
        """
        grant = self._grants.get(agent_id)
        if grant is None:
            return CheckResult(
                allowed=False,
                reason=f"Agent {agent_id!r} has no registered capabilities.",
            )

        reference = now or _utcnow()

        for capability in grant.all_capabilities():
            if capability.resource != resource:
                continue
            if not capability.allows(action):
                continue

            # Matching resource + action found
            if self._strict_expiry and capability.is_expired(now=reference):
                return CheckResult(
                    allowed=False,
                    reason=(
                        f"Capability for resource {resource!r} action {action!r} "
                        f"expired at {capability.expiry!s}."
                    ),
                    capability=capability,
                )

            return CheckResult(
                allowed=True,
                reason=(
                    f"Agent {agent_id!r} has active capability for "
                    f"resource {resource!r} action {action!r}."
                ),
                capability=capability,
            )

        return CheckResult(
            allowed=False,
            reason=(
                f"Agent {agent_id!r} has no capability for "
                f"resource {resource!r} action {action!r}."
            ),
        )

    def list_agent_capabilities(
        self,
        agent_id: str,
        include_expired: bool = False,
        now: Optional[datetime] = None,
    ) -> list[Capability]:
        """Return all capabilities for an agent.

        Parameters
        ----------
        agent_id:
            The agent to query.
        include_expired:
            If True, include expired capabilities. Defaults to False.
        now:
            Reference time for expiry checks.

        Returns
        -------
        list[Capability]
            Matching capabilities.
        """
        grant = self._grants.get(agent_id)
        if grant is None:
            return []
        if include_expired:
            return grant.all_capabilities()
        return grant.active_capabilities(now=now)

    def registered_agents(self) -> list[str]:
        """Return all registered agent IDs."""
        return sorted(self._grants.keys())


__all__ = ["Capability", "CapabilityChecker", "CapabilityGrant", "CheckResult"]
