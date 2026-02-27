"""AgentIdentity — core per-agent identity model with capabilities and restrictions.

Each AgentIdentity represents a single autonomous agent's identity record.
It bundles the agent's authorized capabilities, action restrictions, and
a configurable TTL so that identities can be issued for bounded time windows.
"""
from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass, field
from typing import Optional

from agent_identity.native.capability import Capability
from agent_identity.native.restriction import Enforcement, Restriction, RestrictionViolationError


@dataclass
class AgentIdentity:
    """Core identity record for an autonomous agent.

    Parameters
    ----------
    agent_id:
        Globally unique identifier for this agent (UUID string).
    name:
        Human-readable name for the agent (e.g. ``"billing-reconciler"``).
    owner:
        Principal who created / owns this identity (user ID or team name).
    capabilities:
        List of authorized capabilities. Empty means no authorizations.
    restrictions:
        List of action restrictions applied to this agent.
    ttl_seconds:
        Identity lifetime in seconds from ``created_at``. None means no expiry.
    created_at:
        UTC datetime when this identity was created. Auto-set by ``create()``.
    metadata:
        Arbitrary additional key-value metadata (tags, description, etc.).

    Examples
    --------
    >>> identity = AgentIdentity.create(name="my-agent", owner="alice")
    >>> identity.has_capability("read", "db:users")
    False
    """

    agent_id: str
    name: str
    owner: str
    capabilities: list[Capability] = field(default_factory=list)
    restrictions: list[Restriction] = field(default_factory=list)
    ttl_seconds: Optional[int] = None
    created_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    metadata: dict[str, object] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        name: str,
        owner: str,
        capabilities: list[Capability] | None = None,
        restrictions: list[Restriction] | None = None,
        ttl_seconds: Optional[int] = None,
        metadata: dict[str, object] | None = None,
    ) -> "AgentIdentity":
        """Create a new AgentIdentity with a freshly generated agent_id.

        Parameters
        ----------
        name:
            Human-readable agent name.
        owner:
            Principal who owns this identity.
        capabilities:
            Initial capabilities to grant (default: empty).
        restrictions:
            Initial restrictions to apply (default: empty).
        ttl_seconds:
            Identity TTL in seconds, or None for no expiry.
        metadata:
            Optional extra metadata.

        Returns
        -------
        AgentIdentity
        """
        return cls(
            agent_id=str(uuid.uuid4()),
            name=name,
            owner=owner,
            capabilities=capabilities or [],
            restrictions=restrictions or [],
            ttl_seconds=ttl_seconds,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Time validity
    # ------------------------------------------------------------------

    def is_expired(self) -> bool:
        """Return True when this identity has passed its TTL.

        Returns False when ``ttl_seconds`` is None.
        """
        if self.ttl_seconds is None:
            return False
        expiry = self.created_at + datetime.timedelta(seconds=self.ttl_seconds)
        return datetime.datetime.now(datetime.timezone.utc) > expiry

    def expires_at(self) -> Optional[datetime.datetime]:
        """Return the UTC expiry datetime, or None when there is no TTL."""
        if self.ttl_seconds is None:
            return None
        return self.created_at + datetime.timedelta(seconds=self.ttl_seconds)

    # ------------------------------------------------------------------
    # Capability management
    # ------------------------------------------------------------------

    def grant_capability(self, capability: Capability) -> None:
        """Add *capability* to this identity.

        Parameters
        ----------
        capability:
            The capability to grant.
        """
        self.capabilities.append(capability)

    def revoke_capability(self, action: str, resource: str) -> bool:
        """Remove the first capability matching *action* and *resource*.

        Parameters
        ----------
        action:
            The action to revoke.
        resource:
            The resource to revoke access to.

        Returns
        -------
        bool
            True when a matching capability was found and removed.
        """
        for i, cap in enumerate(self.capabilities):
            if cap.action == action and cap.resource == resource:
                self.capabilities.pop(i)
                return True
        return False

    def has_capability(
        self,
        action: str,
        resource: str,
        *,
        check_expiry: bool = True,
    ) -> bool:
        """Return True when this identity has a matching, non-expired capability.

        Parameters
        ----------
        action:
            The action to check authorization for.
        resource:
            The resource to check authorization for.
        check_expiry:
            When True (default), expired capabilities do not count.

        Returns
        -------
        bool
        """
        for cap in self.capabilities:
            if cap.matches(action, resource):
                if check_expiry and cap.is_expired():
                    continue
                return True
        return False

    def get_capabilities_for(self, action: str) -> list[Capability]:
        """Return all capabilities that authorize *action*."""
        return [cap for cap in self.capabilities if cap.matches_action(action)]

    # ------------------------------------------------------------------
    # Restriction management
    # ------------------------------------------------------------------

    def add_restriction(self, restriction: Restriction) -> None:
        """Add *restriction* to this identity.

        Parameters
        ----------
        restriction:
            The restriction to apply.
        """
        self.restrictions.append(restriction)

    def remove_restriction(self, action: str) -> bool:
        """Remove the first restriction matching *action*.

        Returns True when found and removed.
        """
        for i, rest in enumerate(self.restrictions):
            if rest.action == action:
                self.restrictions.pop(i)
                return True
        return False

    def is_restricted(self, action: str) -> bool:
        """Return True when any BLOCK restriction applies to *action*."""
        return any(
            rest.applies_to(action) and rest.enforcement == Enforcement.BLOCK
            for rest in self.restrictions
        )

    def enforce_restrictions(self, action: str) -> None:
        """Evaluate all restrictions for *action* and enforce them.

        Parameters
        ----------
        action:
            The action the agent is attempting.

        Raises
        ------
        RestrictionViolationError
            When any BLOCK restriction matches *action*.
        """
        for restriction in self.restrictions:
            restriction.enforce(action)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "owner": self.owner,
            "capabilities": [cap.to_dict() for cap in self.capabilities],
            "restrictions": [rest.to_dict() for rest in self.restrictions],
            "ttl_seconds": self.ttl_seconds,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "AgentIdentity":
        """Reconstruct an AgentIdentity from a plain dictionary."""
        return cls(
            agent_id=str(data["agent_id"]),
            name=str(data["name"]),
            owner=str(data["owner"]),
            capabilities=[
                Capability.from_dict(c) for c in (data.get("capabilities") or [])
            ],
            restrictions=[
                Restriction.from_dict(r) for r in (data.get("restrictions") or [])
            ],
            ttl_seconds=int(data["ttl_seconds"]) if data.get("ttl_seconds") else None,
            created_at=datetime.datetime.fromisoformat(str(data["created_at"])),
            metadata=dict(data.get("metadata") or {}),
        )

    def __repr__(self) -> str:
        return (
            f"AgentIdentity("
            f"agent_id={self.agent_id!r}, "
            f"name={self.name!r}, "
            f"owner={self.owner!r}, "
            f"capabilities={len(self.capabilities)}, "
            f"restrictions={len(self.restrictions)})"
        )
