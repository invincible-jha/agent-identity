"""Capability — typed capability definition and matching for agent identities.

A Capability represents a single action an agent is authorized to perform,
optionally scoped to a specific resource and constrained by additional
runtime parameters. Wildcard matching (``"*"``) is supported for both
action and resource fields.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Capability:
    """A single authorized action scoped to a resource.

    Parameters
    ----------
    action:
        The action being authorized (e.g. ``"read"``, ``"write"``,
        ``"execute"``). Use ``"*"`` to match any action.
    resource:
        The target resource path or identifier (e.g. ``"db:users"``).
        Use ``"*"`` to match any resource.
    constraints:
        Optional key-value pairs providing additional restrictions on the
        capability (e.g. ``{"max_rows": 1000}``).
    ttl_seconds:
        Optional lifetime for this specific capability in seconds. When
        set, ``is_expired()`` can be used to enforce time limits.
    granted_at:
        UTC datetime when this capability was granted. Defaults to now.

    Examples
    --------
    >>> cap = Capability(action="read", resource="db:users")
    >>> cap.matches("read", "db:users")
    True
    >>> cap.matches("write", "db:users")
    False
    """

    action: str
    resource: str
    constraints: dict[str, object] = field(default_factory=dict)
    ttl_seconds: Optional[int] = None
    granted_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def matches(self, action: str, resource: str) -> bool:
        """Return True when this capability authorizes *action* on *resource*.

        Wildcard ``"*"`` in either the capability's action or resource
        field matches any value.

        Parameters
        ----------
        action:
            The action being attempted.
        resource:
            The resource being targeted.

        Returns
        -------
        bool
        """
        action_matches = self.action == "*" or self.action == action
        resource_matches = self.resource == "*" or self.resource == resource
        return action_matches and resource_matches

    def matches_action(self, action: str) -> bool:
        """Return True when this capability's action matches *action*."""
        return self.action == "*" or self.action == action

    def matches_resource(self, resource: str) -> bool:
        """Return True when this capability's resource matches *resource*."""
        return self.resource == "*" or self.resource == resource

    # ------------------------------------------------------------------
    # Time validity
    # ------------------------------------------------------------------

    def is_expired(self) -> bool:
        """Return True when this capability has exceeded its TTL.

        Returns False when ``ttl_seconds`` is None (no expiry).
        """
        if self.ttl_seconds is None:
            return False
        expiry = self.granted_at + datetime.timedelta(seconds=self.ttl_seconds)
        return datetime.datetime.now(datetime.timezone.utc) > expiry

    def expires_at(self) -> Optional[datetime.datetime]:
        """Return the expiry datetime, or None when there is no TTL."""
        if self.ttl_seconds is None:
            return None
        return self.granted_at + datetime.timedelta(seconds=self.ttl_seconds)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "action": self.action,
            "resource": self.resource,
            "constraints": self.constraints,
            "ttl_seconds": self.ttl_seconds,
            "granted_at": self.granted_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Capability":
        """Reconstruct a Capability from a plain dictionary."""
        return cls(
            action=str(data["action"]),
            resource=str(data["resource"]),
            constraints=dict(data.get("constraints") or {}),
            ttl_seconds=int(data["ttl_seconds"]) if data.get("ttl_seconds") else None,
            granted_at=datetime.datetime.fromisoformat(str(data["granted_at"])),
        )

    def __str__(self) -> str:
        return f"{self.action}:{self.resource}"

    def __repr__(self) -> str:
        return (
            f"Capability(action={self.action!r}, resource={self.resource!r}, "
            f"constraints={self.constraints!r})"
        )
