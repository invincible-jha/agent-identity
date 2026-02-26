"""IdentityRegistry — central registry of all known agent identities.

Stores AgentIdentityRecord objects in memory keyed by agent_id. Supports
CRUD operations plus free-text and field-based search.
"""
from __future__ import annotations

import datetime
import threading
from dataclasses import dataclass, field


@dataclass
class AgentIdentityRecord:
    """The canonical identity record for a registered agent.

    Parameters
    ----------
    agent_id:
        Globally unique agent identifier (set at registration, immutable).
    display_name:
        Human-readable name for the agent.
    organization:
        Owning organization or deployment namespace.
    capabilities:
        List of capability strings the agent is authorized to exercise.
    metadata:
        Arbitrary key-value metadata attached to the agent.
    did:
        Decentralized Identifier for the agent (populated by DIDProvider).
    registered_at:
        UTC datetime when the agent was first registered.
    updated_at:
        UTC datetime of the most recent update to the record.
    active:
        Whether the agent is currently active. Deregistered agents are
        marked inactive rather than deleted.
    """

    agent_id: str
    display_name: str
    organization: str
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    did: str = ""
    registered_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    updated_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    active: bool = True

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "organization": self.organization,
            "capabilities": list(self.capabilities),
            "metadata": dict(self.metadata),
            "did": self.did,
            "registered_at": self.registered_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "active": self.active,
        }


class AgentAlreadyRegisteredError(ValueError):
    """Raised when attempting to register an agent_id that already exists."""

    def __init__(self, agent_id: str) -> None:
        super().__init__(
            f"Agent {agent_id!r} is already registered. "
            "Use update() to modify an existing record."
        )


class AgentNotFoundError(KeyError):
    """Raised when an agent_id is not present in the registry."""

    def __init__(self, agent_id: str) -> None:
        super().__init__(
            f"Agent {agent_id!r} is not registered. "
            "Use register() to add a new agent."
        )


class IdentityRegistry:
    """Central registry for agent identity records.

    Thread-safe. All mutations acquire a lock before modifying the
    internal store.

    Example
    -------
    ::

        registry = IdentityRegistry()
        record = registry.register(
            agent_id="agent-001",
            display_name="My Agent",
            organization="AumOS",
            capabilities=["read", "write"],
        )
        print(registry.get("agent-001").display_name)
    """

    def __init__(self) -> None:
        self._records: dict[str, AgentIdentityRecord] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(
        self,
        agent_id: str,
        display_name: str,
        organization: str,
        capabilities: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        did: str = "",
    ) -> AgentIdentityRecord:
        """Register a new agent identity.

        Parameters
        ----------
        agent_id:
            Unique identifier for the agent.
        display_name:
            Human-readable name.
        organization:
            Owning organization or namespace.
        capabilities:
            Optional list of capability strings.
        metadata:
            Optional key-value metadata.
        did:
            Optional Decentralized Identifier string.

        Returns
        -------
        AgentIdentityRecord
            The newly created record.

        Raises
        ------
        AgentAlreadyRegisteredError
            If an agent with this ID already exists.
        """
        with self._lock:
            if agent_id in self._records:
                raise AgentAlreadyRegisteredError(agent_id)
            now = datetime.datetime.now(datetime.timezone.utc)
            record = AgentIdentityRecord(
                agent_id=agent_id,
                display_name=display_name,
                organization=organization,
                capabilities=list(capabilities or []),
                metadata=dict(metadata or {}),
                did=did,
                registered_at=now,
                updated_at=now,
                active=True,
            )
            self._records[agent_id] = record
            return record

    def get(self, agent_id: str) -> AgentIdentityRecord:
        """Retrieve an agent identity record by ID.

        Parameters
        ----------
        agent_id:
            The agent to retrieve.

        Returns
        -------
        AgentIdentityRecord

        Raises
        ------
        AgentNotFoundError
            If no agent with this ID is registered.
        """
        with self._lock:
            if agent_id not in self._records:
                raise AgentNotFoundError(agent_id)
            return self._records[agent_id]

    def update(
        self,
        agent_id: str,
        display_name: str | None = None,
        organization: str | None = None,
        capabilities: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        did: str | None = None,
    ) -> AgentIdentityRecord:
        """Update mutable fields on an agent's identity record.

        Only fields provided (non-None) are updated. Returns the updated record.

        Parameters
        ----------
        agent_id:
            The agent to update.
        display_name:
            New display name, if changing.
        organization:
            New organization, if changing.
        capabilities:
            New capability list (replaces existing), if changing.
        metadata:
            New metadata dict (replaces existing), if changing.
        did:
            New DID string, if changing.

        Returns
        -------
        AgentIdentityRecord
            The updated record.

        Raises
        ------
        AgentNotFoundError
            If no agent with this ID is registered.
        """
        with self._lock:
            if agent_id not in self._records:
                raise AgentNotFoundError(agent_id)
            record = self._records[agent_id]
            if display_name is not None:
                record.display_name = display_name
            if organization is not None:
                record.organization = organization
            if capabilities is not None:
                record.capabilities = list(capabilities)
            if metadata is not None:
                record.metadata = dict(metadata)
            if did is not None:
                record.did = did
            record.updated_at = datetime.datetime.now(datetime.timezone.utc)
            return record

    def deregister(self, agent_id: str) -> None:
        """Mark an agent as inactive (soft-delete).

        The record is retained but ``active`` is set to False. This allows
        audit history to be preserved while preventing the agent from being
        treated as a live participant.

        Parameters
        ----------
        agent_id:
            The agent to deregister.

        Raises
        ------
        AgentNotFoundError
            If no agent with this ID is registered.
        """
        with self._lock:
            if agent_id not in self._records:
                raise AgentNotFoundError(agent_id)
            self._records[agent_id].active = False
            self._records[agent_id].updated_at = datetime.datetime.now(
                datetime.timezone.utc
            )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def list_all(self, include_inactive: bool = False) -> list[AgentIdentityRecord]:
        """Return all registered agent records.

        Parameters
        ----------
        include_inactive:
            If True, deregistered agents are included. Defaults to False.

        Returns
        -------
        list[AgentIdentityRecord]
            Records sorted by agent_id.
        """
        with self._lock:
            records = list(self._records.values())

        if not include_inactive:
            records = [r for r in records if r.active]
        return sorted(records, key=lambda r: r.agent_id)

    def search(
        self,
        query: str = "",
        organization: str | None = None,
        capability: str | None = None,
        include_inactive: bool = False,
    ) -> list[AgentIdentityRecord]:
        """Search for agents matching the given criteria.

        Parameters
        ----------
        query:
            Free-text string searched against agent_id and display_name
            (case-insensitive substring match). Empty string matches all.
        organization:
            If provided, only agents from this organization are returned.
        capability:
            If provided, only agents with this capability are returned.
        include_inactive:
            If True, deregistered agents are included. Defaults to False.

        Returns
        -------
        list[AgentIdentityRecord]
            Matching records sorted by agent_id.
        """
        results = self.list_all(include_inactive=include_inactive)
        query_lower = query.lower()

        if query_lower:
            results = [
                r
                for r in results
                if query_lower in r.agent_id.lower()
                or query_lower in r.display_name.lower()
            ]

        if organization is not None:
            results = [r for r in results if r.organization == organization]

        if capability is not None:
            results = [r for r in results if capability in r.capabilities]

        return results

    def __len__(self) -> int:
        """Return number of registered agents (including inactive)."""
        with self._lock:
            return len(self._records)

    def __contains__(self, agent_id: object) -> bool:
        """Support ``"agent-001" in registry`` membership test."""
        with self._lock:
            return agent_id in self._records
