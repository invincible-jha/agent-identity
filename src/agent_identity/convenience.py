"""Convenience API for agent-identity — 3-line quickstart.

Example
-------
::

    from agent_identity import Identity
    identity = Identity.create("my-agent", owner="acme-corp")
    print(identity.record.agent_id)

"""
from __future__ import annotations

from typing import Any


class Identity:
    """Zero-config identity wrapper for the 80% use case.

    Use the ``create()`` class method to create and register a new
    agent identity in one call. Uses an in-memory registry.

    Example
    -------
    ::

        from agent_identity import Identity
        identity = Identity.create("research-agent", owner="ai-team")
        print(identity.record.agent_id)
        print(identity.record.organization)
    """

    _registry: Any = None  # shared in-memory registry for convenience API

    def __init__(self, record: Any, registry: Any) -> None:
        self._record = record
        self._registry = registry

    @classmethod
    def _get_registry(cls) -> Any:
        """Return or create the shared in-memory registry."""
        from agent_identity.registry.identity_registry import IdentityRegistry

        if cls._registry is None:
            cls._registry = IdentityRegistry()
        return cls._registry

    @classmethod
    def create(
        cls,
        name: str,
        owner: str,
        capabilities: list[str] | None = None,
    ) -> "Identity":
        """Create and register a new agent identity.

        Parameters
        ----------
        name:
            Human-readable display name for the agent.
        owner:
            Owning organization or team name.
        capabilities:
            Optional list of capability strings.

        Returns
        -------
        Identity
            The newly created and registered identity wrapper.

        Example
        -------
        ::

            from agent_identity import Identity
            identity = Identity.create("summarizer", owner="nlp-team")
            print(identity.agent_id)
        """
        import uuid

        registry = cls._get_registry()
        agent_id = f"{name}-{str(uuid.uuid4())[:8]}"

        record = registry.register(
            agent_id=agent_id,
            display_name=name,
            organization=owner,
            capabilities=capabilities or [],
        )
        return cls(record=record, registry=registry)

    @property
    def agent_id(self) -> str:
        """The agent's unique identifier."""
        return self._record.agent_id

    @property
    def record(self) -> Any:
        """The underlying AgentIdentityRecord."""
        return self._record

    def __repr__(self) -> str:
        return (
            f"Identity(agent_id={self._record.agent_id!r}, "
            f"name={self._record.display_name!r})"
        )
