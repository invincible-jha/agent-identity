"""DIDProvider — Decentralized Identifier management for agents.

Uses the ``did:aumos`` method. DIDs are formatted as::

    did:aumos:<agent_id>

Resolution maps a DID back to the registered AgentIdentityRecord.
Verification confirms that a DID matches the registered agent_id.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_DID_METHOD = "aumos"
_DID_PATTERN = re.compile(r"^did:aumos:(?P<agent_id>.+)$")


@dataclass
class DIDDocument:
    """A minimal DID document for an agent.

    Parameters
    ----------
    did:
        The fully qualified DID string.
    agent_id:
        The agent identifier encoded in the DID.
    controller:
        The DID that controls this identity (same as did for self-sovereign).
    """

    did: str
    agent_id: str
    controller: str

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "id": self.did,
            "controller": self.controller,
            "agent_id": self.agent_id,
        }


class DIDResolutionError(Exception):
    """Raised when a DID cannot be resolved or verified."""


class DIDProvider:
    """Manages creation, resolution, and verification of ``did:aumos`` DIDs.

    This provider operates on a flat in-memory map of DID -> agent_id.
    It is designed to be used alongside IdentityRegistry: register an agent
    first, then call :meth:`create_did` to bind a DID to it.
    """

    def __init__(self) -> None:
        self._did_to_agent: dict[str, str] = {}
        self._agent_to_did: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create_did(self, agent_id: str) -> str:
        """Create and register a DID for the given agent.

        If a DID already exists for this agent, the existing DID is returned
        without creating a duplicate.

        Parameters
        ----------
        agent_id:
            The agent to create a DID for.

        Returns
        -------
        str
            The fully qualified DID string (``did:aumos:<agent_id>``).
        """
        if agent_id in self._agent_to_did:
            return self._agent_to_did[agent_id]

        did = f"did:{_DID_METHOD}:{agent_id}"
        self._did_to_agent[did] = agent_id
        self._agent_to_did[agent_id] = did
        return did

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve_did(self, did: str) -> DIDDocument:
        """Resolve a DID to a DIDDocument.

        Parameters
        ----------
        did:
            The fully qualified DID string to resolve.

        Returns
        -------
        DIDDocument
            The resolved document.

        Raises
        ------
        DIDResolutionError
            If the DID is malformed or not registered with this provider.
        """
        match = _DID_PATTERN.match(did)
        if not match:
            raise DIDResolutionError(
                f"Malformed DID {did!r}. Expected format: did:aumos:<agent_id>"
            )

        if did not in self._did_to_agent:
            raise DIDResolutionError(
                f"DID {did!r} is not registered with this provider."
            )

        agent_id = self._did_to_agent[did]
        return DIDDocument(
            did=did,
            agent_id=agent_id,
            controller=did,
        )

    def resolve_agent(self, agent_id: str) -> DIDDocument:
        """Resolve an agent_id to its DIDDocument.

        Parameters
        ----------
        agent_id:
            The agent whose DID document to retrieve.

        Returns
        -------
        DIDDocument

        Raises
        ------
        DIDResolutionError
            If no DID has been created for this agent.
        """
        if agent_id not in self._agent_to_did:
            raise DIDResolutionError(
                f"No DID registered for agent {agent_id!r}. "
                "Call create_did() first."
            )
        did = self._agent_to_did[agent_id]
        return self.resolve_did(did)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_did(self, did: str, expected_agent_id: str) -> bool:
        """Verify that a DID belongs to the expected agent.

        Parameters
        ----------
        did:
            The DID to verify.
        expected_agent_id:
            The agent_id the DID should resolve to.

        Returns
        -------
        bool
            True if the DID resolves to ``expected_agent_id``, False otherwise.
        """
        try:
            document = self.resolve_did(did)
        except DIDResolutionError:
            return False
        return document.agent_id == expected_agent_id

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def agent_id_from_did(did: str) -> str:
        """Extract the agent_id encoded in a well-formed DID without lookup.

        Parameters
        ----------
        did:
            A ``did:aumos:<agent_id>`` string.

        Returns
        -------
        str
            The agent_id portion.

        Raises
        ------
        DIDResolutionError
            If the DID is malformed.
        """
        match = _DID_PATTERN.match(did)
        if not match:
            raise DIDResolutionError(
                f"Malformed DID {did!r}. Expected format: did:aumos:<agent_id>"
            )
        return match.group("agent_id")

    def registered_dids(self) -> list[str]:
        """Return sorted list of all registered DID strings."""
        return sorted(self._did_to_agent.keys())
