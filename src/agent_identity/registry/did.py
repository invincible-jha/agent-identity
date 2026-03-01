"""DIDProvider — Decentralized Identifier management for agents.

Uses the ``did:aumos`` method. DIDs are formatted as::

    did:aumos:<agent_id>

Resolution maps a DID back to the registered AgentIdentityRecord.
Verification confirms that a DID matches the registered agent_id.

The module also exposes :meth:`DIDProvider.create_did_key` which creates a
``did:key`` (W3C standard, cryptographic) alongside the legacy ``did:aumos``
identifier. The ``did:key`` method requires the ``cryptography`` package::

    pip install agent-identity[crypto]
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_DID_METHOD = "aumos"
_DID_PATTERN = re.compile(r"^did:aumos:(?P<agent_id>.+)$")

# did:key support — optional; guarded import so the registry module loads
# correctly even without the cryptography package installed.
try:
    from agent_identity.did.did_key import DIDKeyDocument, DIDKeyProvider

    _DID_KEY_AVAILABLE = True
except ImportError:
    _DID_KEY_AVAILABLE = False


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
        # Lazily created when create_did_key() is first called.
        self._did_key_provider: object | None = None

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

    # ------------------------------------------------------------------
    # did:key support (requires cryptography package)
    # ------------------------------------------------------------------

    def create_did_key(self, agent_id: str) -> "DIDKeyDocument":
        """Create a W3C ``did:key`` identifier for an agent.

        This method provides a cryptographic ``did:key`` alongside the legacy
        ``did:aumos`` method. The ``did:key`` encodes the agent's Ed25519
        public key directly in the DID string, making it self-verifiable
        without any registry lookup.

        The ``cryptography`` package must be installed::

            pip install agent-identity[crypto]

        Parameters
        ----------
        agent_id:
            The logical agent identifier to associate with the new key.

        Returns
        -------
        DIDKeyDocument
            The newly created document, containing the DID, public key, and
            private key.

        Raises
        ------
        ImportError
            If the ``cryptography`` package is not installed.
        """
        if not _DID_KEY_AVAILABLE:
            raise ImportError(
                "did:key support requires the 'cryptography' package. "
                "Install it with: pip install agent-identity[crypto]"
            )
        if self._did_key_provider is None:
            self._did_key_provider = DIDKeyProvider()
        # The type ignore is safe: _DID_KEY_AVAILABLE guarantees DIDKeyProvider
        # was imported successfully.
        provider: DIDKeyProvider = self._did_key_provider  # type: ignore[assignment]
        return provider.create(agent_id)

    def resolve_did_key(self, did: str) -> "DIDKeyDocument":
        """Resolve a ``did:key`` string to its document.

        Decodes the public key encoded in the DID string. If the DID was
        created by this provider instance, the stored document (including
        the private key) is returned instead.

        Parameters
        ----------
        did:
            A ``did:key:z<encoded>`` string.

        Returns
        -------
        DIDKeyDocument
            The resolved document.

        Raises
        ------
        ImportError
            If the ``cryptography`` package is not installed.
        ValueError
            If the DID is malformed or uses an unsupported key type.
        """
        if not _DID_KEY_AVAILABLE:
            raise ImportError(
                "did:key support requires the 'cryptography' package. "
                "Install it with: pip install agent-identity[crypto]"
            )
        if self._did_key_provider is None:
            self._did_key_provider = DIDKeyProvider()
        provider: DIDKeyProvider = self._did_key_provider  # type: ignore[assignment]
        return provider.resolve(did)
