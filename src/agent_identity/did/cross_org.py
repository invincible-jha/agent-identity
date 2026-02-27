"""CrossOrgVerifier — verify DID documents from external organizations.

Implements a trust anchor chain model: a root trust anchor is registered,
and external DID documents are accepted only if their org segment appears
in the trust anchor chain (direct trust or transitively trusted org).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from agent_identity.did.document import DIDDocument, _parse_did_agent


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class TrustAnchor:
    """A trusted organization in the trust anchor chain.

    Parameters
    ----------
    org:
        Organization identifier (matches the ``<org>`` segment in a DID).
    display_name:
        Human-readable name for this organization.
    trusted_at:
        UTC datetime when this anchor was established.
    trusted_by:
        Org identifier of the entity that established this trust.
        None for root anchors.
    """

    org: str
    display_name: str
    trusted_at: datetime = field(default_factory=_utcnow)
    trusted_by: Optional[str] = None

    def is_root(self) -> bool:
        """Return True if this is a root trust anchor (trusted_by is None)."""
        return self.trusted_by is None

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "org": self.org,
            "display_name": self.display_name,
            "trusted_at": self.trusted_at.isoformat(),
            "trusted_by": self.trusted_by,
            "is_root": self.is_root(),
        }


@dataclass(frozen=True)
class VerificationOutcome:
    """Result of a cross-org DID document verification.

    Parameters
    ----------
    did:
        The DID that was verified.
    org:
        Organization segment extracted from the DID.
    trusted:
        Whether the organization is in the trust anchor chain.
    trust_path:
        Chain of orgs from the verified org to the root anchor.
    reason:
        Human-readable explanation.
    verified_at:
        UTC datetime of the verification.
    """

    did: str
    org: str
    trusted: bool
    trust_path: list[str]
    reason: str
    verified_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "did": self.did,
            "org": self.org,
            "trusted": self.trusted,
            "trust_path": self.trust_path,
            "reason": self.reason,
            "verified_at": self.verified_at.isoformat(),
        }


class CrossOrgVerifier:
    """Verify DID documents from external organizations via trust anchor chains.

    A trust anchor chain models transitive trust: if org A trusts org B,
    and org B trusts org C, then org A transitively trusts org C.
    Verification passes only if the DID's org can be reached from any
    established trust anchor.

    Parameters
    ----------
    max_chain_depth:
        Maximum depth to traverse when resolving trust chains.
        Prevents infinite loops in circular trust configurations.
    """

    def __init__(self, max_chain_depth: int = 10) -> None:
        self._anchors: dict[str, TrustAnchor] = {}
        self._max_chain_depth = max_chain_depth

    # ------------------------------------------------------------------
    # Trust anchor management
    # ------------------------------------------------------------------

    def add_root_anchor(self, org: str, display_name: str) -> TrustAnchor:
        """Add a root trust anchor (self-trusted organization).

        Parameters
        ----------
        org:
            Organization identifier.
        display_name:
            Human-readable display name.

        Returns
        -------
        TrustAnchor
            The created root anchor.
        """
        anchor = TrustAnchor(org=org, display_name=display_name, trusted_by=None)
        self._anchors[org] = anchor
        return anchor

    def add_delegated_anchor(
        self,
        org: str,
        display_name: str,
        trusted_by: str,
    ) -> TrustAnchor:
        """Add a delegated trust anchor (trusted by an existing anchor).

        Parameters
        ----------
        org:
            Organization identifier to trust.
        display_name:
            Human-readable display name.
        trusted_by:
            Org identifier of the trusting party (must already be anchored).

        Returns
        -------
        TrustAnchor
            The created delegated anchor.

        Raises
        ------
        ValueError
            If ``trusted_by`` is not a known trust anchor.
        """
        if trusted_by not in self._anchors:
            raise ValueError(
                f"trusted_by org {trusted_by!r} is not a known trust anchor. "
                "Register it first with add_root_anchor or add_delegated_anchor."
            )
        anchor = TrustAnchor(org=org, display_name=display_name, trusted_by=trusted_by)
        self._anchors[org] = anchor
        return anchor

    def remove_anchor(self, org: str) -> bool:
        """Remove a trust anchor.

        Parameters
        ----------
        org:
            Organization to remove from the trust chain.

        Returns
        -------
        bool
            True if removed, False if not found.
        """
        if org not in self._anchors:
            return False
        del self._anchors[org]
        return True

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_document(self, document: DIDDocument) -> VerificationOutcome:
        """Verify a DID document against the trust anchor chain.

        Extracts the org from the document's DID and checks whether it
        is reachable in the trust anchor chain.

        Parameters
        ----------
        document:
            The DIDDocument to verify.

        Returns
        -------
        VerificationOutcome
            Verification result with trust path.
        """
        return self.verify_did(document.id)

    def verify_did(self, did: str) -> VerificationOutcome:
        """Verify a DID string against the trust anchor chain.

        Parameters
        ----------
        did:
            The DID string to verify (must be ``did:agent:<org>:<name>`` format).

        Returns
        -------
        VerificationOutcome
            Verification result with trust path.
        """
        now = _utcnow()

        try:
            org, _ = _parse_did_agent(did)
        except ValueError as exc:
            return VerificationOutcome(
                did=did,
                org="",
                trusted=False,
                trust_path=[],
                reason=f"Invalid DID format: {exc}",
                verified_at=now,
            )

        if not self._anchors:
            return VerificationOutcome(
                did=did,
                org=org,
                trusted=False,
                trust_path=[],
                reason="No trust anchors are configured.",
                verified_at=now,
            )

        trust_path = self._resolve_trust_path(org)

        if trust_path:
            return VerificationOutcome(
                did=did,
                org=org,
                trusted=True,
                trust_path=trust_path,
                reason=(
                    f"Organization {org!r} is trusted via chain: "
                    f"{' -> '.join(trust_path)}."
                ),
                verified_at=now,
            )

        return VerificationOutcome(
            did=did,
            org=org,
            trusted=False,
            trust_path=[],
            reason=(
                f"Organization {org!r} is not in any trust anchor chain."
            ),
            verified_at=now,
        )

    def is_trusted_org(self, org: str) -> bool:
        """Return True if an org is directly or transitively trusted.

        Parameters
        ----------
        org:
            Organization identifier to check.

        Returns
        -------
        bool
            True if the org is in the trust anchor chain.
        """
        return bool(self._resolve_trust_path(org))

    def list_anchors(self) -> list[TrustAnchor]:
        """Return all registered trust anchors."""
        return list(self._anchors.values())

    def trust_path_for(self, org: str) -> list[str]:
        """Return the trust path from ``org`` to the root anchor.

        Parameters
        ----------
        org:
            Organization to look up.

        Returns
        -------
        list[str]
            Path from org to root, or empty if not trusted.
        """
        return self._resolve_trust_path(org)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_trust_path(self, org: str) -> list[str]:
        """Traverse the trust chain upward from org to the root.

        Returns the path as a list starting from ``org`` and ending at
        the root anchor. Returns an empty list if the org is not trusted.
        """
        path: list[str] = []
        current = org
        visited: set[str] = set()

        for _ in range(self._max_chain_depth):
            if current in visited:
                # Cycle detected — not trusted
                return []
            visited.add(current)

            anchor = self._anchors.get(current)
            if anchor is None:
                # Not found in anchor registry
                return []

            path.append(current)

            if anchor.is_root():
                return path

            # Traverse to the trusting org
            if anchor.trusted_by is None:
                return path
            current = anchor.trusted_by

        # Exceeded max depth
        return []


__all__ = ["CrossOrgVerifier", "TrustAnchor", "VerificationOutcome"]
