"""DelegationToken — signed capability delegation between agents.

Tokens use HMAC-SHA256 for signing. The token payload is a deterministic
JSON serialization of all token fields except the signature. Verification
recomputes the HMAC over the same payload and compares in constant time.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field


@dataclass
class DelegationToken:
    """A signed delegation of scoped capabilities from one agent to another.

    Parameters
    ----------
    token_id:
        Globally unique identifier for this token (UUID).
    issuer_id:
        Agent ID of the delegating party.
    delegate_id:
        Agent ID receiving the delegation.
    scopes:
        List of capability strings being delegated. An empty list means no
        capabilities are delegated (useful as a sentinel).
    issued_at:
        UTC datetime when the token was created.
    expires_at:
        UTC datetime after which the token is no longer valid.
    parent_token_id:
        ID of the parent DelegationToken if this is a sub-delegation,
        or None for root delegations.
    signature:
        Base64-encoded HMAC-SHA256 signature over the token payload.
        Empty string until the token is signed.
    """

    token_id: str
    issuer_id: str
    delegate_id: str
    scopes: list[str]
    issued_at: datetime.datetime
    expires_at: datetime.datetime
    parent_token_id: str | None = None
    signature: str = ""

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create_token(
        cls,
        issuer_id: str,
        delegate_id: str,
        scopes: list[str],
        secret_key: bytes,
        ttl_seconds: int = 3600,
        parent_token_id: str | None = None,
    ) -> "DelegationToken":
        """Create and sign a new DelegationToken.

        Parameters
        ----------
        issuer_id:
            The agent granting the delegation.
        delegate_id:
            The agent receiving the delegation.
        scopes:
            Capability strings being delegated.
        secret_key:
            Shared secret used for HMAC signing.
        ttl_seconds:
            Token lifetime in seconds from the current UTC time.
        parent_token_id:
            ID of the parent token for sub-delegations, or None.

        Returns
        -------
        DelegationToken
            A fully constructed, signed token.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        token = cls(
            token_id=str(uuid.uuid4()),
            issuer_id=issuer_id,
            delegate_id=delegate_id,
            scopes=sorted(scopes),
            issued_at=now,
            expires_at=now + datetime.timedelta(seconds=ttl_seconds),
            parent_token_id=parent_token_id,
        )
        token.signature = _sign_payload(token._payload_bytes(), secret_key)
        return token

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_token(self, secret_key: bytes) -> bool:
        """Verify the token's HMAC signature and check expiry.

        Parameters
        ----------
        secret_key:
            The same shared secret used when creating the token.

        Returns
        -------
        bool
            True if the signature is valid and the token has not expired.
        """
        if self.is_expired():
            return False
        expected = _sign_payload(self._payload_bytes(), secret_key)
        return hmac.compare_digest(self.signature, expected)

    def is_expired(self) -> bool:
        """Return True if the token has passed its expiry time."""
        return datetime.datetime.now(datetime.timezone.utc) > self.expires_at

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialize token to a plain dictionary."""
        return {
            "token_id": self.token_id,
            "issuer_id": self.issuer_id,
            "delegate_id": self.delegate_id,
            "scopes": self.scopes,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "parent_token_id": self.parent_token_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "DelegationToken":
        """Reconstruct a DelegationToken from a plain dictionary.

        Parameters
        ----------
        data:
            Dictionary as produced by :meth:`to_dict`.

        Returns
        -------
        DelegationToken
        """
        return cls(
            token_id=str(data["token_id"]),
            issuer_id=str(data["issuer_id"]),
            delegate_id=str(data["delegate_id"]),
            scopes=[str(s) for s in (data.get("scopes") or [])],
            issued_at=datetime.datetime.fromisoformat(str(data["issued_at"])),
            expires_at=datetime.datetime.fromisoformat(str(data["expires_at"])),
            parent_token_id=(
                str(data["parent_token_id"]) if data.get("parent_token_id") else None
            ),
            signature=str(data.get("signature", "")),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _payload_bytes(self) -> bytes:
        """Produce a deterministic byte representation of the signable payload."""
        payload = {
            "token_id": self.token_id,
            "issuer_id": self.issuer_id,
            "delegate_id": self.delegate_id,
            "scopes": self.scopes,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "parent_token_id": self.parent_token_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ------------------------------------------------------------------
# HMAC helpers
# ------------------------------------------------------------------


def _sign_payload(payload: bytes, secret_key: bytes) -> str:
    """Compute HMAC-SHA256 over *payload* and return base64url-encoded string."""
    mac = hmac.new(secret_key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii")
