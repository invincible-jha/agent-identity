"""IdentityToken — HMAC-SHA256 signed agent identity token.

Tokens are compact, self-contained representations of an AgentIdentity
that can be transmitted over HTTP headers, stored in databases, or passed
between services. Verification requires the shared secret used to sign
the token; no network call is needed.

Token format
------------
The token is a dot-separated string:
    base64url(header).base64url(payload).base64url(signature)

- header: ``{"alg": "HS256", "typ": "AIT"}`` (Agent Identity Token)
- payload: JSON-serialized AgentIdentity fields + ``"iat"`` and ``"exp"``
- signature: HMAC-SHA256(header.payload, secret)

This format is intentionally JWT-like so that standard tooling can inspect
the header/payload, but it is NOT a JWT (the alg is different and the
verification logic is our own).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json

from agent_identity.native.identity import AgentIdentity


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class TokenError(Exception):
    """Base class for all token-related errors."""


class TokenExpiredError(TokenError):
    """Raised when the token's expiry time has passed."""

    def __init__(self, agent_id: str, expired_at: str) -> None:
        self.agent_id = agent_id
        self.expired_at = expired_at
        super().__init__(
            f"Token for agent '{agent_id}' expired at {expired_at}"
        )


class TokenInvalidError(TokenError):
    """Raised when the token is structurally invalid (bad format)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Invalid token: {reason}")


class TokenTamperedError(TokenError):
    """Raised when HMAC signature verification fails."""

    def __init__(self) -> None:
        super().__init__(
            "Token signature verification failed — token has been tampered with"
        )


# ---------------------------------------------------------------------------
# Token header
# ---------------------------------------------------------------------------

_TOKEN_HEADER: dict[str, str] = {"alg": "HS256", "typ": "AIT"}
_HEADER_B64: str = base64.urlsafe_b64encode(
    json.dumps(_TOKEN_HEADER, separators=(",", ":")).encode("utf-8")
).decode("ascii")


# ---------------------------------------------------------------------------
# IdentityToken
# ---------------------------------------------------------------------------


class IdentityToken:
    """HMAC-SHA256 signed agent identity token issuer and verifier.

    This class provides only class methods — it is a namespace for the
    ``sign`` and ``verify`` operations, not an instance to be stored.

    Examples
    --------
    >>> identity = AgentIdentity.create(name="my-agent", owner="alice")
    >>> token_str = IdentityToken.sign(identity, secret=b"my-secret")
    >>> recovered = IdentityToken.verify(token_str, secret=b"my-secret")
    >>> recovered.agent_id == identity.agent_id
    True
    """

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    @classmethod
    def sign(
        cls,
        identity: AgentIdentity,
        secret: bytes,
    ) -> str:
        """Produce a signed identity token string.

        Parameters
        ----------
        identity:
            The AgentIdentity to encode.
        secret:
            Shared secret for HMAC-SHA256 signing. Must be kept private.

        Returns
        -------
        str
            A dot-separated token string (header.payload.signature).
        """
        payload_dict = cls._build_payload(identity)
        payload_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")

        signing_input = f"{_HEADER_B64}.{payload_b64}"
        signature = cls._compute_signature(signing_input.encode("utf-8"), secret)

        return f"{signing_input}.{signature}"

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    @classmethod
    def verify(cls, token: str, secret: bytes) -> AgentIdentity:
        """Verify a signed token and return the embedded AgentIdentity.

        Parameters
        ----------
        token:
            Token string as produced by :meth:`sign`.
        secret:
            The same shared secret used to sign the token.

        Returns
        -------
        AgentIdentity
            The identity embedded in the token.

        Raises
        ------
        TokenInvalidError
            When the token has an unexpected format.
        TokenTamperedError
            When signature verification fails.
        TokenExpiredError
            When the token has passed its expiry time.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenInvalidError(
                f"Expected 3 dot-separated parts, got {len(parts)}"
            )

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = cls._compute_signature(signing_input, secret)
        if not hmac.compare_digest(signature_b64, expected_sig):
            raise TokenTamperedError()

        # Decode payload
        try:
            payload_bytes = base64.urlsafe_b64decode(
                payload_b64 + "=" * (-len(payload_b64) % 4)
            )
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise TokenInvalidError(f"Could not decode payload: {exc}") from exc

        # Check expiry
        exp_str: str | None = payload.get("exp")
        if exp_str:
            try:
                exp_dt = datetime.datetime.fromisoformat(exp_str)
                if datetime.datetime.now(datetime.timezone.utc) > exp_dt:
                    raise TokenExpiredError(
                        agent_id=str(payload.get("agent_id", "")),
                        expired_at=exp_str,
                    )
            except TokenExpiredError:
                raise
            except Exception as exc:
                raise TokenInvalidError(f"Invalid 'exp' field: {exc}") from exc

        # Reconstruct identity
        try:
            identity = AgentIdentity.from_dict(payload)
        except Exception as exc:
            raise TokenInvalidError(f"Could not reconstruct identity: {exc}") from exc

        return identity

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _build_payload(cls, identity: AgentIdentity) -> dict[str, object]:
        """Build the token payload dict from an AgentIdentity."""
        payload = identity.to_dict()
        payload["iat"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if identity.ttl_seconds is not None:
            exp = identity.created_at + datetime.timedelta(seconds=identity.ttl_seconds)
            payload["exp"] = exp.isoformat()

        return payload

    @classmethod
    def _compute_signature(cls, data: bytes, secret: bytes) -> str:
        """Compute a base64url-encoded HMAC-SHA256 signature."""
        mac = hmac.new(secret, data, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii")
