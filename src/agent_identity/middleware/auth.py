"""AuthMiddleware — authentication handler for agent requests.

Supports three authentication mechanisms:
  - Bearer token (opaque token validated against a token store)
  - Certificate (PEM-encoded X.509 agent certificate)
  - Delegation token (DelegationToken with HMAC-SHA256 signature)

Each mechanism produces an AuthResult indicating success, the authenticated
agent_id, and which mechanism was used.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum


class AuthMechanism(str, Enum):
    """The authentication mechanism used for a request."""

    BEARER = "bearer"
    CERTIFICATE = "certificate"
    DELEGATION = "delegation"


@dataclass
class AuthResult:
    """Result of an authentication attempt.

    Parameters
    ----------
    success:
        Whether authentication succeeded.
    agent_id:
        The authenticated agent ID (empty string if failed).
    mechanism:
        The mechanism that produced this result.
    reason:
        Human-readable explanation of a failure (empty on success).
    """

    success: bool
    agent_id: str
    mechanism: AuthMechanism
    reason: str = ""


class AuthMiddleware:
    """Multi-mechanism authentication middleware for agent requests.

    Parameters
    ----------
    bearer_token_store:
        Mapping of opaque bearer token strings to agent_id values.
        Pass an empty dict to disable bearer auth.
    delegation_secret_key:
        Shared secret used to verify HMAC-signed delegation tokens.
        Pass None to disable delegation auth.
    """

    def __init__(
        self,
        bearer_token_store: dict[str, str] | None = None,
        delegation_secret_key: bytes | None = None,
    ) -> None:
        self._bearer_store: dict[str, str] = bearer_token_store or {}
        self._delegation_key: bytes | None = delegation_secret_key

    # ------------------------------------------------------------------
    # Bearer auth
    # ------------------------------------------------------------------

    def authenticate_bearer(self, token: str) -> AuthResult:
        """Authenticate a request using a bearer token.

        Parameters
        ----------
        token:
            The raw bearer token string (without "Bearer " prefix).

        Returns
        -------
        AuthResult
        """
        agent_id = self._bearer_store.get(token.strip())
        if agent_id:
            return AuthResult(success=True, agent_id=agent_id, mechanism=AuthMechanism.BEARER)
        return AuthResult(
            success=False,
            agent_id="",
            mechanism=AuthMechanism.BEARER,
            reason="Invalid or unknown bearer token.",
        )

    # ------------------------------------------------------------------
    # Certificate auth
    # ------------------------------------------------------------------

    def authenticate_certificate(self, cert_pem: bytes) -> AuthResult:
        """Authenticate a request using a PEM-encoded X.509 agent certificate.

        Parses the certificate and extracts the agent_id from the SAN URI
        extension (``agent-identity://agent-id/<id>``). Certificate signature
        verification against a CA is the caller's responsibility via
        :class:`~agent_identity.certificates.verifier.CertificateVerifier`.

        Parameters
        ----------
        cert_pem:
            PEM-encoded X.509 certificate bytes.

        Returns
        -------
        AuthResult
        """
        try:
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.x509 import SubjectAlternativeName, UniformResourceIdentifier

            cert = load_pem_x509_certificate(cert_pem)

            try:
                san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
            except Exception:
                return AuthResult(
                    success=False,
                    agent_id="",
                    mechanism=AuthMechanism.CERTIFICATE,
                    reason="Certificate contains no SubjectAlternativeName extension.",
                )

            uris: list[str] = [
                name.value
                for name in san_ext.value.get_values_for_type(UniformResourceIdentifier)
            ]

            agent_id = ""
            prefix = "agent-identity://agent-id/"
            for uri in uris:
                if uri.startswith(prefix):
                    agent_id = uri[len(prefix):]
                    break

            if not agent_id:
                return AuthResult(
                    success=False,
                    agent_id="",
                    mechanism=AuthMechanism.CERTIFICATE,
                    reason="Could not extract agent_id from certificate SAN URIs.",
                )

            return AuthResult(
                success=True, agent_id=agent_id, mechanism=AuthMechanism.CERTIFICATE
            )

        except Exception as exc:
            return AuthResult(
                success=False,
                agent_id="",
                mechanism=AuthMechanism.CERTIFICATE,
                reason=f"Certificate parsing failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Delegation token auth
    # ------------------------------------------------------------------

    def authenticate_delegation(
        self,
        token_data: dict[str, object],
    ) -> AuthResult:
        """Authenticate a request using a delegation token.

        The token is reconstructed from its dict representation and its HMAC
        signature is verified using the configured ``delegation_secret_key``.
        The delegate_id is used as the authenticated agent_id.

        Parameters
        ----------
        token_data:
            Dictionary representation of a DelegationToken (as produced by
            ``DelegationToken.to_dict()``).

        Returns
        -------
        AuthResult
        """
        if self._delegation_key is None:
            return AuthResult(
                success=False,
                agent_id="",
                mechanism=AuthMechanism.DELEGATION,
                reason="Delegation authentication is not configured.",
            )

        try:
            from agent_identity.delegation.token import DelegationToken

            token = DelegationToken.from_dict(token_data)
            if not token.verify_token(self._delegation_key):
                return AuthResult(
                    success=False,
                    agent_id="",
                    mechanism=AuthMechanism.DELEGATION,
                    reason="Delegation token signature is invalid or token has expired.",
                )
            return AuthResult(
                success=True,
                agent_id=token.delegate_id,
                mechanism=AuthMechanism.DELEGATION,
            )

        except Exception as exc:
            return AuthResult(
                success=False,
                agent_id="",
                mechanism=AuthMechanism.DELEGATION,
                reason=f"Delegation token verification failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def authenticate_from_header(self, authorization_header: str) -> AuthResult:
        """Parse an HTTP Authorization header and authenticate accordingly.

        Supports:
          - ``Bearer <token>`` — delegates to :meth:`authenticate_bearer`
          - ``Delegation <base64-json>`` — delegates to :meth:`authenticate_delegation`

        Parameters
        ----------
        authorization_header:
            The raw value of the Authorization HTTP header.

        Returns
        -------
        AuthResult
        """
        parts = authorization_header.strip().split(None, 1)
        if len(parts) != 2:
            return AuthResult(
                success=False,
                agent_id="",
                mechanism=AuthMechanism.BEARER,
                reason="Malformed Authorization header.",
            )

        scheme, credentials = parts[0].lower(), parts[1]

        if scheme == "bearer":
            return self.authenticate_bearer(credentials)

        if scheme == "delegation":
            import json

            try:
                token_json = base64.urlsafe_b64decode(credentials + "==").decode("utf-8")
                token_data: dict[str, object] = json.loads(token_json)
                return self.authenticate_delegation(token_data)
            except Exception as exc:
                return AuthResult(
                    success=False,
                    agent_id="",
                    mechanism=AuthMechanism.DELEGATION,
                    reason=f"Failed to decode Delegation credentials: {exc}",
                )

        return AuthResult(
            success=False,
            agent_id="",
            mechanism=AuthMechanism.BEARER,
            reason=f"Unsupported authorization scheme {parts[0]!r}.",
        )
