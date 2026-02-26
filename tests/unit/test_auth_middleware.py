"""Tests for agent_identity.middleware.auth — AuthMiddleware."""
from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from agent_identity.middleware.auth import AuthMechanism, AuthMiddleware, AuthResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def bearer_store() -> dict[str, str]:
    return {"token-abc": "agent-001", "token-xyz": "agent-002"}


@pytest.fixture()
def secret_key() -> bytes:
    return b"super-secret-key-for-testing"


@pytest.fixture()
def middleware(bearer_store: dict[str, str], secret_key: bytes) -> AuthMiddleware:
    return AuthMiddleware(
        bearer_token_store=bearer_store,
        delegation_secret_key=secret_key,
    )


@pytest.fixture()
def middleware_no_delegation(bearer_store: dict[str, str]) -> AuthMiddleware:
    return AuthMiddleware(bearer_token_store=bearer_store, delegation_secret_key=None)


@pytest.fixture()
def valid_delegation_token(secret_key: bytes):
    """Create a real signed delegation token for testing."""
    from agent_identity.delegation.token import DelegationToken

    return DelegationToken.create_token(
        issuer_id="agent-001",
        delegate_id="agent-delegate",
        scopes=["read", "write"],
        secret_key=secret_key,
        ttl_seconds=3600,
    )


# ---------------------------------------------------------------------------
# AuthResult dataclass
# ---------------------------------------------------------------------------


class TestAuthResult:
    def test_success_fields(self) -> None:
        result = AuthResult(
            success=True,
            agent_id="agent-001",
            mechanism=AuthMechanism.BEARER,
        )
        assert result.success is True
        assert result.agent_id == "agent-001"
        assert result.mechanism == AuthMechanism.BEARER
        assert result.reason == ""

    def test_failure_with_reason(self) -> None:
        result = AuthResult(
            success=False,
            agent_id="",
            mechanism=AuthMechanism.CERTIFICATE,
            reason="cert expired",
        )
        assert result.success is False
        assert result.reason == "cert expired"


# ---------------------------------------------------------------------------
# AuthMechanism enum
# ---------------------------------------------------------------------------


class TestAuthMechanism:
    def test_values(self) -> None:
        assert AuthMechanism.BEARER == "bearer"
        assert AuthMechanism.CERTIFICATE == "certificate"
        assert AuthMechanism.DELEGATION == "delegation"


# ---------------------------------------------------------------------------
# AuthMiddleware — bearer
# ---------------------------------------------------------------------------


class TestAuthenticateBearer:
    def test_valid_token_returns_success(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_bearer("token-abc")
        assert result.success is True
        assert result.agent_id == "agent-001"
        assert result.mechanism == AuthMechanism.BEARER

    def test_second_valid_token(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_bearer("token-xyz")
        assert result.success is True
        assert result.agent_id == "agent-002"

    def test_invalid_token_returns_failure(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_bearer("bad-token")
        assert result.success is False
        assert result.agent_id == ""
        assert result.mechanism == AuthMechanism.BEARER
        assert result.reason != ""

    def test_empty_token_fails(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_bearer("")
        assert result.success is False

    def test_token_with_leading_whitespace_is_stripped(
        self, middleware: AuthMiddleware
    ) -> None:
        result = middleware.authenticate_bearer("  token-abc  ")
        assert result.success is True
        assert result.agent_id == "agent-001"

    def test_empty_store_always_fails(self) -> None:
        mw = AuthMiddleware(bearer_token_store={})
        result = mw.authenticate_bearer("any-token")
        assert result.success is False

    def test_no_store_defaults_to_empty(self) -> None:
        mw = AuthMiddleware()
        result = mw.authenticate_bearer("any-token")
        assert result.success is False


# ---------------------------------------------------------------------------
# AuthMiddleware — certificate
# ---------------------------------------------------------------------------


class TestAuthenticateCertificate:
    def test_valid_cert_with_san_uri(self, middleware: AuthMiddleware) -> None:
        """Patch at the cryptography module level so authenticate_certificate
        can run cleanly independent of the installed cryptography API version."""
        from unittest.mock import MagicMock, patch

        # The source does: from cryptography.x509 import load_pem_x509_certificate
        # inside the function body, so we patch the module-level name.
        mock_uri = MagicMock()
        mock_uri.value = "agent-identity://agent-id/agent-cert-001"

        mock_san_value = MagicMock()
        mock_san_value.get_values_for_type.return_value = [mock_uri]

        mock_san_ext = MagicMock()
        mock_san_ext.value = mock_san_value

        mock_cert = MagicMock()
        mock_cert.extensions.get_extension_for_class.return_value = mock_san_ext

        with patch("cryptography.x509.load_pem_x509_certificate", return_value=mock_cert):
            result = middleware.authenticate_certificate(b"fake-pem")

        assert result.success is True
        assert result.agent_id == "agent-cert-001"
        assert result.mechanism == AuthMechanism.CERTIFICATE

    def test_invalid_pem_returns_failure(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_certificate(b"not-a-pem")
        assert result.success is False
        assert result.mechanism == AuthMechanism.CERTIFICATE
        assert "parsing failed" in result.reason.lower()

    def test_cert_without_agent_identity_uri_prefix_fails(
        self, middleware: AuthMiddleware
    ) -> None:
        """Cert that has a SAN URI but without the agent-identity:// prefix fails."""
        from unittest.mock import MagicMock, patch

        mock_uri = MagicMock()
        mock_uri.value = "https://example.com/not-an-agent"

        mock_san_value = MagicMock()
        mock_san_value.get_values_for_type.return_value = [mock_uri]

        mock_san_ext = MagicMock()
        mock_san_ext.value = mock_san_value

        mock_cert = MagicMock()
        mock_cert.extensions.get_extension_for_class.return_value = mock_san_ext

        with patch("cryptography.x509.load_pem_x509_certificate", return_value=mock_cert):
            result = middleware.authenticate_certificate(b"fake-pem")

        assert result.success is False
        assert "agent_id" in result.reason.lower() or "extract" in result.reason.lower()

    def test_cert_with_no_san_extension(self, middleware: AuthMiddleware) -> None:
        """A cert whose extensions.get_extension_for_class raises should fail gracefully."""
        from unittest.mock import MagicMock, patch

        mock_cert = MagicMock()
        mock_cert.extensions.get_extension_for_class.side_effect = Exception(
            "No SAN extension"
        )

        with patch("cryptography.x509.load_pem_x509_certificate", return_value=mock_cert):
            result = middleware.authenticate_certificate(b"fake-pem")

        assert result.success is False
        assert result.mechanism == AuthMechanism.CERTIFICATE


# ---------------------------------------------------------------------------
# AuthMiddleware — delegation
# ---------------------------------------------------------------------------


class TestAuthenticateDelegation:
    def test_delegation_disabled_returns_failure(
        self, middleware_no_delegation: AuthMiddleware
    ) -> None:
        result = middleware_no_delegation.authenticate_delegation({"token_id": "x"})
        assert result.success is False
        assert result.mechanism == AuthMechanism.DELEGATION
        assert "not configured" in result.reason.lower()

    def test_valid_delegation_token(
        self, middleware: AuthMiddleware, valid_delegation_token, secret_key: bytes
    ) -> None:
        token_data = valid_delegation_token.to_dict()
        result = middleware.authenticate_delegation(token_data)
        assert result.success is True
        assert result.agent_id == "agent-delegate"
        assert result.mechanism == AuthMechanism.DELEGATION

    def test_invalid_signature_fails(
        self, middleware: AuthMiddleware, valid_delegation_token
    ) -> None:
        token_data = valid_delegation_token.to_dict()
        token_data["signature"] = "invalidsignature"
        result = middleware.authenticate_delegation(token_data)
        assert result.success is False
        assert result.mechanism == AuthMechanism.DELEGATION

    def test_expired_token_fails(self, middleware: AuthMiddleware, secret_key: bytes) -> None:
        from agent_identity.delegation.token import DelegationToken

        token = DelegationToken.create_token(
            issuer_id="agent-001",
            delegate_id="agent-delegate",
            scopes=["read"],
            secret_key=secret_key,
            ttl_seconds=-1,  # already expired
        )
        result = middleware.authenticate_delegation(token.to_dict())
        assert result.success is False

    def test_malformed_token_data_fails(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_delegation({"garbage": "data"})
        assert result.success is False
        assert result.mechanism == AuthMechanism.DELEGATION
        assert "failed" in result.reason.lower()


# ---------------------------------------------------------------------------
# AuthMiddleware — authenticate_from_header
# ---------------------------------------------------------------------------


class TestAuthenticateFromHeader:
    def test_bearer_scheme_routes_to_bearer_auth(
        self, middleware: AuthMiddleware
    ) -> None:
        result = middleware.authenticate_from_header("Bearer token-abc")
        assert result.success is True
        assert result.agent_id == "agent-001"
        assert result.mechanism == AuthMechanism.BEARER

    def test_bearer_scheme_case_insensitive(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_from_header("BEARER token-abc")
        assert result.success is True

    def test_delegation_scheme_routes_to_delegation_auth(
        self, middleware: AuthMiddleware, valid_delegation_token
    ) -> None:
        token_json = json.dumps(valid_delegation_token.to_dict())
        encoded = base64.urlsafe_b64encode(token_json.encode()).decode()
        result = middleware.authenticate_from_header(f"Delegation {encoded}")
        assert result.success is True
        assert result.agent_id == "agent-delegate"

    def test_malformed_header_single_part_fails(
        self, middleware: AuthMiddleware
    ) -> None:
        result = middleware.authenticate_from_header("Bearer")
        assert result.success is False
        assert "malformed" in result.reason.lower()

    def test_empty_header_fails(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_from_header("")
        assert result.success is False

    def test_unsupported_scheme_fails(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_from_header("Basic dXNlcjpwYXNz")
        assert result.success is False
        assert "unsupported" in result.reason.lower()

    def test_delegation_with_bad_base64_fails(
        self, middleware: AuthMiddleware
    ) -> None:
        result = middleware.authenticate_from_header("Delegation !!!not-base64!!!")
        assert result.success is False
        assert result.mechanism == AuthMechanism.DELEGATION

    def test_invalid_bearer_token_in_header(self, middleware: AuthMiddleware) -> None:
        result = middleware.authenticate_from_header("Bearer unknown-token")
        assert result.success is False
