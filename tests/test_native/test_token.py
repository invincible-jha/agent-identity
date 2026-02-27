"""Tests for IdentityToken — HMAC-SHA256 signed agent identity token."""
from __future__ import annotations

import base64
import datetime
import json
import uuid

import pytest

from agent_identity.native.capability import Capability
from agent_identity.native.identity import AgentIdentity
from agent_identity.native.restriction import Restriction
from agent_identity.native.token import (
    IdentityToken,
    TokenExpiredError,
    TokenInvalidError,
    TokenTamperedError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECRET = b"test-secret-key-for-unit-tests"
WRONG_SECRET = b"wrong-secret-key"


def make_identity(ttl_seconds: int | None = 3600) -> AgentIdentity:
    identity = AgentIdentity.create(
        name="test-agent",
        owner="alice",
        ttl_seconds=ttl_seconds,
    )
    identity.grant_capability(Capability(action="read", resource="db:users"))
    identity.add_restriction(Restriction(action="delete", reason="no deletes"))
    return identity


# ---------------------------------------------------------------------------
# sign()
# ---------------------------------------------------------------------------


class TestSign:
    def test_sign_returns_string(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        assert isinstance(token, str)

    def test_sign_produces_three_dot_separated_parts(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        parts = token.split(".")
        assert len(parts) == 3

    def test_sign_header_is_base64_json(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        header_b64 = token.split(".")[0]
        header_bytes = base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4))
        header = json.loads(header_bytes)
        assert header["alg"] == "HS256"
        assert header["typ"] == "AIT"

    def test_sign_payload_contains_agent_id(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        payload_b64 = token.split(".")[1]
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        payload = json.loads(payload_bytes)
        assert payload["agent_id"] == identity.agent_id

    def test_sign_payload_contains_exp_when_ttl_set(self) -> None:
        identity = make_identity(ttl_seconds=3600)
        token = IdentityToken.sign(identity, secret=SECRET)
        payload_b64 = token.split(".")[1]
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        payload = json.loads(payload_bytes)
        assert "exp" in payload

    def test_sign_payload_no_exp_when_no_ttl(self) -> None:
        identity = make_identity(ttl_seconds=None)
        token = IdentityToken.sign(identity, secret=SECRET)
        payload_b64 = token.split(".")[1]
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        payload = json.loads(payload_bytes)
        assert "exp" not in payload

    def test_same_identity_different_secrets_produce_different_tokens(self) -> None:
        identity = make_identity()
        token1 = IdentityToken.sign(identity, secret=b"secret1")
        token2 = IdentityToken.sign(identity, secret=b"secret2")
        # Signatures will differ
        assert token1.split(".")[2] != token2.split(".")[2]


# ---------------------------------------------------------------------------
# verify() — valid token
# ---------------------------------------------------------------------------


class TestVerifyValid:
    def test_verify_returns_agent_identity(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert isinstance(recovered, AgentIdentity)

    def test_verify_agent_id_matches(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert recovered.agent_id == identity.agent_id

    def test_verify_name_matches(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert recovered.name == identity.name

    def test_verify_capabilities_preserved(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert len(recovered.capabilities) == 1
        assert recovered.capabilities[0].action == "read"
        assert recovered.capabilities[0].resource == "db:users"

    def test_verify_restrictions_preserved(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert len(recovered.restrictions) == 1
        assert recovered.restrictions[0].action == "delete"

    def test_verify_ttl_preserved(self) -> None:
        identity = make_identity(ttl_seconds=1800)
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert recovered.ttl_seconds == 1800

    def test_verify_no_ttl_identity(self) -> None:
        identity = make_identity(ttl_seconds=None)
        token = IdentityToken.sign(identity, secret=SECRET)
        recovered = IdentityToken.verify(token, secret=SECRET)
        assert recovered.ttl_seconds is None


# ---------------------------------------------------------------------------
# verify() — error cases
# ---------------------------------------------------------------------------


class TestVerifyErrors:
    def test_wrong_secret_raises_tampered_error(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        with pytest.raises(TokenTamperedError):
            IdentityToken.verify(token, secret=WRONG_SECRET)

    def test_modified_payload_raises_tampered_error(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        header_b64, payload_b64, sig_b64 = token.split(".")

        # Tamper with the payload
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        payload = json.loads(payload_bytes)
        payload["owner"] = "evil-hacker"
        tampered_payload = json.dumps(payload, separators=(",", ":")).encode()
        tampered_payload_b64 = base64.urlsafe_b64encode(tampered_payload).decode("ascii")

        tampered_token = f"{header_b64}.{tampered_payload_b64}.{sig_b64}"
        with pytest.raises(TokenTamperedError):
            IdentityToken.verify(tampered_token, secret=SECRET)

    def test_invalid_format_raises_invalid_error(self) -> None:
        with pytest.raises(TokenInvalidError, match="3 dot-separated"):
            IdentityToken.verify("notavalidtoken", secret=SECRET)

    def test_two_part_token_raises_invalid_error(self) -> None:
        with pytest.raises(TokenInvalidError):
            IdentityToken.verify("part1.part2", secret=SECRET)

    def test_expired_token_raises_expired_error(self) -> None:
        # Create identity that expired in the past
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=200)
        identity = AgentIdentity(
            agent_id=str(uuid.uuid4()),
            name="expired-agent",
            owner="alice",
            ttl_seconds=100,
            created_at=past,
        )
        token = IdentityToken.sign(identity, secret=SECRET)
        with pytest.raises(TokenExpiredError) as exc_info:
            IdentityToken.verify(token, secret=SECRET)
        assert exc_info.value.agent_id == identity.agent_id

    def test_expired_error_contains_agent_id(self) -> None:
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=200)
        identity = AgentIdentity(
            agent_id="known-agent-id",
            name="old",
            owner="alice",
            ttl_seconds=100,
            created_at=past,
        )
        token = IdentityToken.sign(identity, secret=SECRET)
        with pytest.raises(TokenExpiredError) as exc_info:
            IdentityToken.verify(token, secret=SECRET)
        assert "known-agent-id" in exc_info.value.agent_id

    def test_garbled_payload_raises_invalid_error(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        header_b64, _, sig_b64 = token.split(".")
        # Use random bytes that won't decode as valid JSON
        garbled = base64.urlsafe_b64encode(b"\x00\x01\x02\x03").decode("ascii")
        garbled_token = f"{header_b64}.{garbled}.{sig_b64}"
        with pytest.raises((TokenTamperedError, TokenInvalidError)):
            IdentityToken.verify(garbled_token, secret=SECRET)

    def test_empty_secret_differs_from_original(self) -> None:
        identity = make_identity()
        token = IdentityToken.sign(identity, secret=SECRET)
        with pytest.raises(TokenTamperedError):
            IdentityToken.verify(token, secret=b"")


# ---------------------------------------------------------------------------
# Token error class hierarchy
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    def test_tampered_is_token_error(self) -> None:
        from agent_identity.native.token import TokenError
        assert issubclass(TokenTamperedError, TokenError)

    def test_expired_is_token_error(self) -> None:
        from agent_identity.native.token import TokenError
        assert issubclass(TokenExpiredError, TokenError)

    def test_invalid_is_token_error(self) -> None:
        from agent_identity.native.token import TokenError
        assert issubclass(TokenInvalidError, TokenError)
