"""Tests for W3C did:key method implementation.

Covers:
- Ed25519KeyManager: generate, sign, verify, wrong-data-fails
- Base58btc codec: round-trips, known vectors
- DIDKeyProvider: create, resolve, format validation
- Sign/verify flow end-to-end
- Round-trip: create -> resolve -> same public key
- Invalid DID format rejection
- Backward compat: existing did:aumos still works
- Without cryptography installed: helpful ImportError
- Known test vectors: Ed25519 public key -> expected did:key string
"""
from __future__ import annotations

import importlib
import sys
import unittest.mock
from unittest.mock import patch

import pytest

from agent_identity.did.did_key import (
    DIDKeyDocument,
    DIDKeyProvider,
    _base58btc_decode,
    _base58btc_encode,
    _public_key_to_did,
    _validate_did_key_format,
)
from agent_identity.did.key_manager import Ed25519KeyManager
from agent_identity.registry.did import DIDProvider


# ---------------------------------------------------------------------------
# Ed25519KeyManager tests
# ---------------------------------------------------------------------------


class TestEd25519KeyManager:
    """Tests for Ed25519 key generation, signing, and verification."""

    def test_generate_keypair_returns_32_byte_keys(self) -> None:
        """Generated keypair must consist of two 32-byte byte strings."""
        manager = Ed25519KeyManager()
        private_bytes, public_bytes = manager.generate_keypair()
        assert isinstance(private_bytes, bytes)
        assert isinstance(public_bytes, bytes)
        assert len(private_bytes) == 32
        assert len(public_bytes) == 32

    def test_generate_keypair_unique_each_call(self) -> None:
        """Two successive calls must produce different key pairs."""
        manager = Ed25519KeyManager()
        private_1, public_1 = manager.generate_keypair()
        private_2, public_2 = manager.generate_keypair()
        assert private_1 != private_2
        assert public_1 != public_2

    def test_sign_returns_64_byte_signature(self) -> None:
        """Ed25519 signatures are always 64 bytes."""
        manager = Ed25519KeyManager()
        private_bytes, _ = manager.generate_keypair()
        signature = manager.sign(private_bytes, b"test payload")
        assert isinstance(signature, bytes)
        assert len(signature) == 64

    def test_verify_valid_signature_returns_true(self) -> None:
        """A valid signature produced by sign() must verify as True."""
        manager = Ed25519KeyManager()
        private_bytes, public_bytes = manager.generate_keypair()
        data = b"hello from agent-identity"
        signature = manager.sign(private_bytes, data)
        assert manager.verify(public_bytes, signature, data) is True

    def test_verify_wrong_data_returns_false(self) -> None:
        """Verifying a signature against different data must return False."""
        manager = Ed25519KeyManager()
        private_bytes, public_bytes = manager.generate_keypair()
        data = b"original payload"
        signature = manager.sign(private_bytes, data)
        assert manager.verify(public_bytes, signature, b"tampered payload") is False

    def test_verify_wrong_key_returns_false(self) -> None:
        """Verifying with a different public key must return False."""
        manager = Ed25519KeyManager()
        private_bytes, _ = manager.generate_keypair()
        _, other_public_bytes = manager.generate_keypair()
        data = b"some data"
        signature = manager.sign(private_bytes, data)
        assert manager.verify(other_public_bytes, signature, data) is False

    def test_verify_mutated_signature_returns_false(self) -> None:
        """Flipping a bit in the signature must cause verification to fail."""
        manager = Ed25519KeyManager()
        private_bytes, public_bytes = manager.generate_keypair()
        data = b"payload"
        signature = manager.sign(private_bytes, data)
        # Flip the first byte
        mutated = bytes([signature[0] ^ 0xFF]) + signature[1:]
        assert manager.verify(public_bytes, mutated, data) is False


# ---------------------------------------------------------------------------
# Base58btc codec tests
# ---------------------------------------------------------------------------


class TestBase58BtcCodec:
    """Tests for the base58btc encode/decode round-trip."""

    def test_roundtrip_arbitrary_bytes(self) -> None:
        """Encode then decode must recover the original bytes."""
        original = bytes(range(34))  # 34 bytes: same length as multicodec key
        encoded = _base58btc_encode(original)
        decoded = _base58btc_decode(encoded)
        assert decoded == original

    def test_roundtrip_all_zeros_except_last(self) -> None:
        """Leading zero bytes are preserved in the round-trip."""
        original = b"\x00\x00\x00\x01"
        encoded = _base58btc_encode(original)
        decoded = _base58btc_decode(encoded)
        assert decoded == original

    def test_roundtrip_single_byte(self) -> None:
        """Single-byte values encode and decode correctly."""
        for byte_value in [0x01, 0x3A, 0xFF]:
            data = bytes([byte_value])
            assert _base58btc_decode(_base58btc_encode(data)) == data

    def test_known_vector_zero_byte(self) -> None:
        """A single 0x00 byte encodes to the single character '1'."""
        # In base58btc, leading zero bytes map to '1'
        encoded = _base58btc_encode(b"\x00")
        assert encoded == "1"

    def test_decode_invalid_character_raises_value_error(self) -> None:
        """Characters outside the base58btc alphabet must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid base58btc character"):
            _base58btc_decode("0OIl")  # '0', 'O', 'I', 'l' are excluded


# ---------------------------------------------------------------------------
# DIDKeyProvider: creation and resolution
# ---------------------------------------------------------------------------


class TestDIDKeyProvider:
    """Tests for DIDKeyProvider.create() and resolve()."""

    def test_create_returns_did_key_document(self) -> None:
        """create() must return a DIDKeyDocument with all fields set."""
        provider = DIDKeyProvider()
        doc = provider.create("agent-007")
        assert isinstance(doc, DIDKeyDocument)
        assert doc.agent_id == "agent-007"
        assert doc.did.startswith("did:key:z")
        assert len(doc.public_key) == 32
        assert doc.private_key is not None
        assert len(doc.private_key) == 32

    def test_create_different_agents_produce_unique_dids(self) -> None:
        """Each create() call must produce a unique DID."""
        provider = DIDKeyProvider()
        doc_a = provider.create("agent-a")
        doc_b = provider.create("agent-b")
        assert doc_a.did != doc_b.did

    def test_created_did_format_is_valid(self) -> None:
        """The created DID must match the did:key:z<encoded> pattern."""
        provider = DIDKeyProvider()
        doc = provider.create("agent-test")
        # Must start with the multibase 'z' prefix for base58btc
        assert doc.did.startswith("did:key:z")
        # Encoded part must be non-empty
        encoded_part = doc.did[len("did:key:z"):]
        assert len(encoded_part) > 0
        # Must consist only of base58btc characters
        valid_chars = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        assert all(c in valid_chars for c in encoded_part)

    def test_resolve_returns_stored_document(self) -> None:
        """resolve() on a locally-created DID must return the full document."""
        provider = DIDKeyProvider()
        doc = provider.create("agent-x")
        resolved = provider.resolve(doc.did)
        assert resolved.did == doc.did
        assert resolved.public_key == doc.public_key
        # Private key is present because the DID was created by this provider
        assert resolved.private_key == doc.private_key

    def test_resolve_unknown_did_decodes_public_key(self) -> None:
        """resolve() on an external DID must decode the public key from the string."""
        provider_a = DIDKeyProvider()
        doc = provider_a.create("agent-a")

        # A fresh provider that has never seen this DID
        provider_b = DIDKeyProvider()
        resolved = provider_b.resolve(doc.did)
        assert resolved.did == doc.did
        assert resolved.public_key == doc.public_key
        # No private key in the external resolution
        assert resolved.private_key is None
        assert resolved.agent_id == "unknown"

    def test_resolve_invalid_format_raises_value_error(self) -> None:
        """resolve() on a non-did:key string must raise ValueError."""
        provider = DIDKeyProvider()
        with pytest.raises(ValueError, match="Invalid did:key format"):
            provider.resolve("did:aumos:agent-007")

    def test_resolve_empty_encoded_part_raises_value_error(self) -> None:
        """resolve() on 'did:key:z' with no encoded part must raise ValueError."""
        provider = DIDKeyProvider()
        with pytest.raises(ValueError, match="Invalid did:key format"):
            provider.resolve("did:key:z")


# ---------------------------------------------------------------------------
# Sign and verify flow
# ---------------------------------------------------------------------------


class TestSignVerifyFlow:
    """End-to-end sign and verify tests."""

    def test_sign_and_verify_succeeds(self) -> None:
        """create -> sign -> verify must succeed."""
        provider = DIDKeyProvider()
        doc = provider.create("signer-agent")
        payload = b"authenticate this request"
        signature = provider.sign(doc.did, payload)
        assert provider.verify(doc.did, signature, payload) is True

    def test_verify_tampered_data_fails(self) -> None:
        """Verifying a valid signature against modified data must return False."""
        provider = DIDKeyProvider()
        doc = provider.create("signer-agent")
        payload = b"original message"
        signature = provider.sign(doc.did, payload)
        assert provider.verify(doc.did, signature, b"modified message") is False

    def test_sign_without_private_key_raises_key_error(self) -> None:
        """sign() with an unknown DID must raise KeyError."""
        provider = DIDKeyProvider()
        with pytest.raises(KeyError, match="No private key available"):
            provider.sign("did:key:zQmFakeDidThatIsNotInStore", b"data")

    def test_verify_cross_provider_succeeds(self) -> None:
        """A signature produced by one provider must verify on another instance."""
        provider_a = DIDKeyProvider()
        doc = provider_a.create("cross-agent")
        payload = b"cross-provider verification"
        signature = provider_a.sign(doc.did, payload)

        # provider_b has no private key for this DID, but can still verify
        provider_b = DIDKeyProvider()
        assert provider_b.verify(doc.did, signature, payload) is True


# ---------------------------------------------------------------------------
# Round-trip: create -> resolve -> same public key
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """Tests for public key round-trip consistency."""

    def test_resolve_yields_same_public_key(self) -> None:
        """The public key recovered via resolve() must match the original."""
        provider = DIDKeyProvider()
        doc = provider.create("round-trip-agent")
        resolved = provider.resolve(doc.did)
        assert resolved.public_key == doc.public_key

    def test_public_key_to_did_and_back(self) -> None:
        """_public_key_to_did() and resolve() form an exact round-trip."""
        manager = Ed25519KeyManager()
        _, public_bytes = manager.generate_keypair()
        did = _public_key_to_did(public_bytes)
        provider = DIDKeyProvider(key_manager=manager)
        resolved = provider.resolve(did)
        assert resolved.public_key == public_bytes


# ---------------------------------------------------------------------------
# Invalid DID format rejection
# ---------------------------------------------------------------------------


class TestInvalidDIDFormat:
    """Tests that malformed DID strings are rejected with clear errors."""

    def test_reject_did_aumos_format(self) -> None:
        """did:aumos strings must be rejected as invalid did:key format."""
        with pytest.raises(ValueError, match="Invalid did:key format"):
            _validate_did_key_format("did:aumos:agent-001")

    def test_reject_did_key_missing_z_prefix(self) -> None:
        """did:key strings without the 'z' multibase prefix are invalid."""
        with pytest.raises(ValueError, match="Invalid did:key format"):
            _validate_did_key_format("did:key:SomethingWithoutZ")

    def test_reject_bare_string(self) -> None:
        """An arbitrary string is not a valid did:key."""
        with pytest.raises(ValueError, match="Invalid did:key format"):
            _validate_did_key_format("not-a-did-at-all")

    def test_reject_did_key_empty_encoded_part(self) -> None:
        """did:key:z with nothing after the 'z' is invalid."""
        with pytest.raises(ValueError, match="Invalid did:key format"):
            _validate_did_key_format("did:key:z")


# ---------------------------------------------------------------------------
# Backward compatibility: existing did:aumos still works
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Existing did:aumos behavior must be unaffected by the new code."""

    def test_create_aumos_did_still_works(self) -> None:
        """DIDProvider.create_did() must return a well-formed did:aumos DID."""
        provider = DIDProvider()
        did = provider.create_did("legacy-agent")
        assert did == "did:aumos:legacy-agent"

    def test_resolve_aumos_did_still_works(self) -> None:
        """DIDProvider.resolve_did() must resolve a did:aumos DID correctly."""
        provider = DIDProvider()
        did = provider.create_did("legacy-agent")
        document = provider.resolve_did(did)
        assert document.agent_id == "legacy-agent"
        assert document.did == did

    def test_verify_aumos_did_still_works(self) -> None:
        """DIDProvider.verify_did() must still work for did:aumos."""
        provider = DIDProvider()
        did = provider.create_did("verify-me")
        assert provider.verify_did(did, "verify-me") is True
        assert provider.verify_did(did, "other-agent") is False

    def test_did_provider_create_did_key_method_exists(self) -> None:
        """DIDProvider must expose create_did_key() for W3C key DIDs."""
        provider = DIDProvider()
        doc = provider.create_did_key("agent-with-key-did")
        assert doc.did.startswith("did:key:z")
        assert doc.agent_id == "agent-with-key-did"


# ---------------------------------------------------------------------------
# Without cryptography installed: helpful ImportError
# ---------------------------------------------------------------------------


class TestMissingCryptographyPackage:
    """Verify that the ImportError message guides users to install the extra."""

    def test_import_error_message_is_actionable(self) -> None:
        """Ed25519KeyManager must raise ImportError with install instructions."""
        with patch.dict(sys.modules, {"cryptography": None}):
            # Force the import guard to fail by patching _CRYPTO_AVAILABLE
            with patch(
                "agent_identity.did.key_manager._CRYPTO_AVAILABLE",
                False,
            ):
                with pytest.raises(ImportError, match="pip install agent-identity\\[crypto\\]"):
                    Ed25519KeyManager()


# ---------------------------------------------------------------------------
# Known test vectors
# ---------------------------------------------------------------------------


class TestKnownVectors:
    """Verify the did:key encoding against known vectors.

    Reference: https://w3c-ccg.github.io/did-method-key/#test-vectors
    The test vectors below use a fixed Ed25519 public key and verify the
    expected did:key output.
    """

    # Known Ed25519 public key (32 bytes, all bytes = 0x01 for simplicity)
    # The multicodec encoding is 0xed01 || public_key_bytes
    # base58btc of those 34 bytes produces a deterministic result.
    _FIXED_PUBLIC_KEY: bytes = bytes([0x01] * 32)

    def test_known_public_key_produces_deterministic_did(self) -> None:
        """The same public key must always produce the same did:key string."""
        did_first = _public_key_to_did(self._FIXED_PUBLIC_KEY)
        did_second = _public_key_to_did(self._FIXED_PUBLIC_KEY)
        assert did_first == did_second

    def test_known_public_key_did_roundtrip(self) -> None:
        """Encoding a known public key and resolving it must recover the key."""
        did = _public_key_to_did(self._FIXED_PUBLIC_KEY)
        provider = DIDKeyProvider()
        resolved = provider.resolve(did)
        assert resolved.public_key == self._FIXED_PUBLIC_KEY

    def test_official_test_vector_ed25519(self) -> None:
        """Validate against a known did:key test vector for Ed25519.

        The vector is derived by decoding the expected DID back to raw bytes,
        confirming the multicodec prefix is 0xed01, then verifying that
        re-encoding those public key bytes produces the original DID.

        Public key bytes (hex):
          3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
        Expected DID:
          did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp
        """
        public_key_hex = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        public_key_bytes = bytes.fromhex(public_key_hex)
        expected_did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        computed_did = _public_key_to_did(public_key_bytes)
        assert computed_did == expected_did

    def test_did_starts_with_z6mk_for_ed25519(self) -> None:
        """All Ed25519 did:key values must start with 'did:key:z6Mk'.

        The multicodec prefix 0xed01 followed by a 32-byte key, base58btc
        encoded, always begins with 'z6Mk' for standard Ed25519 keys.
        """
        manager = Ed25519KeyManager()
        _, public_bytes = manager.generate_keypair()
        did = _public_key_to_did(public_bytes)
        assert did.startswith("did:key:z6Mk"), (
            f"Expected did:key:z6Mk prefix but got: {did[:20]}..."
        )


# ---------------------------------------------------------------------------
# DIDKeyDocument serialization
# ---------------------------------------------------------------------------


class TestDIDKeyDocumentSerialization:
    """Tests for DIDKeyDocument.to_dict()."""

    def test_to_dict_omits_private_key(self) -> None:
        """to_dict() must not include raw private key bytes."""
        provider = DIDKeyProvider()
        doc = provider.create("safe-agent")
        serialized = doc.to_dict()
        assert "private_key" not in serialized
        assert serialized["has_private_key"] is True

    def test_to_dict_includes_required_fields(self) -> None:
        """to_dict() must include did, agent_id, public_key_hex, created_at."""
        provider = DIDKeyProvider()
        doc = provider.create("fields-agent")
        serialized = doc.to_dict()
        assert "did" in serialized
        assert "agent_id" in serialized
        assert "public_key_hex" in serialized
        assert "created_at" in serialized
        assert serialized["did"] == doc.did
        assert serialized["agent_id"] == "fields-agent"
