"""DIDKeyProvider — W3C did:key method implementation.

Implements the ``did:key`` DID method as specified in:
https://w3c-ccg.github.io/did-method-key/

did:key encoding
----------------
1. Generate an Ed25519 public key (32 raw bytes).
2. Prepend the Ed25519 multicodec prefix: ``0xed 0x01`` (2 bytes).
3. Encode the 34-byte result with base58btc.
4. Prefix the encoded string with ``z`` (the multibase indicator for base58btc).
5. Assemble: ``did:key:z<base58btc-encoded>``.

The resulting DID is self-describing — the public key is recoverable from
the DID string alone, without any external registry.

Optional dependency
-------------------
The :class:`Ed25519KeyManager` (and therefore key generation, signing, and
verification) requires the ``cryptography`` package::

    pip install agent-identity[crypto]

:meth:`DIDKeyProvider.resolve` can decode the public key from a ``did:key``
string without the ``cryptography`` package (no signing involved).
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from agent_identity.did.key_manager import Ed25519KeyManager

# ---------------------------------------------------------------------------
# Multicodec prefix for Ed25519 public keys (varint-encoded 0xed01)
# ---------------------------------------------------------------------------

_ED25519_MULTICODEC_PREFIX: bytes = b"\xed\x01"

# ---------------------------------------------------------------------------
# Base58btc codec
# ---------------------------------------------------------------------------

_BASE58_ALPHABET: bytes = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(data: bytes) -> str:
    """Encode *data* to a base58btc string.

    Parameters
    ----------
    data:
        Arbitrary bytes to encode.

    Returns
    -------
    str
        Base58btc-encoded string (ASCII characters only).
    """
    n = int.from_bytes(data, "big")
    result: list[bytes] = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(_BASE58_ALPHABET[remainder : remainder + 1])
    # Preserve leading zero bytes as '1' characters
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _base58btc_decode(encoded: str) -> bytes:
    """Decode a base58btc string back to bytes.

    Parameters
    ----------
    encoded:
        A base58btc string as produced by :func:`_base58btc_encode`.

    Returns
    -------
    bytes
        The decoded byte sequence.

    Raises
    ------
    ValueError
        If the string contains a character not in the base58btc alphabet.
    """
    n = 0
    alphabet_str = _BASE58_ALPHABET.decode("ascii")
    for char in encoded:
        if char not in alphabet_str:
            raise ValueError(
                f"Invalid base58btc character {char!r} in encoded string {encoded!r}"
            )
        n = n * 58 + alphabet_str.index(char)
    # Convert integer back to bytes
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    # Re-attach leading zero bytes encoded as '1' characters
    pad_size = 0
    for char in encoded:
        if char == "1":
            pad_size += 1
        else:
            break
    return b"\x00" * pad_size + result


# ---------------------------------------------------------------------------
# DIDKeyDocument
# ---------------------------------------------------------------------------


@dataclass
class DIDKeyDocument:
    """A minimal document representing a ``did:key`` identity.

    Unlike the W3C ``did:agent`` :class:`~agent_identity.did.document.DIDDocument`,
    this is a lightweight dataclass — the ``did:key`` spec has no registry
    and no mutable document state.

    Parameters
    ----------
    did:
        The fully qualified ``did:key:z<encoded>`` string.
    agent_id:
        The logical agent identifier associated with this key.
        Set to ``"unknown"`` when the document is resolved from the DID string
        alone (no registry context).
    public_key:
        The 32-byte raw Ed25519 public key.
    private_key:
        The 32-byte raw Ed25519 private key. ``None`` when the document is
        created from a DID string alone (no private key available).
    created_at:
        UTC datetime when this document was created.
    """

    did: str
    agent_id: str
    public_key: bytes
    private_key: bytes | None = None
    created_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary.

        Private key bytes are intentionally omitted from the output.
        """
        return {
            "did": self.did,
            "agent_id": self.agent_id,
            "public_key_hex": self.public_key.hex(),
            "has_private_key": self.private_key is not None,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# DIDKeyProvider
# ---------------------------------------------------------------------------


class DIDKeyProvider:
    """Create, store, and resolve ``did:key`` identifiers.

    The ``did:key`` method is stateless by design — the public key is
    fully encoded in the DID string itself. However, this provider maintains
    an in-memory store mapping DID strings to :class:`DIDKeyDocument` objects
    so that private keys can be retrieved for signing.

    Parameters
    ----------
    key_manager:
        Optional :class:`~agent_identity.did.key_manager.Ed25519KeyManager`
        instance to use for key operations. A new instance is created if not
        provided.

    Example
    -------
    ::

        provider = DIDKeyProvider()
        doc = provider.create("agent-001")
        signature = provider.sign(doc.did, b"authenticate this")
        valid = provider.verify(doc.did, signature, b"authenticate this")
        assert valid
    """

    def __init__(self, key_manager: Ed25519KeyManager | None = None) -> None:
        self._key_manager: Ed25519KeyManager = key_manager or Ed25519KeyManager()
        self._store: dict[str, DIDKeyDocument] = {}

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create(self, agent_id: str) -> DIDKeyDocument:
        """Create a new ``did:key`` for an agent.

        Generates a fresh Ed25519 keypair, encodes the public key as a
        ``did:key`` DID, stores the document (including the private key),
        and returns it.

        Parameters
        ----------
        agent_id:
            The logical identifier for the agent this DID represents.

        Returns
        -------
        DIDKeyDocument
            The newly created document, including the private key.
        """
        private_bytes, public_bytes = self._key_manager.generate_keypair()
        did = _public_key_to_did(public_bytes)
        doc = DIDKeyDocument(
            did=did,
            agent_id=agent_id,
            public_key=public_bytes,
            private_key=private_bytes,
        )
        self._store[did] = doc
        return doc

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(self, did: str) -> DIDKeyDocument:
        """Resolve a ``did:key`` to its document.

        If the DID was created by this provider instance and is in the local
        store, the stored document (including the private key) is returned.
        Otherwise, the public key is decoded from the DID string itself and a
        document without a private key is returned.

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
        ValueError
            If the DID is not in ``did:key:z<encoded>`` format, or if the
            multicodec prefix is not the Ed25519 prefix.
        """
        _validate_did_key_format(did)

        if did in self._store:
            return self._store[did]

        # Decode the public key from the DID string
        encoded = did[len("did:key:z"):]
        decoded = _base58btc_decode(encoded)
        if not decoded.startswith(_ED25519_MULTICODEC_PREFIX):
            prefix_hex = decoded[:2].hex() if len(decoded) >= 2 else decoded.hex()
            raise ValueError(
                f"Unsupported multicodec prefix 0x{prefix_hex} in DID {did!r}. "
                "Only Ed25519 (0xed01) keys are supported."
            )
        public_bytes = decoded[len(_ED25519_MULTICODEC_PREFIX):]
        return DIDKeyDocument(
            did=did,
            agent_id="unknown",
            public_key=public_bytes,
        )

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, did: str, data: bytes) -> bytes:
        """Sign *data* using the private key associated with a ``did:key``.

        Parameters
        ----------
        did:
            A ``did:key`` DID whose private key is held in this provider's store.
        data:
            The bytes to sign.

        Returns
        -------
        bytes
            The 64-byte Ed25519 signature.

        Raises
        ------
        KeyError
            If no private key is available for the given DID.
        """
        doc = self._store.get(did)
        if doc is None or doc.private_key is None:
            raise KeyError(
                f"No private key available for {did!r}. "
                "The DID must be created with this provider instance."
            )
        return self._key_manager.sign(doc.private_key, data)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, did: str, signature: bytes, data: bytes) -> bool:
        """Verify a signature against a ``did:key``'s public key.

        The public key is resolved from the DID string — no registry lookup
        is required.

        Parameters
        ----------
        did:
            A ``did:key`` DID whose public key to verify against.
        signature:
            The 64-byte Ed25519 signature to verify.
        data:
            The original signed data.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.

        Raises
        ------
        ValueError
            If the DID cannot be resolved (malformed format or unsupported prefix).
        """
        doc = self.resolve(did)
        return self._key_manager.verify(doc.public_key, signature, data)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def stored_dids(self) -> list[str]:
        """Return a sorted list of all DID strings held in the local store."""
        return sorted(self._store.keys())


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _public_key_to_did(public_key_bytes: bytes) -> str:
    """Encode a raw Ed25519 public key as a ``did:key`` DID.

    Parameters
    ----------
    public_key_bytes:
        The 32-byte raw Ed25519 public key.

    Returns
    -------
    str
        A ``did:key:z<base58btc>`` string.
    """
    multicodec_bytes = _ED25519_MULTICODEC_PREFIX + public_key_bytes
    encoded = _base58btc_encode(multicodec_bytes)
    return f"did:key:z{encoded}"


def _validate_did_key_format(did: str) -> None:
    """Raise :class:`ValueError` if *did* is not a valid ``did:key`` string.

    A valid ``did:key`` starts with ``did:key:z`` and has at least one
    character following the ``z`` multibase prefix.

    Parameters
    ----------
    did:
        The DID string to validate.

    Raises
    ------
    ValueError
        If the format is invalid.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(
            f"Invalid did:key format: {did!r}. "
            "Expected format: did:key:z<base58btc-encoded-public-key>"
        )
    encoded_part = did[len("did:key:z"):]
    if not encoded_part:
        raise ValueError(
            f"Invalid did:key format: {did!r}. The encoded key portion is empty."
        )


__all__ = [
    "DIDKeyDocument",
    "DIDKeyProvider",
    "_base58btc_decode",
    "_base58btc_encode",
    "_public_key_to_did",
    "_validate_did_key_format",
]
