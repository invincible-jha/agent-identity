"""Ed25519KeyManager — Ed25519 key generation, signing, and verification.

This module provides a thin wrapper around the ``cryptography`` package's
Ed25519 primitives. It is intentionally minimal: generate a keypair, sign
bytes, verify a signature. All key material is handled as raw bytes so
callers can store or transmit keys without depending on this module's
internal types.

Optional dependency
-------------------
Requires the ``cryptography`` package (>=41.0). Install via::

    pip install agent-identity[crypto]
"""
from __future__ import annotations

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


class Ed25519KeyManager:
    """Ed25519 key management: generate, sign, and verify.

    Requires the ``cryptography`` package. If it is not installed, the
    constructor raises :class:`ImportError` with an actionable message.

    Example
    -------
    ::

        manager = Ed25519KeyManager()
        private_bytes, public_bytes = manager.generate_keypair()
        signature = manager.sign(private_bytes, b"hello world")
        assert manager.verify(public_bytes, signature, b"hello world")
    """

    def __init__(self) -> None:
        if not _CRYPTO_AVAILABLE:
            raise ImportError(
                "The 'cryptography' package is required for Ed25519 operations. "
                "Install it with: pip install agent-identity[crypto]"
            )

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a new Ed25519 keypair.

        Returns
        -------
        tuple[bytes, bytes]
            A ``(private_key_bytes, public_key_bytes)`` pair. Both are
            32-byte raw representations.
        """
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return private_bytes, public_bytes

    def sign(self, private_key_bytes: bytes, data: bytes) -> bytes:
        """Sign data with an Ed25519 private key.

        Parameters
        ----------
        private_key_bytes:
            The 32-byte raw private key as returned by :meth:`generate_keypair`.
        data:
            The bytes to sign.

        Returns
        -------
        bytes
            The 64-byte Ed25519 signature.
        """
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return private_key.sign(data)

    def verify(self, public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
        """Verify an Ed25519 signature.

        Parameters
        ----------
        public_key_bytes:
            The 32-byte raw public key as returned by :meth:`generate_keypair`.
        signature:
            The 64-byte signature to verify.
        data:
            The original signed data.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as _PubKey,
        )

        public_key = _PubKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


__all__ = ["Ed25519KeyManager"]
