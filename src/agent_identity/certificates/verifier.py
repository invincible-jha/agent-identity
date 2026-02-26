"""Certificate verification — chain, expiry, and revocation checks.

The CertVerifier validates an agent certificate against a trusted CA and
optionally against a RevocationList to detect revoked credentials.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from agent_identity.certificates.agent_cert import AgentCertificate
from agent_identity.certificates.revocation import RevocationList


@dataclass
class VerificationResult:
    """Outcome of a certificate verification check.

    Parameters
    ----------
    valid:
        Overall pass/fail result.
    chain_valid:
        Whether the certificate was signed by the expected CA.
    not_expired:
        Whether the certificate is within its validity window.
    not_revoked:
        Whether the certificate serial is absent from the CRL.
    errors:
        List of human-readable error strings describing failures.
    """

    valid: bool
    chain_valid: bool
    not_expired: bool
    not_revoked: bool
    errors: list[str] = field(default_factory=list)


class CertVerifier:
    """Verifies agent certificates against a trusted CA.

    Parameters
    ----------
    ca_cert:
        The trusted CA certificate used for chain validation.
    revocation_list:
        Optional RevocationList for revocation checks.
    """

    def __init__(
        self,
        ca_cert: x509.Certificate,
        revocation_list: RevocationList | None = None,
    ) -> None:
        self._ca_cert = ca_cert
        self._revocation_list = revocation_list

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def verify(self, agent_cert: AgentCertificate) -> VerificationResult:
        """Verify an AgentCertificate against the trusted CA.

        Checks the certificate chain signature, validity window, and
        revocation status.

        Parameters
        ----------
        agent_cert:
            The agent certificate to verify.

        Returns
        -------
        VerificationResult
            Detailed result with per-check flags and error messages.
        """
        cert = agent_cert.load_x509()
        return self.verify_x509(cert)

    def verify_x509(self, cert: x509.Certificate) -> VerificationResult:
        """Verify a raw X.509 certificate object.

        Parameters
        ----------
        cert:
            The X.509 certificate to verify.

        Returns
        -------
        VerificationResult
            Detailed result with per-check flags and error messages.
        """
        errors: list[str] = []

        chain_valid = self._verify_chain(cert, errors)
        not_expired = self._verify_expiry(cert, errors)
        not_revoked = self._verify_revocation(cert, errors)

        return VerificationResult(
            valid=chain_valid and not_expired and not_revoked,
            chain_valid=chain_valid,
            not_expired=not_expired,
            not_revoked=not_revoked,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _verify_chain(self, cert: x509.Certificate, errors: list[str]) -> bool:
        """Check that cert was signed by the trusted CA."""
        try:
            ca_public_key = self._ca_cert.public_key()
            if not isinstance(ca_public_key, RSAPublicKey):
                errors.append("CA public key is not RSA")
                return False

            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            errors.append("Certificate signature is invalid — not signed by trusted CA")
            return False
        except Exception as exc:
            errors.append(f"Chain verification error: {exc}")
            return False

    def _verify_expiry(self, cert: x509.Certificate, errors: list[str]) -> bool:
        """Check that the certificate is within its validity window."""
        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        if now < not_before:
            errors.append(
                f"Certificate is not yet valid (valid from {not_before.isoformat()})"
            )
            return False

        if now > not_after:
            errors.append(
                f"Certificate expired at {not_after.isoformat()}"
            )
            return False

        return True

    def _verify_revocation(self, cert: x509.Certificate, errors: list[str]) -> bool:
        """Check that the certificate serial is not revoked."""
        if self._revocation_list is None:
            return True

        if self._revocation_list.is_revoked(cert.serial_number):
            errors.append(
                f"Certificate serial {cert.serial_number} has been revoked"
            )
            return False

        return True
