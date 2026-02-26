"""Tests for agent_identity.certificates.verifier — CertVerifier."""
from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_identity.certificates.ca import CertificateAuthority
from agent_identity.certificates.revocation import RevocationList
from agent_identity.certificates.verifier import CertVerifier, VerificationResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    """A single shared CA for this module (expensive to create)."""
    return CertificateAuthority.generate_ca()


@pytest.fixture()
def valid_cert(ca: CertificateAuthority):
    return ca.sign_agent_cert(
        agent_id="agent-verifier-test",
        organization="TestOrg",
        capabilities=["read"],
        trust_level=2,
        validity_days=365,
    )


@pytest.fixture()
def verifier(ca: CertificateAuthority) -> CertVerifier:
    return CertVerifier(ca_cert=ca.ca_cert)


@pytest.fixture()
def verifier_with_crl(ca: CertificateAuthority) -> tuple[CertVerifier, RevocationList]:
    crl = RevocationList()
    return CertVerifier(ca_cert=ca.ca_cert, revocation_list=crl), crl


# ---------------------------------------------------------------------------
# VerificationResult dataclass
# ---------------------------------------------------------------------------


class TestVerificationResult:
    def test_valid_when_all_checks_pass(self) -> None:
        result = VerificationResult(
            valid=True,
            chain_valid=True,
            not_expired=True,
            not_revoked=True,
        )
        assert result.valid is True
        assert result.errors == []

    def test_invalid_when_chain_fails(self) -> None:
        result = VerificationResult(
            valid=False,
            chain_valid=False,
            not_expired=True,
            not_revoked=True,
            errors=["bad signature"],
        )
        assert result.valid is False
        assert "bad signature" in result.errors


# ---------------------------------------------------------------------------
# CertVerifier.verify — happy path
# ---------------------------------------------------------------------------


class TestVerify:
    def test_valid_cert_issued_by_ca_passes_all_checks(
        self, verifier: CertVerifier, valid_cert
    ) -> None:
        result = verifier.verify(valid_cert)
        assert result.valid is True
        assert result.chain_valid is True
        assert result.not_expired is True
        assert result.not_revoked is True
        assert result.errors == []

    def test_verify_x509_accepts_raw_cert_object(
        self, verifier: CertVerifier, valid_cert
    ) -> None:
        cert_obj = valid_cert.load_x509()
        result = verifier.verify_x509(cert_obj)
        assert result.valid is True


# ---------------------------------------------------------------------------
# CertVerifier — chain verification
# ---------------------------------------------------------------------------


class TestChainVerification:
    def test_cert_signed_by_different_ca_fails(self, ca: CertificateAuthority) -> None:
        other_ca = CertificateAuthority.generate_ca(common_name="Other CA")
        foreign_cert = other_ca.sign_agent_cert(
            agent_id="foreign-agent",
            organization="ForeignOrg",
            capabilities=[],
            trust_level=1,
        )
        verifier = CertVerifier(ca_cert=ca.ca_cert)
        result = verifier.verify(foreign_cert)
        assert result.valid is False
        assert result.chain_valid is False
        assert any("invalid" in e.lower() or "signature" in e.lower() for e in result.errors)

    def test_non_rsa_ca_key_returns_failure(self, ca: CertificateAuthority, valid_cert) -> None:
        """Simulate a CA whose public key is not RSA."""
        mock_ca_cert = MagicMock(spec=x509.Certificate)
        mock_public_key = MagicMock()
        # Make isinstance(mock_public_key, RSAPublicKey) return False
        mock_public_key.__class__ = object
        mock_ca_cert.public_key.return_value = mock_public_key

        verifier = CertVerifier(ca_cert=mock_ca_cert)
        cert_obj = valid_cert.load_x509()
        result = verifier.verify_x509(cert_obj)
        assert result.chain_valid is False
        assert any("not RSA" in e or "rsa" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# CertVerifier — expiry verification
# ---------------------------------------------------------------------------


class TestExpiryVerification:
    def test_expired_cert_fails_expiry_check(self, ca: CertificateAuthority) -> None:
        """Issue a real cert and mock the clock so it appears past its expiry."""
        import datetime
        from unittest.mock import patch

        cert = ca.sign_agent_cert(
            agent_id="expired-agent",
            organization="TestOrg",
            capabilities=[],
            trust_level=1,
            validity_days=1,
        )
        # Simulate being 2 days in the future
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)
        real_datetime = datetime.datetime

        class FakeDatetime(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return future

        with patch("agent_identity.certificates.verifier.datetime") as mock_dt_mod:
            mock_dt_mod.datetime = FakeDatetime
            mock_dt_mod.timezone = datetime.timezone
            verifier = CertVerifier(ca_cert=ca.ca_cert)
            result = verifier.verify(cert)

        assert result.not_expired is False
        assert result.valid is False
        assert any("expired" in e.lower() for e in result.errors)

    def test_not_yet_valid_cert_fails_expiry(self, ca: CertificateAuthority) -> None:
        """Create a cert whose not_valid_before is in the future."""
        from cryptography.x509.oid import NameOID

        future_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        future_start = now + datetime.timedelta(days=365)

        san_uris = [
            x509.UniformResourceIdentifier("agent-identity://agent-id/future-agent"),
            x509.UniformResourceIdentifier("agent-identity://org/TestOrg"),
            x509.UniformResourceIdentifier("agent-identity://trust-level/1"),
            x509.UniformResourceIdentifier("agent-identity://capabilities/"),
        ]

        cert_obj = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "future-agent")]))
            .issuer_name(ca.ca_cert.subject)
            .public_key(future_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(future_start)
            .not_valid_after(future_start + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san_uris), critical=False)
            .sign(ca.ca_key, hashes.SHA256())
        )
        verifier = CertVerifier(ca_cert=ca.ca_cert)
        result = verifier.verify_x509(cert_obj)
        assert result.not_expired is False
        assert any("not yet valid" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# CertVerifier — revocation verification
# ---------------------------------------------------------------------------


class TestRevocationVerification:
    def test_no_crl_always_passes_revocation(
        self, verifier: CertVerifier, valid_cert
    ) -> None:
        result = verifier.verify(valid_cert)
        assert result.not_revoked is True

    def test_revoked_serial_fails_verification(
        self, ca: CertificateAuthority, valid_cert
    ) -> None:
        crl = RevocationList()
        crl.revoke_cert(valid_cert.serial_number)
        verifier = CertVerifier(ca_cert=ca.ca_cert, revocation_list=crl)
        result = verifier.verify(valid_cert)
        assert result.not_revoked is False
        assert result.valid is False
        assert any("revoked" in e.lower() for e in result.errors)

    def test_different_serial_not_revoked(
        self, ca: CertificateAuthority, valid_cert
    ) -> None:
        crl = RevocationList()
        crl.revoke_cert(valid_cert.serial_number + 999)
        verifier = CertVerifier(ca_cert=ca.ca_cert, revocation_list=crl)
        result = verifier.verify(valid_cert)
        assert result.not_revoked is True
