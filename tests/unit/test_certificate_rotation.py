"""Tests for agent_identity.certificates.rotation — CertRotator."""
from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest

from agent_identity.certificates.ca import CertificateAuthority
from agent_identity.certificates.rotation import CertRotator, RotationResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    return CertificateAuthority.generate_ca()


@pytest.fixture()
def rotator(ca: CertificateAuthority) -> CertRotator:
    return CertRotator(
        ca=ca,
        rotation_threshold_days=30,
        default_validity_days=365,
    )


@pytest.fixture()
def fresh_cert(ca: CertificateAuthority):
    return ca.sign_agent_cert(
        agent_id="agent-rotator-test",
        organization="TestOrg",
        capabilities=["read"],
        trust_level=2,
        validity_days=365,
    )


@pytest.fixture()
def expiring_cert(ca: CertificateAuthority):
    """Certificate that expires in 10 days (within 30-day threshold)."""
    return ca.sign_agent_cert(
        agent_id="agent-expiring",
        organization="TestOrg",
        capabilities=["read"],
        trust_level=2,
        validity_days=10,
    )


@pytest.fixture()
def expired_cert(ca: CertificateAuthority):
    """Certificate that has already expired.

    We issue a cert with validity_days=1 and then mutate the not_after field
    directly on the dataclass to place it in the past, avoiding the cryptography
    library's constraint that not_after must be after not_before.
    """
    import datetime

    cert = ca.sign_agent_cert(
        agent_id="agent-expired",
        organization="TestOrg",
        capabilities=["read"],
        trust_level=1,
        validity_days=1,
    )
    # Mutate the dataclass fields to simulate expiry
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    object.__setattr__(cert, "not_after", past)
    return cert


# ---------------------------------------------------------------------------
# RotationResult dataclass
# ---------------------------------------------------------------------------


class TestRotationResult:
    def test_not_rotated(self) -> None:
        result = RotationResult(rotated=False, new_cert=None, reason="still valid")
        assert result.rotated is False
        assert result.new_cert is None

    def test_rotated(self, fresh_cert) -> None:
        result = RotationResult(rotated=True, new_cert=fresh_cert, reason="expiring soon")
        assert result.rotated is True
        assert result.new_cert is not None


# ---------------------------------------------------------------------------
# CertRotator — check_and_rotate
# ---------------------------------------------------------------------------


class TestCheckAndRotate:
    def test_fresh_cert_not_rotated(
        self, rotator: CertRotator, fresh_cert
    ) -> None:
        result = rotator.check_and_rotate(fresh_cert)
        assert result.rotated is False
        assert result.new_cert is None
        assert "more days" in result.reason

    def test_reason_contains_days_remaining_for_fresh_cert(
        self, rotator: CertRotator, fresh_cert
    ) -> None:
        result = rotator.check_and_rotate(fresh_cert)
        assert str(fresh_cert.days_remaining()) in result.reason

    def test_expiring_cert_triggers_rotation(
        self, rotator: CertRotator, expiring_cert
    ) -> None:
        result = rotator.check_and_rotate(expiring_cert)
        assert result.rotated is True
        assert result.new_cert is not None

    def test_rotated_cert_preserves_agent_id(
        self, rotator: CertRotator, expiring_cert
    ) -> None:
        result = rotator.check_and_rotate(expiring_cert)
        assert result.new_cert is not None
        assert result.new_cert.agent_id == expiring_cert.agent_id

    def test_rotated_cert_preserves_organization(
        self, rotator: CertRotator, expiring_cert
    ) -> None:
        result = rotator.check_and_rotate(expiring_cert)
        assert result.new_cert is not None
        assert result.new_cert.organization == expiring_cert.organization

    def test_rotated_cert_preserves_capabilities(
        self, rotator: CertRotator, expiring_cert
    ) -> None:
        result = rotator.check_and_rotate(expiring_cert)
        assert result.new_cert is not None
        assert result.new_cert.capabilities == expiring_cert.capabilities

    def test_rotated_cert_gets_new_serial(
        self, rotator: CertRotator, expiring_cert
    ) -> None:
        result = rotator.check_and_rotate(expiring_cert)
        assert result.new_cert is not None
        assert result.new_cert.serial_number != expiring_cert.serial_number

    def test_expired_cert_triggers_rotation(
        self, rotator: CertRotator, expired_cert
    ) -> None:
        result = rotator.check_and_rotate(expired_cert)
        assert result.rotated is True
        assert result.new_cert is not None

    def test_expired_cert_reason_contains_expired(
        self, rotator: CertRotator, expired_cert
    ) -> None:
        result = rotator.check_and_rotate(expired_cert)
        assert "expired" in result.reason.lower()

    def test_exact_threshold_triggers_rotation(self, ca: CertificateAuthority) -> None:
        """A cert with exactly rotation_threshold_days remaining should rotate."""
        rotator = CertRotator(ca=ca, rotation_threshold_days=30)
        cert = ca.sign_agent_cert(
            agent_id="threshold-agent",
            organization="TestOrg",
            capabilities=[],
            trust_level=1,
            validity_days=30,
        )
        result = rotator.check_and_rotate(cert)
        assert result.rotated is True

    def test_default_validity_applied_to_new_cert(
        self, ca: CertificateAuthority, expiring_cert
    ) -> None:
        rotator = CertRotator(ca=ca, rotation_threshold_days=30, default_validity_days=180)
        result = rotator.check_and_rotate(expiring_cert)
        assert result.new_cert is not None
        # New cert should have ~180 days remaining
        assert result.new_cert.days_remaining() >= 170


# ---------------------------------------------------------------------------
# CertRotator — force_rotate
# ---------------------------------------------------------------------------


class TestForceRotate:
    def test_force_rotate_always_issues_new_cert(
        self, rotator: CertRotator, fresh_cert
    ) -> None:
        new_cert = rotator.force_rotate(fresh_cert)
        assert new_cert is not None
        assert new_cert.agent_id == fresh_cert.agent_id

    def test_force_rotate_produces_new_serial(
        self, rotator: CertRotator, fresh_cert
    ) -> None:
        new_cert = rotator.force_rotate(fresh_cert)
        assert new_cert.serial_number != fresh_cert.serial_number

    def test_force_rotate_preserves_metadata(
        self, rotator: CertRotator, fresh_cert
    ) -> None:
        new_cert = rotator.force_rotate(fresh_cert)
        assert new_cert.organization == fresh_cert.organization
        assert new_cert.trust_level == fresh_cert.trust_level
        assert new_cert.capabilities == fresh_cert.capabilities

    def test_force_rotate_on_expired_cert(
        self, rotator: CertRotator, expired_cert
    ) -> None:
        new_cert = rotator.force_rotate(expired_cert)
        assert not new_cert.is_expired()
