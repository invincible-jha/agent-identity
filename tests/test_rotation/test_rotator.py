"""Tests for CredentialRotator and LeakageDetector — E15.4."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_identity.rotation.rotator import (
    Credential,
    CredentialRotator,
    LeakageDetector,
    LeakageResult,
    RotationResult,
    RotationStatus,
    _generate_credential_value,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc(offset_hours: float = 0.0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=offset_hours)


def _make_credential(
    credential_id: str = "cred-001",
    value: str = "supersecretapikey12345",
    expires_at: datetime | None = None,
    rotation_before_hours: float = 24.0,
    status: RotationStatus = RotationStatus.ACTIVE,
) -> Credential:
    return Credential(
        credential_id=credential_id,
        credential_type="api_key",
        value=value,
        expires_at=expires_at,
        rotation_before_hours=rotation_before_hours,
        status=status,
    )


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------


class TestGenerateCredentialValue:
    def test_default_length(self) -> None:
        value = _generate_credential_value()
        assert len(value) == 32

    def test_custom_length(self) -> None:
        value = _generate_credential_value(64)
        assert len(value) == 64

    def test_unique_values(self) -> None:
        values = {_generate_credential_value() for _ in range(20)}
        assert len(values) == 20  # All unique


# ---------------------------------------------------------------------------
# Credential dataclass
# ---------------------------------------------------------------------------


class TestCredential:
    def test_no_expiry_does_not_need_rotation(self) -> None:
        cred = _make_credential()
        assert not cred.needs_rotation()

    def test_needs_rotation_when_within_window(self) -> None:
        # Expires in 12 hours, rotation window is 24 hours
        cred = _make_credential(expires_at=_utc(+12), rotation_before_hours=24.0)
        assert cred.needs_rotation()

    def test_no_rotation_needed_when_outside_window(self) -> None:
        # Expires in 48 hours, rotation window is 24 hours
        cred = _make_credential(expires_at=_utc(+48), rotation_before_hours=24.0)
        assert not cred.needs_rotation()

    def test_already_expired_needs_rotation(self) -> None:
        cred = _make_credential(expires_at=_utc(-1))
        assert cred.needs_rotation()

    def test_revoked_never_needs_rotation(self) -> None:
        cred = _make_credential(
            expires_at=_utc(-1),
            status=RotationStatus.REVOKED,
        )
        assert not cred.needs_rotation()

    def test_is_expired_when_past_expiry(self) -> None:
        cred = _make_credential(expires_at=_utc(-1))
        assert cred.is_expired()

    def test_not_expired_when_future_expiry(self) -> None:
        cred = _make_credential(expires_at=_utc(+24))
        assert not cred.is_expired()

    def test_to_dict_masks_value_by_default(self) -> None:
        cred = _make_credential(value="mysecretvalue")
        data = cred.to_dict()
        assert data["value"] == "***REDACTED***"

    def test_to_dict_includes_value_when_requested(self) -> None:
        cred = _make_credential(value="mysecretvalue")
        data = cred.to_dict(include_value=True)
        assert data["value"] == "mysecretvalue"

    def test_to_dict_structure(self) -> None:
        cred = _make_credential()
        data = cred.to_dict()
        assert "credential_id" in data
        assert "credential_type" in data
        assert "status" in data
        assert "expires_at" in data


# ---------------------------------------------------------------------------
# CredentialRotator — registration
# ---------------------------------------------------------------------------


class TestCredentialRotatorRegistration:
    def test_register_credential(self) -> None:
        rotator = CredentialRotator()
        cred = _make_credential()
        rotator.register(cred)
        assert rotator.get("cred-001") is not None

    def test_register_duplicate_raises(self) -> None:
        rotator = CredentialRotator()
        rotator.register(_make_credential())
        with pytest.raises(ValueError, match="already registered"):
            rotator.register(_make_credential())

    def test_get_nonexistent_returns_none(self) -> None:
        rotator = CredentialRotator()
        assert rotator.get("ghost") is None

    def test_revoke_credential(self) -> None:
        rotator = CredentialRotator()
        rotator.register(_make_credential())
        assert rotator.revoke("cred-001") is True
        cred = rotator.get("cred-001")
        assert cred is not None
        assert cred.status == RotationStatus.REVOKED

    def test_revoke_nonexistent_returns_false(self) -> None:
        rotator = CredentialRotator()
        assert rotator.revoke("ghost") is False


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class TestRotation:
    def test_rotate_changes_value(self) -> None:
        rotator = CredentialRotator()
        rotator.register(_make_credential(value="oldvalue123456789012"))
        result = rotator.rotate("cred-001", new_value="newvalue12345678901234")
        assert result.success is True
        cred = rotator.get("cred-001")
        assert cred is not None
        assert cred.value == "newvalue12345678901234"

    def test_rotate_auto_generates_value(self) -> None:
        rotator = CredentialRotator()
        rotator.register(_make_credential(value="oldvalue123456789012"))
        result = rotator.rotate("cred-001")
        assert result.success is True
        cred = rotator.get("cred-001")
        assert cred is not None
        assert cred.value != "oldvalue123456789012"
        assert len(cred.value) == 32

    def test_rotate_updates_status_and_timestamp(self) -> None:
        rotator = CredentialRotator()
        rotator.register(_make_credential())
        rotator.rotate("cred-001")
        cred = rotator.get("cred-001")
        assert cred is not None
        assert cred.status == RotationStatus.ROTATED
        assert cred.last_rotated_at is not None

    def test_rotate_nonexistent_returns_failure(self) -> None:
        rotator = CredentialRotator()
        result = rotator.rotate("ghost")
        assert result.success is False
        assert "not found" in result.error

    def test_rotate_revoked_returns_failure(self) -> None:
        rotator = CredentialRotator()
        cred = _make_credential(status=RotationStatus.REVOKED)
        rotator.register(cred)
        result = rotator.rotate("cred-001")
        assert result.success is False
        assert "revoked" in result.error

    def test_rotation_callback_invoked(self) -> None:
        received: list[tuple[str, str]] = []

        def callback(cred_id: str, new_val: str) -> None:
            received.append((cred_id, new_val))

        rotator = CredentialRotator(rotation_callback=callback)
        rotator.register(_make_credential())
        rotator.rotate("cred-001", new_value="freshvalue1234567890")
        assert len(received) == 1
        assert received[0][0] == "cred-001"
        assert received[0][1] == "freshvalue1234567890"


# ---------------------------------------------------------------------------
# Rotate due
# ---------------------------------------------------------------------------


class TestRotateDue:
    def test_rotate_due_processes_eligible_credentials(self) -> None:
        rotator = CredentialRotator()
        # Should rotate: expires in 12h, window is 24h
        rotator.register(_make_credential("c1", expires_at=_utc(+12), rotation_before_hours=24))
        # Should NOT rotate: expires in 48h, window is 24h
        rotator.register(_make_credential("c2", expires_at=_utc(+48), rotation_before_hours=24))
        results = rotator.rotate_due()
        rotated_ids = [r.credential_id for r in results]
        assert "c1" in rotated_ids
        assert "c2" not in rotated_ids

    def test_rotate_due_returns_empty_when_none_due(self) -> None:
        rotator = CredentialRotator()
        rotator.register(_make_credential("c1", expires_at=_utc(+72)))
        results = rotator.rotate_due()
        assert results == []


class TestPendingRotation:
    def test_pending_rotation_identifies_due_credentials(self) -> None:
        rotator = CredentialRotator()
        rotator.register(_make_credential("c1", expires_at=_utc(+6), rotation_before_hours=24))
        rotator.register(_make_credential("c2", expires_at=_utc(+48), rotation_before_hours=24))
        pending = rotator.pending_rotation()
        assert "c1" in pending
        assert "c2" not in pending


class TestRotationResult:
    def test_to_dict_structure(self) -> None:
        result = RotationResult(
            credential_id="cred-001",
            old_value="old",
            new_value="new",
            rotated_at=datetime.now(timezone.utc),
            success=True,
        )
        data = result.to_dict()
        assert "credential_id" in data
        assert "rotated_at" in data
        assert "success" in data

    def test_to_dict_masks_values_by_default(self) -> None:
        result = RotationResult(
            credential_id="cred-001",
            old_value="oldsecret",
            new_value="newsecret",
            rotated_at=datetime.now(timezone.utc),
            success=True,
        )
        data = result.to_dict()
        assert data["old_value"] == "***"
        assert data["new_value"] == "***"


# ---------------------------------------------------------------------------
# LeakageDetector
# ---------------------------------------------------------------------------


class TestLeakageDetector:
    def test_detects_value_in_text(self) -> None:
        detector = LeakageDetector()
        cred = _make_credential(value="supersecretapikey12345")
        result = detector.scan(cred, ["Log entry: key=supersecretapikey12345 used"])
        assert result.leaked is True
        assert len(result.found_in) == 1

    def test_no_leak_when_value_absent(self) -> None:
        detector = LeakageDetector()
        cred = _make_credential(value="supersecretapikey12345")
        result = detector.scan(cred, ["Normal log entry with no sensitive data"])
        assert result.leaked is False
        assert len(result.found_in) == 0

    def test_skips_short_credentials(self) -> None:
        detector = LeakageDetector(min_value_length=8)
        cred = _make_credential(value="short")
        result = detector.scan(cred, ["Contains short in text"])
        assert result.leaked is False

    def test_scan_count_correct(self) -> None:
        detector = LeakageDetector()
        cred = _make_credential(value="supersecretvalue12345")
        texts = ["log1", "log2", "log3"]
        result = detector.scan(cred, texts)
        assert result.scan_count == 3

    def test_finds_all_occurrences(self) -> None:
        detector = LeakageDetector()
        cred = _make_credential(value="supersecretapikey12345")
        texts = [
            "First log: supersecretapikey12345",
            "Second log: safe content",
            "Third log: supersecretapikey12345 again",
        ]
        result = detector.scan(cred, texts)
        assert result.leaked is True
        assert len(result.found_in) == 2

    def test_scan_multiple_credentials(self) -> None:
        detector = LeakageDetector()
        cred_a = _make_credential("c1", value="secretvalueabc12345")
        cred_b = _make_credential("c2", value="anothersecretxyz678")
        texts = ["Found secretvalueabc12345 in output"]
        results = detector.scan_multiple([cred_a, cred_b], texts)
        assert len(results) == 2
        leaked = [r for r in results if r.leaked]
        assert len(leaked) == 1
        assert leaked[0].credential_id == "c1"

    def test_to_dict_structure(self) -> None:
        result = LeakageResult(
            credential_id="c1",
            leaked=True,
            found_in=["snippet"],
            scan_count=5,
        )
        data = result.to_dict()
        assert "credential_id" in data
        assert "leaked" in data
        assert "scan_count" in data
