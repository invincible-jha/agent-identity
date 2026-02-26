"""Tests for agent_identity.certificates.revocation — RevocationList."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_identity.certificates.revocation import RevocationList


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def revocation_list() -> RevocationList:
    return RevocationList()


@pytest.fixture()
def persist_path(tmp_path: Path) -> Path:
    return tmp_path / "revoked.json"


# ---------------------------------------------------------------------------
# RevocationList — in-memory (no persist path)
# ---------------------------------------------------------------------------


class TestInMemory:
    def test_not_revoked_initially(self, revocation_list: RevocationList) -> None:
        assert revocation_list.is_revoked(12345) is False

    def test_revoke_cert_marks_serial_revoked(
        self, revocation_list: RevocationList
    ) -> None:
        revocation_list.revoke_cert(99999)
        assert revocation_list.is_revoked(99999) is True

    def test_revoke_multiple_serials(self, revocation_list: RevocationList) -> None:
        revocation_list.revoke_cert(1)
        revocation_list.revoke_cert(2)
        assert revocation_list.is_revoked(1) is True
        assert revocation_list.is_revoked(2) is True

    def test_unrelated_serial_not_revoked(
        self, revocation_list: RevocationList
    ) -> None:
        revocation_list.revoke_cert(100)
        assert revocation_list.is_revoked(200) is False

    def test_revoke_idempotent(self, revocation_list: RevocationList) -> None:
        revocation_list.revoke_cert(42)
        revocation_list.revoke_cert(42)
        assert revocation_list.count() == 1

    def test_revoke_with_reason_accepted(
        self, revocation_list: RevocationList
    ) -> None:
        revocation_list.revoke_cert(55, reason="key compromise")
        assert revocation_list.is_revoked(55) is True

    def test_unrevoke_removes_serial(self, revocation_list: RevocationList) -> None:
        revocation_list.revoke_cert(77)
        revocation_list.unrevoke_cert(77)
        assert revocation_list.is_revoked(77) is False

    def test_unrevoke_nonexistent_is_noop(
        self, revocation_list: RevocationList
    ) -> None:
        revocation_list.unrevoke_cert(9999)  # must not raise

    def test_revoked_serials_snapshot_is_frozenset(
        self, revocation_list: RevocationList
    ) -> None:
        revocation_list.revoke_cert(1)
        revocation_list.revoke_cert(2)
        snapshot = revocation_list.revoked_serials()
        assert isinstance(snapshot, frozenset)
        assert snapshot == frozenset({1, 2})

    def test_count_zero_initially(self, revocation_list: RevocationList) -> None:
        assert revocation_list.count() == 0

    def test_count_increments(self, revocation_list: RevocationList) -> None:
        revocation_list.revoke_cert(1)
        revocation_list.revoke_cert(2)
        assert revocation_list.count() == 2

    def test_count_decrements_on_unrevoke(
        self, revocation_list: RevocationList
    ) -> None:
        revocation_list.revoke_cert(1)
        revocation_list.unrevoke_cert(1)
        assert revocation_list.count() == 0


# ---------------------------------------------------------------------------
# RevocationList — persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_persist_creates_file_on_revoke(self, persist_path: Path) -> None:
        crl = RevocationList(persist_path=persist_path)
        crl.revoke_cert(100)
        assert persist_path.exists()

    def test_persist_file_contains_correct_serials(
        self, persist_path: Path
    ) -> None:
        crl = RevocationList(persist_path=persist_path)
        crl.revoke_cert(10)
        crl.revoke_cert(20)
        payload = json.loads(persist_path.read_text(encoding="utf-8"))
        assert set(payload["revoked_serials"]) == {10, 20}

    def test_load_existing_persist_file_on_init(self, persist_path: Path) -> None:
        """A second RevocationList opened at the same path should restore revocations."""
        first = RevocationList(persist_path=persist_path)
        first.revoke_cert(777)
        second = RevocationList(persist_path=persist_path)
        assert second.is_revoked(777) is True

    def test_unrevoke_updates_persist_file(self, persist_path: Path) -> None:
        crl = RevocationList(persist_path=persist_path)
        crl.revoke_cert(500)
        crl.unrevoke_cert(500)
        payload = json.loads(persist_path.read_text(encoding="utf-8"))
        assert 500 not in payload["revoked_serials"]

    def test_persist_path_parent_created_if_missing(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "sub" / "dir" / "revoked.json"
        crl = RevocationList(persist_path=deep_path)
        crl.revoke_cert(1)
        assert deep_path.exists()

    def test_corrupt_persist_file_resets_to_empty(self, persist_path: Path) -> None:
        persist_path.write_text("not valid json", encoding="utf-8")
        crl = RevocationList(persist_path=persist_path)
        assert crl.count() == 0

    def test_no_persist_path_does_not_write_to_disk(
        self, revocation_list: RevocationList, tmp_path: Path
    ) -> None:
        revocation_list.revoke_cert(1)
        # Nothing should have been written anywhere under tmp_path
        assert list(tmp_path.rglob("*.json")) == []
