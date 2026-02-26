"""Tests for agent_identity.delegation.revocation — DelegationRevocation."""
from __future__ import annotations

import pytest

from agent_identity.delegation.revocation import DelegationRevocation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def revocation() -> DelegationRevocation:
    return DelegationRevocation()


# ---------------------------------------------------------------------------
# DelegationRevocation — revoke / is_revoked
# ---------------------------------------------------------------------------


class TestRevokeAndIsRevoked:
    def test_not_revoked_initially(self, revocation: DelegationRevocation) -> None:
        assert revocation.is_revoked("token-001") is False

    def test_revoke_marks_token_revoked(self, revocation: DelegationRevocation) -> None:
        revocation.revoke("token-001")
        assert revocation.is_revoked("token-001") is True

    def test_revoke_multiple_tokens(self, revocation: DelegationRevocation) -> None:
        revocation.revoke("token-001")
        revocation.revoke("token-002")
        assert revocation.is_revoked("token-001") is True
        assert revocation.is_revoked("token-002") is True

    def test_unrelated_token_not_revoked(self, revocation: DelegationRevocation) -> None:
        revocation.revoke("token-001")
        assert revocation.is_revoked("token-999") is False

    def test_revoke_idempotent(self, revocation: DelegationRevocation) -> None:
        revocation.revoke("token-001")
        revocation.revoke("token-001")  # second call must not raise
        assert revocation.count() == 1


# ---------------------------------------------------------------------------
# DelegationRevocation — revoke_chain
# ---------------------------------------------------------------------------


class TestRevokeChain:
    def test_revoke_chain_revokes_root_and_descendants(
        self, revocation: DelegationRevocation
    ) -> None:
        # Structure: root -> child -> grandchild; sibling is unrelated
        all_ids = ["root", "child", "grandchild", "sibling"]
        parent_map: dict[str, str | None] = {
            "root": None,
            "child": "root",
            "grandchild": "child",
            "sibling": None,
        }
        revoked = revocation.revoke_chain("root", all_ids, parent_map)
        assert sorted(revoked) == ["child", "grandchild", "root"]
        assert revocation.is_revoked("root") is True
        assert revocation.is_revoked("child") is True
        assert revocation.is_revoked("grandchild") is True
        assert revocation.is_revoked("sibling") is False

    def test_revoke_chain_returns_sorted_list(
        self, revocation: DelegationRevocation
    ) -> None:
        all_ids = ["z-token", "a-token", "m-token"]
        parent_map = {"z-token": None, "a-token": "z-token", "m-token": "z-token"}
        revoked = revocation.revoke_chain("z-token", all_ids, parent_map)
        assert revoked == sorted(revoked)

    def test_revoke_chain_skips_already_revoked(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.revoke("child")
        all_ids = ["root", "child"]
        parent_map = {"root": None, "child": "root"}
        revoked = revocation.revoke_chain("root", all_ids, parent_map)
        # "child" was already revoked, so it should not appear in revoked_now
        assert "child" not in revoked
        assert "root" in revoked

    def test_revoke_chain_leaf_token_only_revokes_itself(
        self, revocation: DelegationRevocation
    ) -> None:
        all_ids = ["root", "leaf"]
        parent_map = {"root": None, "leaf": "root"}
        revoked = revocation.revoke_chain("leaf", all_ids, parent_map)
        assert revoked == ["leaf"]
        assert revocation.is_revoked("root") is False

    def test_revoke_chain_with_empty_list(
        self, revocation: DelegationRevocation
    ) -> None:
        revoked = revocation.revoke_chain("root", [], {})
        assert revoked == []


# ---------------------------------------------------------------------------
# DelegationRevocation — unrevoke
# ---------------------------------------------------------------------------


class TestUnrevoke:
    def test_unrevoke_removes_from_revocation_set(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.revoke("token-001")
        revocation.unrevoke("token-001")
        assert revocation.is_revoked("token-001") is False

    def test_unrevoke_nonexistent_is_noop(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.unrevoke("ghost-token")  # must not raise

    def test_unrevoke_does_not_affect_other_tokens(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.revoke("token-001")
        revocation.revoke("token-002")
        revocation.unrevoke("token-001")
        assert revocation.is_revoked("token-002") is True


# ---------------------------------------------------------------------------
# DelegationRevocation — revoked_token_ids / count
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_revoked_token_ids_empty_initially(
        self, revocation: DelegationRevocation
    ) -> None:
        assert revocation.revoked_token_ids() == frozenset()

    def test_revoked_token_ids_is_immutable_snapshot(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.revoke("token-001")
        snapshot = revocation.revoked_token_ids()
        revocation.revoke("token-002")
        assert "token-002" not in snapshot  # snapshot was taken before

    def test_count_zero_initially(self, revocation: DelegationRevocation) -> None:
        assert revocation.count() == 0

    def test_count_increments_on_revoke(self, revocation: DelegationRevocation) -> None:
        revocation.revoke("token-001")
        revocation.revoke("token-002")
        assert revocation.count() == 2

    def test_count_decrements_on_unrevoke(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.revoke("token-001")
        revocation.unrevoke("token-001")
        assert revocation.count() == 0


# ---------------------------------------------------------------------------
# DelegationRevocation — restore
# ---------------------------------------------------------------------------


class TestRestore:
    def test_restore_marks_all_provided_ids_as_revoked(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.restore(["token-a", "token-b", "token-c"])
        assert revocation.is_revoked("token-a") is True
        assert revocation.is_revoked("token-b") is True
        assert revocation.is_revoked("token-c") is True

    def test_restore_is_additive(self, revocation: DelegationRevocation) -> None:
        revocation.revoke("existing")
        revocation.restore(["new-one"])
        assert revocation.is_revoked("existing") is True
        assert revocation.is_revoked("new-one") is True

    def test_restore_empty_list_is_noop(
        self, revocation: DelegationRevocation
    ) -> None:
        revocation.restore([])
        assert revocation.count() == 0
