"""Tests for agent_identity.delegation.chain — DelegationChain."""
from __future__ import annotations

import pytest

from agent_identity.delegation.chain import (
    ChainEntry,
    DelegationChain,
    DelegationChainError,
)
from agent_identity.delegation.token import DelegationToken


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SECRET: bytes = b"test-secret-key-for-chain-tests"


def make_token(
    issuer: str,
    delegate: str,
    scopes: list[str],
    parent_id: str | None = None,
    ttl: int = 3600,
) -> DelegationToken:
    return DelegationToken.create_token(
        issuer_id=issuer,
        delegate_id=delegate,
        scopes=scopes,
        secret_key=SECRET,
        ttl_seconds=ttl,
        parent_token_id=parent_id,
    )


@pytest.fixture()
def chain() -> DelegationChain:
    return DelegationChain(max_depth=5)


@pytest.fixture()
def root_token() -> DelegationToken:
    return make_token("root-issuer", "agent-a", ["read", "write", "execute"])


@pytest.fixture()
def child_token(root_token: DelegationToken) -> DelegationToken:
    return make_token("agent-a", "agent-b", ["read", "write"], parent_id=root_token.token_id)


@pytest.fixture()
def grandchild_token(child_token: DelegationToken) -> DelegationToken:
    return make_token("agent-b", "agent-c", ["read"], parent_id=child_token.token_id)


# ---------------------------------------------------------------------------
# ChainEntry dataclass
# ---------------------------------------------------------------------------


class TestChainEntry:
    def test_fields(self, root_token: DelegationToken) -> None:
        entry = ChainEntry(token=root_token, depth=0)
        assert entry.token is root_token
        assert entry.depth == 0


# ---------------------------------------------------------------------------
# DelegationChain — add_delegation
# ---------------------------------------------------------------------------


class TestAddDelegation:
    def test_add_root_token_succeeds(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        assert len(chain) == 1

    def test_add_root_has_depth_zero(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        assert chain.get_depth(root_token.token_id) == 0

    def test_add_child_increments_depth(
        self,
        chain: DelegationChain,
        root_token: DelegationToken,
        child_token: DelegationToken,
    ) -> None:
        chain.add_delegation(root_token)
        chain.add_delegation(child_token)
        assert chain.get_depth(child_token.token_id) == 1

    def test_add_grandchild_depth_is_two(
        self,
        chain: DelegationChain,
        root_token: DelegationToken,
        child_token: DelegationToken,
        grandchild_token: DelegationToken,
    ) -> None:
        chain.add_delegation(root_token)
        chain.add_delegation(child_token)
        chain.add_delegation(grandchild_token)
        assert chain.get_depth(grandchild_token.token_id) == 2

    def test_duplicate_token_id_raises_value_error(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        with pytest.raises(ValueError, match="already present"):
            chain.add_delegation(root_token)

    def test_missing_parent_raises_chain_error(
        self, chain: DelegationChain
    ) -> None:
        orphan = make_token("x", "y", ["read"], parent_id="nonexistent-token-id")
        with pytest.raises(DelegationChainError, match="not found"):
            chain.add_delegation(orphan)

    def test_scope_escalation_raises_chain_error(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        # child claims a scope the parent does not have
        escalation = make_token(
            "agent-a",
            "agent-b",
            ["read", "admin"],  # "admin" is not in root scopes
            parent_id=root_token.token_id,
        )
        with pytest.raises(DelegationChainError, match="expand scopes"):
            chain.add_delegation(escalation)

    def test_max_depth_exceeded_raises_chain_error(self) -> None:
        tiny_chain = DelegationChain(max_depth=1)
        root = make_token("r", "a", ["read"])
        child = make_token("a", "b", ["read"], parent_id=root.token_id)
        too_deep = make_token("b", "c", ["read"], parent_id=child.token_id)

        tiny_chain.add_delegation(root)
        tiny_chain.add_delegation(child)
        with pytest.raises(DelegationChainError, match="Max delegation chain depth"):
            tiny_chain.add_delegation(too_deep)

    def test_child_with_equal_scopes_is_allowed(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        same_scopes = make_token(
            "agent-a", "agent-b", list(root_token.scopes), parent_id=root_token.token_id
        )
        chain.add_delegation(same_scopes)  # must not raise

    def test_empty_scopes_always_subset(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        no_scope = make_token("agent-a", "agent-b", [], parent_id=root_token.token_id)
        chain.add_delegation(no_scope)  # must not raise


# ---------------------------------------------------------------------------
# DelegationChain — get_chain
# ---------------------------------------------------------------------------


class TestGetChain:
    def test_root_only_chain_has_one_element(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        result = chain.get_chain(root_token.token_id)
        assert len(result) == 1
        assert result[0].token_id == root_token.token_id

    def test_chain_order_root_first(
        self,
        chain: DelegationChain,
        root_token: DelegationToken,
        child_token: DelegationToken,
        grandchild_token: DelegationToken,
    ) -> None:
        chain.add_delegation(root_token)
        chain.add_delegation(child_token)
        chain.add_delegation(grandchild_token)
        result = chain.get_chain(grandchild_token.token_id)
        assert len(result) == 3
        assert result[0].token_id == root_token.token_id
        assert result[1].token_id == child_token.token_id
        assert result[2].token_id == grandchild_token.token_id

    def test_unknown_token_id_raises_key_error(
        self, chain: DelegationChain
    ) -> None:
        with pytest.raises(KeyError, match="not found"):
            chain.get_chain("ghost-id")


# ---------------------------------------------------------------------------
# DelegationChain — effective_scopes
# ---------------------------------------------------------------------------


class TestEffectiveScopes:
    def test_root_effective_scopes_equal_its_scopes(
        self, chain: DelegationChain, root_token: DelegationToken
    ) -> None:
        chain.add_delegation(root_token)
        scopes = chain.effective_scopes(root_token.token_id)
        assert scopes == frozenset(root_token.scopes)

    def test_child_effective_scopes_are_intersection(
        self,
        chain: DelegationChain,
        root_token: DelegationToken,
        child_token: DelegationToken,
    ) -> None:
        chain.add_delegation(root_token)
        chain.add_delegation(child_token)
        scopes = chain.effective_scopes(child_token.token_id)
        # child has ["read", "write"]; root has ["read", "write", "execute"]
        assert scopes == frozenset(["read", "write"])

    def test_grandchild_effective_scopes_narrowed_to_read(
        self,
        chain: DelegationChain,
        root_token: DelegationToken,
        child_token: DelegationToken,
        grandchild_token: DelegationToken,
    ) -> None:
        chain.add_delegation(root_token)
        chain.add_delegation(child_token)
        chain.add_delegation(grandchild_token)
        scopes = chain.effective_scopes(grandchild_token.token_id)
        assert scopes == frozenset(["read"])

    def test_effective_scopes_unknown_token_raises(
        self, chain: DelegationChain
    ) -> None:
        with pytest.raises(KeyError):
            chain.effective_scopes("unknown")


# ---------------------------------------------------------------------------
# DelegationChain — get_depth / token_ids / __len__
# ---------------------------------------------------------------------------


class TestQueryMethods:
    def test_get_depth_unknown_raises(self, chain: DelegationChain) -> None:
        with pytest.raises(KeyError):
            chain.get_depth("missing")

    def test_token_ids_returns_sorted_list(
        self,
        chain: DelegationChain,
        root_token: DelegationToken,
        child_token: DelegationToken,
    ) -> None:
        chain.add_delegation(root_token)
        chain.add_delegation(child_token)
        ids = chain.token_ids()
        assert ids == sorted([root_token.token_id, child_token.token_id])

    def test_len_empty_chain(self, chain: DelegationChain) -> None:
        assert len(chain) == 0

    def test_len_after_additions(
        self,
        chain: DelegationChain,
        root_token: DelegationToken,
        child_token: DelegationToken,
    ) -> None:
        chain.add_delegation(root_token)
        chain.add_delegation(child_token)
        assert len(chain) == 2
