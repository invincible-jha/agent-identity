"""Tests for agent_identity.native.resolver — BindingStore and resolve_binding.

Covers:
- BindingStore CRUD: store / lookup / remove / list_all / clear
- BindingStore membership (__contains__) and length (__len__)
- resolve_binding with an existing binding returns found=True, verified=True
- resolve_binding with a missing agent_id returns found=False, verified=False
- resolve_binding populates the error field when not found
- resolve_binding returns the correct IdentityBinding in the result
- Overwriting a stored binding with a new one replaces it
- BindingStore.clear() empties the store
"""
from __future__ import annotations

import pytest

from agent_identity.native.binding import BindingMethod, NativeIdentityBinder
from agent_identity.native.resolver import BindingStore, ResolutionResult, resolve_binding

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_AGENT_A = "agent-alpha"
_AGENT_B = "agent-beta"
_AGENT_C = "agent-gamma"


@pytest.fixture()
def store() -> BindingStore:
    """Return a fresh, empty BindingStore for each test."""
    return BindingStore()


@pytest.fixture()
def binder() -> NativeIdentityBinder:
    """Return a NativeIdentityBinder using COMPOSITE (default)."""
    return NativeIdentityBinder()


@pytest.fixture()
def populated_store(store: BindingStore, binder: NativeIdentityBinder) -> BindingStore:
    """Return a store pre-populated with bindings for AGENT_A and AGENT_B."""
    store.store(binder.bind(_AGENT_A))
    store.store(binder.bind(_AGENT_B))
    return store


# ===========================================================================
# BindingStore — basic construction
# ===========================================================================


class TestBindingStoreConstruction:
    def test_new_store_is_empty(self, store: BindingStore) -> None:
        assert len(store) == 0

    def test_new_store_list_all_is_empty(self, store: BindingStore) -> None:
        assert store.list_all() == []

    def test_new_store_contains_no_agents(self, store: BindingStore) -> None:
        assert _AGENT_A not in store


# ===========================================================================
# BindingStore.store()
# ===========================================================================


class TestBindingStoreStore:
    def test_store_increases_length(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        assert len(store) == 1

    def test_store_multiple_agents(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        store.store(binder.bind(_AGENT_B))
        assert len(store) == 2

    def test_store_overwrites_existing_binding(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        first_binding = binder.bind(_AGENT_A, metadata={"version": "1"})
        store.store(first_binding)

        second_binding = binder.bind(_AGENT_A, metadata={"version": "2"})
        store.store(second_binding)

        assert len(store) == 1
        retrieved = store.lookup(_AGENT_A)
        assert retrieved is not None
        assert retrieved.metadata["version"] == "2"

    def test_store_returns_none(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        result = store.store(binder.bind(_AGENT_A))
        assert result is None


# ===========================================================================
# BindingStore.lookup()
# ===========================================================================


class TestBindingStoreLookup:
    def test_lookup_existing_binding(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        original = binder.bind(_AGENT_A)
        store.store(original)
        retrieved = store.lookup(_AGENT_A)
        assert retrieved is original

    def test_lookup_missing_agent_returns_none(self, store: BindingStore) -> None:
        assert store.lookup("nonexistent-agent") is None

    def test_lookup_after_remove_returns_none(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        store.remove(_AGENT_A)
        assert store.lookup(_AGENT_A) is None

    def test_lookup_agent_b_does_not_return_agent_a_binding(
        self, populated_store: BindingStore
    ) -> None:
        binding = populated_store.lookup(_AGENT_B)
        assert binding is not None
        assert binding.agent_id == _AGENT_B


# ===========================================================================
# BindingStore.remove()
# ===========================================================================


class TestBindingStoreRemove:
    def test_remove_existing_returns_true(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        assert store.remove(_AGENT_A) is True

    def test_remove_missing_returns_false(self, store: BindingStore) -> None:
        assert store.remove("nonexistent-agent") is False

    def test_remove_decreases_length(
        self, populated_store: BindingStore
    ) -> None:
        populated_store.remove(_AGENT_A)
        assert len(populated_store) == 1

    def test_remove_only_removes_target(
        self, populated_store: BindingStore
    ) -> None:
        populated_store.remove(_AGENT_A)
        assert populated_store.lookup(_AGENT_B) is not None

    def test_remove_twice_returns_false_second_time(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        store.remove(_AGENT_A)
        assert store.remove(_AGENT_A) is False


# ===========================================================================
# BindingStore.list_all()
# ===========================================================================


class TestBindingStoreListAll:
    def test_list_all_empty_store(self, store: BindingStore) -> None:
        assert store.list_all() == []

    def test_list_all_returns_all_bindings(
        self, populated_store: BindingStore
    ) -> None:
        all_bindings = populated_store.list_all()
        agent_ids = {b.agent_id for b in all_bindings}
        assert agent_ids == {_AGENT_A, _AGENT_B}

    def test_list_all_returns_copy(
        self, populated_store: BindingStore
    ) -> None:
        """Mutating the returned list must not affect the store."""
        listing = populated_store.list_all()
        listing.clear()
        assert len(populated_store) == 2

    def test_list_all_count_matches_len(
        self, populated_store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        populated_store.store(binder.bind(_AGENT_C))
        assert len(populated_store.list_all()) == len(populated_store)


# ===========================================================================
# BindingStore.clear()
# ===========================================================================


class TestBindingStoreClear:
    def test_clear_empties_store(self, populated_store: BindingStore) -> None:
        populated_store.clear()
        assert len(populated_store) == 0

    def test_clear_makes_list_all_empty(self, populated_store: BindingStore) -> None:
        populated_store.clear()
        assert populated_store.list_all() == []

    def test_clear_on_empty_store_is_safe(self, store: BindingStore) -> None:
        store.clear()  # must not raise
        assert len(store) == 0

    def test_store_after_clear_works(
        self, populated_store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        populated_store.clear()
        populated_store.store(binder.bind(_AGENT_C))
        assert len(populated_store) == 1


# ===========================================================================
# BindingStore — membership and length
# ===========================================================================


class TestBindingStoreMembership:
    def test_contains_after_store(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        assert _AGENT_A in store

    def test_not_contains_before_store(self, store: BindingStore) -> None:
        assert _AGENT_A not in store

    def test_not_contains_after_remove(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        store.remove(_AGENT_A)
        assert _AGENT_A not in store

    def test_len_reflects_number_of_distinct_agents(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        assert len(store) == 0
        store.store(binder.bind(_AGENT_A))
        assert len(store) == 1
        store.store(binder.bind(_AGENT_B))
        assert len(store) == 2
        store.remove(_AGENT_A)
        assert len(store) == 1


# ===========================================================================
# resolve_binding()
# ===========================================================================


class TestResolveBinding:
    """resolve_binding() combines lookup with live runtime verification."""

    def test_resolve_existing_binding_found(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        result = resolve_binding(_AGENT_A, store)
        assert result.found is True

    def test_resolve_existing_binding_verified(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        result = resolve_binding(_AGENT_A, store)
        assert result.verified is True

    def test_resolve_existing_binding_returns_binding(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        original = binder.bind(_AGENT_A)
        store.store(original)
        result = resolve_binding(_AGENT_A, store)
        assert result.binding is original

    def test_resolve_existing_binding_no_error(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        result = resolve_binding(_AGENT_A, store)
        assert result.error is None

    def test_resolve_missing_agent_not_found(self, store: BindingStore) -> None:
        result = resolve_binding("ghost-agent", store)
        assert result.found is False

    def test_resolve_missing_agent_not_verified(self, store: BindingStore) -> None:
        result = resolve_binding("ghost-agent", store)
        assert result.verified is False

    def test_resolve_missing_agent_binding_is_none(self, store: BindingStore) -> None:
        result = resolve_binding("ghost-agent", store)
        assert result.binding is None

    def test_resolve_missing_agent_has_error_message(self, store: BindingStore) -> None:
        result = resolve_binding("ghost-agent", store)
        assert result.error is not None
        assert len(result.error) > 0

    def test_resolve_missing_agent_error_contains_agent_id(
        self, store: BindingStore
    ) -> None:
        result = resolve_binding("ghost-agent", store)
        assert "ghost-agent" in (result.error or "")

    def test_resolve_returns_resolution_result_type(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        result = resolve_binding(_AGENT_A, store)
        assert isinstance(result, ResolutionResult)

    @pytest.mark.parametrize("method", list(BindingMethod))
    def test_resolve_all_methods_verified(
        self, store: BindingStore, method: BindingMethod
    ) -> None:
        """resolve_binding works correctly for all four BindingMethod values."""
        method_binder = NativeIdentityBinder(method)
        store.store(method_binder.bind(_AGENT_A))
        result = resolve_binding(_AGENT_A, store)
        assert result.found is True
        assert result.verified is True

    def test_resolve_after_overwrite_uses_new_binding(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        """Re-binding an agent should resolve to the new binding."""
        first_binding = binder.bind(_AGENT_A, metadata={"round": "first"})
        store.store(first_binding)

        second_binding = binder.bind(_AGENT_A, metadata={"round": "second"})
        store.store(second_binding)

        result = resolve_binding(_AGENT_A, store)
        assert result.found is True
        assert result.binding is second_binding
        assert result.binding.metadata["round"] == "second"

    def test_resolve_after_remove_returns_not_found(
        self, store: BindingStore, binder: NativeIdentityBinder
    ) -> None:
        store.store(binder.bind(_AGENT_A))
        store.remove(_AGENT_A)
        result = resolve_binding(_AGENT_A, store)
        assert result.found is False

    def test_resolve_one_agent_does_not_affect_another(
        self, populated_store: BindingStore
    ) -> None:
        result_a = resolve_binding(_AGENT_A, populated_store)
        result_b = resolve_binding(_AGENT_B, populated_store)

        assert result_a.found is True
        assert result_b.found is True
        assert result_a.binding is not result_b.binding
        assert result_a.binding is not None
        assert result_b.binding is not None
        assert result_a.binding.agent_id == _AGENT_A
        assert result_b.binding.agent_id == _AGENT_B
