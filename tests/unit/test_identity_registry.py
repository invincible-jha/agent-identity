"""Tests for agent_identity.registry.identity_registry — IdentityRegistry."""
from __future__ import annotations

import datetime

import pytest

from agent_identity.registry.identity_registry import (
    AgentAlreadyRegisteredError,
    AgentIdentityRecord,
    AgentNotFoundError,
    IdentityRegistry,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> IdentityRegistry:
    return IdentityRegistry()


def _register(
    registry: IdentityRegistry,
    agent_id: str = "agent-001",
    display_name: str = "Test Agent",
    organization: str = "TestOrg",
    capabilities: list[str] | None = None,
    metadata: dict[str, object] | None = None,
    did: str = "",
) -> AgentIdentityRecord:
    return registry.register(
        agent_id=agent_id,
        display_name=display_name,
        organization=organization,
        capabilities=capabilities or [],
        metadata=metadata or {},
        did=did,
    )


# ---------------------------------------------------------------------------
# AgentIdentityRecord — to_dict
# ---------------------------------------------------------------------------


class TestAgentIdentityRecord:
    def test_to_dict_contains_all_fields(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        record = AgentIdentityRecord(
            agent_id="agent-xyz",
            display_name="XYZ Agent",
            organization="OrgA",
            capabilities=["read"],
            metadata={"env": "prod"},
            did="did:aumos:agent-xyz",
            registered_at=now,
            updated_at=now,
            active=True,
        )
        d = record.to_dict()
        assert d["agent_id"] == "agent-xyz"
        assert d["display_name"] == "XYZ Agent"
        assert d["organization"] == "OrgA"
        assert d["capabilities"] == ["read"]
        assert d["metadata"] == {"env": "prod"}
        assert d["did"] == "did:aumos:agent-xyz"
        assert d["active"] is True
        assert "registered_at" in d
        assert "updated_at" in d


# ---------------------------------------------------------------------------
# AgentAlreadyRegisteredError / AgentNotFoundError
# ---------------------------------------------------------------------------


class TestErrors:
    def test_already_registered_is_value_error(self) -> None:
        with pytest.raises(ValueError):
            raise AgentAlreadyRegisteredError("agent-001")

    def test_not_found_is_key_error(self) -> None:
        with pytest.raises(KeyError):
            raise AgentNotFoundError("agent-001")

    def test_already_registered_message_contains_agent_id(self) -> None:
        err = AgentAlreadyRegisteredError("agent-001")
        assert "agent-001" in str(err)

    def test_not_found_message_contains_agent_id(self) -> None:
        err = AgentNotFoundError("agent-001")
        assert "agent-001" in str(err)


# ---------------------------------------------------------------------------
# IdentityRegistry — register
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_returns_correct_record(self, registry: IdentityRegistry) -> None:
        record = _register(registry)
        assert record.agent_id == "agent-001"
        assert record.display_name == "Test Agent"
        assert record.organization == "TestOrg"
        assert record.active is True

    def test_register_sets_registered_at_to_utc_now(
        self, registry: IdentityRegistry
    ) -> None:
        before = datetime.datetime.now(datetime.timezone.utc)
        record = _register(registry)
        after = datetime.datetime.now(datetime.timezone.utc)
        assert before <= record.registered_at <= after

    def test_register_with_capabilities(self, registry: IdentityRegistry) -> None:
        record = _register(registry, capabilities=["read", "write"])
        assert "read" in record.capabilities
        assert "write" in record.capabilities

    def test_register_with_metadata(self, registry: IdentityRegistry) -> None:
        record = _register(registry, metadata={"env": "prod"})
        assert record.metadata["env"] == "prod"

    def test_register_with_did(self, registry: IdentityRegistry) -> None:
        record = _register(registry, did="did:aumos:agent-001")
        assert record.did == "did:aumos:agent-001"

    def test_register_duplicate_raises_already_registered(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry)
        with pytest.raises(AgentAlreadyRegisteredError):
            _register(registry)

    def test_register_adds_to_registry(self, registry: IdentityRegistry) -> None:
        _register(registry)
        assert "agent-001" in registry

    def test_len_increases_after_register(self, registry: IdentityRegistry) -> None:
        assert len(registry) == 0
        _register(registry)
        assert len(registry) == 1


# ---------------------------------------------------------------------------
# IdentityRegistry — get
# ---------------------------------------------------------------------------


class TestGet:
    def test_get_returns_registered_agent(self, registry: IdentityRegistry) -> None:
        _register(registry)
        record = registry.get("agent-001")
        assert record.agent_id == "agent-001"

    def test_get_unknown_agent_raises_not_found(
        self, registry: IdentityRegistry
    ) -> None:
        with pytest.raises(AgentNotFoundError):
            registry.get("nobody")


# ---------------------------------------------------------------------------
# IdentityRegistry — update
# ---------------------------------------------------------------------------


class TestUpdate:
    def test_update_display_name(self, registry: IdentityRegistry) -> None:
        _register(registry)
        record = registry.update("agent-001", display_name="Updated Name")
        assert record.display_name == "Updated Name"

    def test_update_organization(self, registry: IdentityRegistry) -> None:
        _register(registry)
        record = registry.update("agent-001", organization="NewOrg")
        assert record.organization == "NewOrg"

    def test_update_capabilities_replaces_list(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry, capabilities=["read"])
        record = registry.update("agent-001", capabilities=["write", "execute"])
        assert record.capabilities == ["write", "execute"]

    def test_update_metadata_replaces_dict(self, registry: IdentityRegistry) -> None:
        _register(registry, metadata={"old": "value"})
        record = registry.update("agent-001", metadata={"new": "data"})
        assert record.metadata == {"new": "data"}
        assert "old" not in record.metadata

    def test_update_did(self, registry: IdentityRegistry) -> None:
        _register(registry)
        record = registry.update("agent-001", did="did:aumos:agent-001")
        assert record.did == "did:aumos:agent-001"

    def test_update_sets_updated_at(self, registry: IdentityRegistry) -> None:
        _register(registry)
        before = datetime.datetime.now(datetime.timezone.utc)
        record = registry.update("agent-001", display_name="Changed")
        after = datetime.datetime.now(datetime.timezone.utc)
        assert before <= record.updated_at <= after

    def test_update_none_fields_not_changed(self, registry: IdentityRegistry) -> None:
        _register(registry, display_name="Original")
        registry.update("agent-001")  # no fields provided
        record = registry.get("agent-001")
        assert record.display_name == "Original"

    def test_update_unknown_agent_raises_not_found(
        self, registry: IdentityRegistry
    ) -> None:
        with pytest.raises(AgentNotFoundError):
            registry.update("nobody", display_name="X")


# ---------------------------------------------------------------------------
# IdentityRegistry — deregister
# ---------------------------------------------------------------------------


class TestDeregister:
    def test_deregister_marks_inactive(self, registry: IdentityRegistry) -> None:
        _register(registry)
        registry.deregister("agent-001")
        record = registry.get("agent-001")
        assert record.active is False

    def test_deregister_retains_record(self, registry: IdentityRegistry) -> None:
        _register(registry)
        registry.deregister("agent-001")
        assert len(registry) == 1

    def test_deregister_sets_updated_at(self, registry: IdentityRegistry) -> None:
        _register(registry)
        before = datetime.datetime.now(datetime.timezone.utc)
        registry.deregister("agent-001")
        record = registry.get("agent-001")
        after = datetime.datetime.now(datetime.timezone.utc)
        assert before <= record.updated_at <= after

    def test_deregister_unknown_raises_not_found(
        self, registry: IdentityRegistry
    ) -> None:
        with pytest.raises(AgentNotFoundError):
            registry.deregister("nobody")


# ---------------------------------------------------------------------------
# IdentityRegistry — list_all
# ---------------------------------------------------------------------------


class TestListAll:
    def test_list_all_empty_registry(self, registry: IdentityRegistry) -> None:
        assert registry.list_all() == []

    def test_list_all_excludes_inactive_by_default(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry, agent_id="agent-001")
        _register(registry, agent_id="agent-002")
        registry.deregister("agent-001")
        active = registry.list_all()
        ids = [r.agent_id for r in active]
        assert "agent-001" not in ids
        assert "agent-002" in ids

    def test_list_all_include_inactive(self, registry: IdentityRegistry) -> None:
        _register(registry, agent_id="agent-001")
        registry.deregister("agent-001")
        all_records = registry.list_all(include_inactive=True)
        assert len(all_records) == 1

    def test_list_all_sorted_by_agent_id(self, registry: IdentityRegistry) -> None:
        _register(registry, agent_id="zzz")
        _register(registry, agent_id="aaa")
        records = registry.list_all()
        ids = [r.agent_id for r in records]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# IdentityRegistry — search
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_no_criteria_returns_all_active(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry, agent_id="agent-001")
        _register(registry, agent_id="agent-002")
        results = registry.search()
        assert len(results) == 2

    def test_search_by_query_matches_agent_id(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry, agent_id="analytics-engine")
        _register(registry, agent_id="chatbot-v1")
        results = registry.search(query="analytics")
        assert len(results) == 1
        assert results[0].agent_id == "analytics-engine"

    def test_search_by_query_matches_display_name(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry, agent_id="agent-001", display_name="Data Crawler")
        _register(registry, agent_id="agent-002", display_name="Chat Bot")
        results = registry.search(query="Crawler")
        assert len(results) == 1
        assert results[0].agent_id == "agent-001"

    def test_search_is_case_insensitive(self, registry: IdentityRegistry) -> None:
        _register(registry, agent_id="AGENT-UPPER")
        results = registry.search(query="agent-upper")
        assert len(results) == 1

    def test_search_by_organization(self, registry: IdentityRegistry) -> None:
        _register(registry, agent_id="a1", organization="OrgA")
        _register(registry, agent_id="a2", organization="OrgB")
        results = registry.search(organization="OrgA")
        assert all(r.organization == "OrgA" for r in results)
        assert len(results) == 1

    def test_search_by_capability(self, registry: IdentityRegistry) -> None:
        _register(registry, agent_id="a1", capabilities=["read", "write"])
        _register(registry, agent_id="a2", capabilities=["execute"])
        results = registry.search(capability="write")
        assert len(results) == 1
        assert results[0].agent_id == "a1"

    def test_search_combined_filters(self, registry: IdentityRegistry) -> None:
        _register(registry, agent_id="a1", organization="OrgA", capabilities=["read"])
        _register(registry, agent_id="a2", organization="OrgA", capabilities=["write"])
        results = registry.search(organization="OrgA", capability="read")
        assert len(results) == 1
        assert results[0].agent_id == "a1"

    def test_search_empty_query_matches_all(self, registry: IdentityRegistry) -> None:
        _register(registry, agent_id="agent-001")
        _register(registry, agent_id="agent-002")
        results = registry.search(query="")
        assert len(results) == 2

    def test_search_no_match_returns_empty(self, registry: IdentityRegistry) -> None:
        _register(registry)
        results = registry.search(query="xyzzy-no-match")
        assert results == []


# ---------------------------------------------------------------------------
# IdentityRegistry — __contains__
# ---------------------------------------------------------------------------


class TestContains:
    def test_contains_true_for_registered_agent(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry)
        assert "agent-001" in registry

    def test_contains_false_for_unknown_agent(
        self, registry: IdentityRegistry
    ) -> None:
        assert "ghost" not in registry

    def test_contains_true_for_inactive_agent(
        self, registry: IdentityRegistry
    ) -> None:
        _register(registry)
        registry.deregister("agent-001")
        assert "agent-001" in registry
