"""Tests for agent_identity.registry.did — DIDProvider."""
from __future__ import annotations

import pytest

from agent_identity.registry.did import (
    DIDDocument,
    DIDProvider,
    DIDResolutionError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def provider() -> DIDProvider:
    return DIDProvider()


@pytest.fixture()
def provider_with_agent(provider: DIDProvider) -> DIDProvider:
    provider.create_did("agent-001")
    return provider


# ---------------------------------------------------------------------------
# DIDDocument dataclass
# ---------------------------------------------------------------------------


class TestDIDDocument:
    def test_to_dict_structure(self) -> None:
        doc = DIDDocument(
            did="did:aumos:agent-001",
            agent_id="agent-001",
            controller="did:aumos:agent-001",
        )
        d = doc.to_dict()
        assert d["id"] == "did:aumos:agent-001"
        assert d["controller"] == "did:aumos:agent-001"
        assert d["agent_id"] == "agent-001"


# ---------------------------------------------------------------------------
# DIDProvider — create_did
# ---------------------------------------------------------------------------


class TestCreateDID:
    def test_creates_aumos_did(self, provider: DIDProvider) -> None:
        did = provider.create_did("agent-001")
        assert did == "did:aumos:agent-001"

    def test_did_format_includes_agent_id(self, provider: DIDProvider) -> None:
        did = provider.create_did("my-special-agent")
        assert "my-special-agent" in did
        assert did.startswith("did:aumos:")

    def test_idempotent_returns_same_did(self, provider: DIDProvider) -> None:
        did1 = provider.create_did("agent-001")
        did2 = provider.create_did("agent-001")
        assert did1 == did2

    def test_different_agents_get_different_dids(self, provider: DIDProvider) -> None:
        did1 = provider.create_did("agent-001")
        did2 = provider.create_did("agent-002")
        assert did1 != did2


# ---------------------------------------------------------------------------
# DIDProvider — resolve_did
# ---------------------------------------------------------------------------


class TestResolveDID:
    def test_resolve_returns_correct_document(
        self, provider_with_agent: DIDProvider
    ) -> None:
        doc = provider_with_agent.resolve_did("did:aumos:agent-001")
        assert doc.did == "did:aumos:agent-001"
        assert doc.agent_id == "agent-001"
        assert doc.controller == "did:aumos:agent-001"

    def test_resolve_unregistered_did_raises(self, provider: DIDProvider) -> None:
        provider.create_did("agent-001")
        with pytest.raises(DIDResolutionError, match="not registered"):
            provider.resolve_did("did:aumos:nonexistent")

    def test_resolve_malformed_did_raises(self, provider: DIDProvider) -> None:
        with pytest.raises(DIDResolutionError, match="Malformed"):
            provider.resolve_did("not-a-did")

    def test_resolve_wrong_method_raises(self, provider: DIDProvider) -> None:
        with pytest.raises(DIDResolutionError):
            provider.resolve_did("did:web:example.com")

    def test_resolve_did_controller_equals_did(
        self, provider_with_agent: DIDProvider
    ) -> None:
        doc = provider_with_agent.resolve_did("did:aumos:agent-001")
        assert doc.controller == doc.did


# ---------------------------------------------------------------------------
# DIDProvider — resolve_agent
# ---------------------------------------------------------------------------


class TestResolveAgent:
    def test_resolve_agent_returns_correct_document(
        self, provider_with_agent: DIDProvider
    ) -> None:
        doc = provider_with_agent.resolve_agent("agent-001")
        assert doc.agent_id == "agent-001"

    def test_resolve_agent_without_did_raises(self, provider: DIDProvider) -> None:
        with pytest.raises(DIDResolutionError, match="No DID registered"):
            provider.resolve_agent("nobody")


# ---------------------------------------------------------------------------
# DIDProvider — verify_did
# ---------------------------------------------------------------------------


class TestVerifyDID:
    def test_verify_correct_agent_returns_true(
        self, provider_with_agent: DIDProvider
    ) -> None:
        result = provider_with_agent.verify_did("did:aumos:agent-001", "agent-001")
        assert result is True

    def test_verify_wrong_agent_returns_false(
        self, provider_with_agent: DIDProvider
    ) -> None:
        result = provider_with_agent.verify_did("did:aumos:agent-001", "agent-002")
        assert result is False

    def test_verify_unregistered_did_returns_false(
        self, provider: DIDProvider
    ) -> None:
        result = provider.verify_did("did:aumos:ghost", "ghost")
        assert result is False

    def test_verify_malformed_did_returns_false(
        self, provider: DIDProvider
    ) -> None:
        result = provider.verify_did("bad-did-format", "agent-001")
        assert result is False


# ---------------------------------------------------------------------------
# DIDProvider — agent_id_from_did (static)
# ---------------------------------------------------------------------------


class TestAgentIdFromDID:
    def test_extracts_agent_id(self) -> None:
        agent_id = DIDProvider.agent_id_from_did("did:aumos:agent-001")
        assert agent_id == "agent-001"

    def test_extracts_complex_agent_id(self) -> None:
        agent_id = DIDProvider.agent_id_from_did("did:aumos:org/agent/sub-agent")
        assert agent_id == "org/agent/sub-agent"

    def test_malformed_did_raises(self) -> None:
        with pytest.raises(DIDResolutionError, match="Malformed"):
            DIDProvider.agent_id_from_did("not-a-valid-did")

    def test_wrong_method_raises(self) -> None:
        with pytest.raises(DIDResolutionError):
            DIDProvider.agent_id_from_did("did:ethr:agent-001")


# ---------------------------------------------------------------------------
# DIDProvider — registered_dids
# ---------------------------------------------------------------------------


class TestRegisteredDIDs:
    def test_empty_initially(self, provider: DIDProvider) -> None:
        assert provider.registered_dids() == []

    def test_returns_sorted_list(self, provider: DIDProvider) -> None:
        provider.create_did("zzz")
        provider.create_did("aaa")
        dids = provider.registered_dids()
        assert dids == sorted(dids)

    def test_contains_created_did(self, provider: DIDProvider) -> None:
        provider.create_did("agent-001")
        assert "did:aumos:agent-001" in provider.registered_dids()

    def test_idempotent_create_does_not_duplicate(
        self, provider: DIDProvider
    ) -> None:
        provider.create_did("agent-001")
        provider.create_did("agent-001")
        assert provider.registered_dids().count("did:aumos:agent-001") == 1
