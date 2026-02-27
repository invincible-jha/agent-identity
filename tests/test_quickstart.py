"""Test that the 3-line quickstart API works for agent-identity."""
from __future__ import annotations


def test_quickstart_import() -> None:
    from agent_identity import Identity

    identity = Identity.create("test-agent", owner="test-org")
    assert identity is not None


def test_quickstart_create_has_agent_id() -> None:
    from agent_identity import Identity

    identity = Identity.create("research-agent", owner="ai-team")
    assert isinstance(identity.agent_id, str)
    assert "research-agent" in identity.agent_id


def test_quickstart_record_accessible() -> None:
    from agent_identity import Identity
    from agent_identity.registry.identity_registry import AgentIdentityRecord

    identity = Identity.create("doc-agent", owner="nlp-org")
    assert isinstance(identity.record, AgentIdentityRecord)
    assert identity.record.display_name == "doc-agent"
    assert identity.record.organization == "nlp-org"


def test_quickstart_with_capabilities() -> None:
    from agent_identity import Identity

    identity = Identity.create("ml-agent", owner="ml-team", capabilities=["nlp", "vision"])
    assert "nlp" in identity.record.capabilities
    assert "vision" in identity.record.capabilities


def test_quickstart_repr() -> None:
    from agent_identity import Identity

    identity = Identity.create("repr-agent", owner="test")
    text = repr(identity)
    assert "Identity" in text
    assert "repr-agent" in text


def test_quickstart_multiple_identities() -> None:
    from agent_identity import Identity

    id1 = Identity.create("agent-a", owner="org-a")
    id2 = Identity.create("agent-b", owner="org-b")
    assert id1.agent_id != id2.agent_id
