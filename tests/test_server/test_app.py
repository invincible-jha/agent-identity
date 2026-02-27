"""Tests for agent_identity.server.app — HTTP handler integration."""
from __future__ import annotations

from http.server import HTTPServer

import pytest

from agent_identity.server import routes
from agent_identity.server.app import AgentIdentityHandler, create_server


@pytest.fixture(autouse=True)
def reset_server_state() -> None:
    """Reset module-level state before each test."""
    routes.reset_state()


class TestAgentIdentityHandlerHealth:
    def test_health_returns_ok(self) -> None:
        status, data = routes.handle_health()
        assert status == 200
        assert data["status"] == "ok"

    def test_health_service_name(self) -> None:
        status, data = routes.handle_health()
        assert data["service"] == "agent-identity"

    def test_health_reports_zero_count_initially(self) -> None:
        status, data = routes.handle_health()
        assert data["identity_count"] == 0


class TestAgentIdentityHandlerCreateIdentity:
    def test_register_new_agent(self) -> None:
        body = {
            "agent_id": "http-agent-001",
            "display_name": "HTTP Test Agent",
            "organization": "TestOrg",
        }
        status, data = routes.handle_create_identity(body)
        assert status == 201
        assert data["agent_id"] == "http-agent-001"

    def test_register_duplicate_returns_409(self) -> None:
        body = {
            "agent_id": "dup-agent",
            "display_name": "Dup",
            "organization": "Org",
        }
        routes.handle_create_identity(body)
        status, _ = routes.handle_create_identity(body)
        assert status == 409

    def test_register_increments_identity_count(self) -> None:
        for i in range(3):
            routes.handle_create_identity(
                {
                    "agent_id": f"count-agent-{i}",
                    "display_name": f"Agent {i}",
                    "organization": "AumOS",
                }
            )

        status, data = routes.handle_health()
        assert data["identity_count"] == 3


class TestAgentIdentityHandlerVerify:
    def test_verify_registered_agent(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "verify-ok",
                "display_name": "Verify OK",
                "organization": "AumOS",
                "capabilities": ["llm", "tool"],
            }
        )
        status, data = routes.handle_verify(
            {"agent_id": "verify-ok", "claimed_capabilities": ["llm"]}
        )
        assert status == 200
        assert data["verified"] is True

    def test_verify_unregistered_agent(self) -> None:
        status, data = routes.handle_verify({"agent_id": "nobody"})
        assert status == 200
        assert data["verified"] is False

    def test_verify_missing_capabilities(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "limited",
                "display_name": "Limited",
                "organization": "Org",
                "capabilities": ["read"],
            }
        )
        status, data = routes.handle_verify(
            {"agent_id": "limited", "claimed_capabilities": ["admin"]}
        )
        assert status == 200
        assert data["verified"] is False
        assert "admin" in data["missing_capabilities"]


class TestAgentIdentityHandlerTrust:
    def test_trust_score_for_registered_agent(self) -> None:
        routes.handle_create_identity(
            {
                "agent_id": "trust-ok",
                "display_name": "Trust",
                "organization": "AumOS",
            }
        )
        status, data = routes.handle_get_trust("trust-ok")
        assert status == 200
        assert "composite" in data
        assert "level" in data

    def test_trust_score_not_found(self) -> None:
        status, data = routes.handle_get_trust("ghost-agent")
        assert status == 404


class TestCreateServer:
    def test_create_server_returns_http_server(self) -> None:
        server = create_server(host="127.0.0.1", port=0)
        try:
            assert isinstance(server, HTTPServer)
        finally:
            server.server_close()

    def test_create_server_uses_correct_handler(self) -> None:
        server = create_server(host="127.0.0.1", port=0)
        try:
            assert server.RequestHandlerClass is AgentIdentityHandler
        finally:
            server.server_close()


class TestServerModels:
    def test_create_identity_request_required_fields(self) -> None:
        from agent_identity.server.models import CreateIdentityRequest

        req = CreateIdentityRequest(
            agent_id="a1",
            display_name="Agent One",
            organization="AumOS",
        )
        assert req.agent_id == "a1"
        assert req.capabilities == []

    def test_identity_response_fields(self) -> None:
        from agent_identity.server.models import IdentityResponse

        resp = IdentityResponse(
            agent_id="a1",
            display_name="Agent One",
            organization="AumOS",
            registered_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
            active=True,
        )
        assert resp.agent_id == "a1"
        assert resp.active is True

    def test_verify_response_fields(self) -> None:
        from agent_identity.server.models import VerifyResponse

        resp = VerifyResponse(
            agent_id="a1",
            verified=True,
            active=True,
            capabilities_valid=True,
        )
        assert resp.verified is True
        assert resp.missing_capabilities == []

    def test_trust_response_fields(self) -> None:
        from agent_identity.server.models import TrustResponse

        resp = TrustResponse(
            agent_id="a1",
            composite=75.0,
            level="HIGH",
            timestamp="2024-01-01T00:00:00",
        )
        assert resp.composite == 75.0

    def test_health_response_defaults(self) -> None:
        from agent_identity.server.models import HealthResponse

        resp = HealthResponse()
        assert resp.status == "ok"
        assert resp.service == "agent-identity"
