"""HTTP server mode for agent-identity.

Provides a lightweight stdlib-based HTTP API for identity management and
trust verification without requiring any additional web framework dependencies.
"""
from __future__ import annotations

from agent_identity.server.app import AgentIdentityHandler, create_server, run_server

__all__ = ["AgentIdentityHandler", "create_server", "run_server"]
