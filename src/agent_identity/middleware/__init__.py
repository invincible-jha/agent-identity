"""Identity middleware — authentication, authorization, and audit logging.

Provides three independent middleware components:

- :class:`AuthMiddleware` — bearer token, certificate, and delegation token auth
- :class:`RBACMiddleware` — role-based permission checking
- :class:`IdentityAuditLogger` — append-only JSONL audit trail

Quick start
-----------
::

    from agent_identity.middleware import AuthMiddleware, RBACMiddleware, IdentityAuditLogger

    auth = AuthMiddleware(bearer_token_store={"secret-token": "agent-001"})
    result = auth.authenticate_bearer("secret-token")
    assert result.success

    rbac = RBACMiddleware()
    rbac.assign_role("agent-001", "operator")
    rbac.require_permission("agent-001", "certificate:issue")

    audit = IdentityAuditLogger()
    audit.log_registration("agent-001")
"""
from __future__ import annotations

from agent_identity.middleware.audit import AuditEvent, IdentityAuditLogger
from agent_identity.middleware.auth import AuthMechanism, AuthMiddleware, AuthResult
from agent_identity.middleware.rbac import BUILTIN_ROLES, PrivilegeLevel, RBACMiddleware, Role

__all__ = [
    "AuditEvent",
    "AuthMechanism",
    "AuthMiddleware",
    "AuthResult",
    "BUILTIN_ROLES",
    "IdentityAuditLogger",
    "PrivilegeLevel",
    "RBACMiddleware",
    "Role",
]
