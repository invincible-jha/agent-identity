#!/usr/bin/env python3
"""Example: RBAC Middleware

Demonstrates using RBACMiddleware and AuthMiddleware to enforce
role-based access control on agent actions.

Usage:
    python examples/04_rbac_middleware.py

Requirements:
    pip install agent-identity
"""
from __future__ import annotations

import agent_identity
from agent_identity import (
    RBACMiddleware,
    AuthMiddleware,
    AuthMechanism,
    AuthResult,
    Role,
    BUILTIN_ROLES,
    PrivilegeLevel,
    IdentityAuditLogger,
    AuditEvent,
)


def main() -> None:
    print(f"agent-identity version: {agent_identity.__version__}")

    # Step 1: Show built-in roles
    print("Built-in roles:")
    for role_name, role in list(BUILTIN_ROLES.items())[:3]:
        print(f"  [{role_name}] level={role.privilege_level.value} permissions={role.permissions[:3]}")

    # Step 2: Create RBAC middleware
    rbac = RBACMiddleware()
    rbac.assign_role("agent-alpha", "operator")
    rbac.assign_role("agent-beta", "viewer")
    rbac.assign_role("agent-gamma", "admin")
    print(f"\nRBAC middleware: roles assigned to 3 agents.")

    # Step 3: Check permissions
    test_cases: list[tuple[str, str]] = [
        ("agent-alpha", "write"),
        ("agent-beta", "write"),
        ("agent-gamma", "delete"),
        ("agent-alpha", "delete"),
        ("agent-beta", "read"),
    ]

    print("\nPermission checks:")
    for agent_id, permission in test_cases:
        allowed = rbac.check_permission(agent_id=agent_id, permission=permission)
        role = rbac.get_role(agent_id)
        status = "ALLOWED" if allowed else "DENIED"
        print(f"  [{status}] {agent_id} ({role.name if role else 'no-role'}) -> {permission}")

    # Step 4: Auth middleware
    auth = AuthMiddleware(mechanism=AuthMechanism.API_KEY)
    token = auth.issue_token(agent_id="agent-alpha", scope=["read", "write"])
    print(f"\nToken issued for agent-alpha: {token.token[:16]}...")

    auth_result = auth.verify(token.token)
    print(f"Token valid: {auth_result.is_valid} | scope={auth_result.scope}")

    # Step 5: Audit logger
    audit_logger = IdentityAuditLogger()
    event = AuditEvent(
        agent_id="agent-beta",
        action="attempted write access",
        outcome="denied",
        reason="Insufficient privileges",
    )
    audit_logger.log(event)
    print(f"\nAudit events logged: {audit_logger.count()}")


if __name__ == "__main__":
    main()
