"""Tests for agent_identity.middleware.rbac — RBACMiddleware."""
from __future__ import annotations

import pytest

from agent_identity.middleware.rbac import (
    BUILTIN_ROLES,
    PrivilegeLevel,
    RBACMiddleware,
    Role,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def rbac() -> RBACMiddleware:
    return RBACMiddleware()


@pytest.fixture()
def rbac_no_escalation() -> RBACMiddleware:
    return RBACMiddleware(allow_privilege_escalation=False)


@pytest.fixture()
def custom_role() -> Role:
    return Role(
        name="analyst",
        privilege_level=5,
        permissions={"report:read", "report:generate"},
        description="Analyst role.",
    )


# ---------------------------------------------------------------------------
# PrivilegeLevel enum
# ---------------------------------------------------------------------------


class TestPrivilegeLevel:
    def test_ordering(self) -> None:
        assert PrivilegeLevel.OBSERVER < PrivilegeLevel.AGENT
        assert PrivilegeLevel.AGENT < PrivilegeLevel.OPERATOR
        assert PrivilegeLevel.OPERATOR < PrivilegeLevel.ADMIN

    def test_values(self) -> None:
        assert PrivilegeLevel.OBSERVER == 0
        assert PrivilegeLevel.AGENT == 1
        assert PrivilegeLevel.OPERATOR == 2
        assert PrivilegeLevel.ADMIN == 3


# ---------------------------------------------------------------------------
# Role dataclass
# ---------------------------------------------------------------------------


class TestRole:
    def test_has_permission_true(self) -> None:
        role = Role(name="tester", privilege_level=1, permissions={"read"})
        assert role.has_permission("read") is True

    def test_has_permission_false(self) -> None:
        role = Role(name="tester", privilege_level=1, permissions={"read"})
        assert role.has_permission("write") is False

    def test_empty_permissions(self) -> None:
        role = Role(name="empty", privilege_level=0)
        assert role.has_permission("any") is False


# ---------------------------------------------------------------------------
# Built-in roles sanity checks
# ---------------------------------------------------------------------------


class TestBuiltinRoles:
    def test_builtin_role_names_present(self) -> None:
        for name in ("observer", "agent", "operator", "admin"):
            assert name in BUILTIN_ROLES

    def test_admin_has_identity_delete(self) -> None:
        assert "identity:delete" in BUILTIN_ROLES["admin"].permissions

    def test_observer_has_only_read_permissions(self) -> None:
        observer = BUILTIN_ROLES["observer"]
        assert all("read" in p for p in observer.permissions)

    def test_operator_can_issue_certs(self) -> None:
        assert "certificate:issue" in BUILTIN_ROLES["operator"].permissions


# ---------------------------------------------------------------------------
# RBACMiddleware — role management
# ---------------------------------------------------------------------------


class TestRoleManagement:
    def test_builtin_roles_available_by_default(self, rbac: RBACMiddleware) -> None:
        role_names = rbac.list_roles()
        for name in ("observer", "agent", "operator", "admin"):
            assert name in role_names

    def test_add_custom_role(
        self, rbac: RBACMiddleware, custom_role: Role
    ) -> None:
        rbac.add_role(custom_role)
        assert "analyst" in rbac.list_roles()

    def test_add_duplicate_role_raises(
        self, rbac: RBACMiddleware, custom_role: Role
    ) -> None:
        rbac.add_role(custom_role)
        with pytest.raises(ValueError, match="already exists"):
            rbac.add_role(custom_role)

    def test_get_existing_role(self, rbac: RBACMiddleware) -> None:
        role = rbac.get_role("admin")
        assert role.name == "admin"

    def test_get_unknown_role_raises_key_error(self, rbac: RBACMiddleware) -> None:
        with pytest.raises(KeyError):
            rbac.get_role("nonexistent-role")

    def test_list_roles_is_sorted(self, rbac: RBACMiddleware) -> None:
        roles = rbac.list_roles()
        assert roles == sorted(roles)


# ---------------------------------------------------------------------------
# RBACMiddleware — assignment
# ---------------------------------------------------------------------------


class TestRoleAssignment:
    def test_assign_role_to_agent(self, rbac: RBACMiddleware) -> None:
        rbac.assign_role("agent-001", "observer")
        assert "observer" in rbac.get_agent_roles("agent-001")

    def test_assign_multiple_roles(self, rbac: RBACMiddleware) -> None:
        rbac.assign_role("agent-001", "observer")
        rbac.assign_role("agent-001", "agent")
        roles = rbac.get_agent_roles("agent-001")
        assert "observer" in roles
        assert "agent" in roles

    def test_assign_unknown_role_raises(self, rbac: RBACMiddleware) -> None:
        with pytest.raises(KeyError):
            rbac.assign_role("agent-001", "ghost-role")

    def test_revoke_role_from_agent(self, rbac: RBACMiddleware) -> None:
        rbac.assign_role("agent-001", "agent")
        rbac.revoke_role("agent-001", "agent")
        assert "agent" not in rbac.get_agent_roles("agent-001")

    def test_revoke_unassigned_role_is_noop(self, rbac: RBACMiddleware) -> None:
        rbac.revoke_role("agent-001", "observer")  # must not raise

    def test_get_agent_roles_empty_for_unknown_agent(
        self, rbac: RBACMiddleware
    ) -> None:
        assert rbac.get_agent_roles("nobody") == []

    def test_get_agent_roles_is_sorted(self, rbac: RBACMiddleware) -> None:
        rbac.assign_role("agent-001", "operator")
        rbac.assign_role("agent-001", "agent")
        roles = rbac.get_agent_roles("agent-001")
        assert roles == sorted(roles)


# ---------------------------------------------------------------------------
# RBACMiddleware — check_permission
# ---------------------------------------------------------------------------


class TestCheckPermission:
    def test_agent_with_no_roles_has_no_permissions(
        self, rbac: RBACMiddleware
    ) -> None:
        assert rbac.check_permission("agent-001", "identity:read") is False

    def test_observer_can_read_identity(self, rbac: RBACMiddleware) -> None:
        rbac.assign_role("agent-001", "observer")
        assert rbac.check_permission("agent-001", "identity:read") is True

    def test_observer_cannot_write_identity(self, rbac: RBACMiddleware) -> None:
        rbac.assign_role("agent-001", "observer")
        assert rbac.check_permission("agent-001", "identity:write") is False

    def test_admin_has_all_permissions_with_escalation(
        self, rbac: RBACMiddleware
    ) -> None:
        rbac.assign_role("agent-001", "admin")
        # Admin should hold every permission defined in any lower-privilege role
        assert rbac.check_permission("agent-001", "trust:read") is True
        assert rbac.check_permission("agent-001", "identity:delete") is True
        assert rbac.check_permission("agent-001", "rbac:manage") is True

    def test_operator_inherits_observer_permissions_via_escalation(
        self, rbac: RBACMiddleware
    ) -> None:
        rbac.assign_role("agent-001", "operator")
        assert rbac.check_permission("agent-001", "identity:read") is True

    def test_no_escalation_does_not_inherit_lower_role_perms(
        self, rbac_no_escalation: RBACMiddleware
    ) -> None:
        # With escalation disabled, operator should only have its explicit permissions
        rbac_no_escalation.assign_role("agent-001", "operator")
        # "identity:read" IS in operator's own permissions, so this should still be True
        assert rbac_no_escalation.check_permission("agent-001", "identity:read") is True

    def test_no_escalation_restricts_permissions(
        self, rbac_no_escalation: RBACMiddleware
    ) -> None:
        rbac_no_escalation.assign_role("agent-001", "agent")
        # "identity:write" is not in agent's explicit permissions
        assert rbac_no_escalation.check_permission("agent-001", "identity:write") is False

    def test_custom_role_with_unique_permission(
        self, rbac_no_escalation: RBACMiddleware, custom_role: Role
    ) -> None:
        # Use no-escalation middleware: custom role only grants its own permissions
        rbac_no_escalation.add_role(custom_role)
        rbac_no_escalation.assign_role("agent-001", "analyst")
        assert rbac_no_escalation.check_permission("agent-001", "report:read") is True
        # "identity:delete" is not in analyst's own permissions
        assert rbac_no_escalation.check_permission("agent-001", "identity:delete") is False


# ---------------------------------------------------------------------------
# RBACMiddleware — require_permission
# ---------------------------------------------------------------------------


class TestRequirePermission:
    def test_require_permission_passes_when_held(
        self, rbac: RBACMiddleware
    ) -> None:
        rbac.assign_role("agent-001", "admin")
        rbac.require_permission("agent-001", "identity:delete")  # must not raise

    def test_require_permission_raises_when_not_held(
        self, rbac: RBACMiddleware
    ) -> None:
        rbac.assign_role("agent-001", "observer")
        with pytest.raises(PermissionError, match="does not have permission"):
            rbac.require_permission("agent-001", "identity:write")

    def test_require_permission_error_message_contains_agent_and_perm(
        self, rbac: RBACMiddleware
    ) -> None:
        try:
            rbac.require_permission("agent-xyz", "secret:access")
        except PermissionError as exc:
            assert "agent-xyz" in str(exc)
            assert "secret:access" in str(exc)
