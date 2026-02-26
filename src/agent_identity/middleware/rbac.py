"""RBACMiddleware — Role-Based Access Control for agent operations.

Defines a Role hierarchy with built-in roles (admin, operator, agent, observer)
and a permission-checking interface. Roles carry an ordered privilege level
so that higher roles subsume lower-role permissions.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import IntEnum


class PrivilegeLevel(IntEnum):
    """Ordered privilege levels corresponding to built-in roles.

    Higher values represent more privilege. Custom roles may use any integer.
    """

    OBSERVER = 0
    AGENT = 1
    OPERATOR = 2
    ADMIN = 3


@dataclass
class Role:
    """A named role with an associated privilege level and permission set.

    Parameters
    ----------
    name:
        Unique name for this role (e.g. "admin", "operator").
    privilege_level:
        Integer privilege level. Higher means more access.
    permissions:
        Explicit set of permission strings granted to this role.
    description:
        Human-readable description of the role.
    """

    name: str
    privilege_level: int
    permissions: set[str] = field(default_factory=set)
    description: str = ""

    def has_permission(self, permission: str) -> bool:
        """Return True if this role explicitly grants *permission*."""
        return permission in self.permissions


# ------------------------------------------------------------------
# Built-in roles
# ------------------------------------------------------------------

BUILTIN_ROLES: dict[str, Role] = {
    "observer": Role(
        name="observer",
        privilege_level=PrivilegeLevel.OBSERVER,
        permissions={"identity:read", "trust:read"},
        description="Read-only access to identity and trust data.",
    ),
    "agent": Role(
        name="agent",
        privilege_level=PrivilegeLevel.AGENT,
        permissions={
            "identity:read",
            "trust:read",
            "trust:record",
            "delegation:create",
            "delegation:read",
        },
        description="Standard agent permissions for self-management and delegation.",
    ),
    "operator": Role(
        name="operator",
        privilege_level=PrivilegeLevel.OPERATOR,
        permissions={
            "identity:read",
            "identity:write",
            "trust:read",
            "trust:write",
            "trust:record",
            "delegation:create",
            "delegation:read",
            "delegation:revoke",
            "certificate:read",
            "certificate:issue",
        },
        description="Operational access including certificate issuance and trust management.",
    ),
    "admin": Role(
        name="admin",
        privilege_level=PrivilegeLevel.ADMIN,
        permissions={
            "identity:read",
            "identity:write",
            "identity:delete",
            "trust:read",
            "trust:write",
            "trust:record",
            "trust:reset",
            "delegation:create",
            "delegation:read",
            "delegation:revoke",
            "certificate:read",
            "certificate:issue",
            "certificate:revoke",
            "audit:read",
            "rbac:manage",
        },
        description="Full administrative access to all identity management functions.",
    ),
}


class RBACMiddleware:
    """Role-Based Access Control middleware.

    Manages role assignments for agents and enforces permission checks.
    Built-in roles are available by default. Custom roles may be added via
    :meth:`add_role`.

    Parameters
    ----------
    allow_privilege_escalation:
        If True, an agent with a role at privilege_level N is also considered
        to have all permissions held by any lower-privilege built-in role.
        Defaults to True (i.e., admin can do everything operator can).
    """

    def __init__(self, allow_privilege_escalation: bool = True) -> None:
        self._roles: dict[str, Role] = dict(BUILTIN_ROLES)
        self._assignments: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self._allow_escalation = allow_privilege_escalation

    # ------------------------------------------------------------------
    # Role management
    # ------------------------------------------------------------------

    def add_role(self, role: Role) -> None:
        """Register a custom role.

        Parameters
        ----------
        role:
            The Role to add. Its name must be unique.

        Raises
        ------
        ValueError
            If a role with this name already exists.
        """
        with self._lock:
            if role.name in self._roles:
                raise ValueError(f"Role {role.name!r} already exists.")
            self._roles[role.name] = role

    def get_role(self, role_name: str) -> Role:
        """Return the Role object for *role_name*.

        Raises
        ------
        KeyError
            If the role does not exist.
        """
        with self._lock:
            if role_name not in self._roles:
                raise KeyError(f"Role {role_name!r} is not defined.")
            return self._roles[role_name]

    def list_roles(self) -> list[str]:
        """Return sorted list of all role names."""
        with self._lock:
            return sorted(self._roles.keys())

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------

    def assign_role(self, agent_id: str, role_name: str) -> None:
        """Assign a role to an agent.

        Parameters
        ----------
        agent_id:
            The agent to assign the role to.
        role_name:
            The name of the role to assign. Must exist.

        Raises
        ------
        KeyError
            If the role does not exist.
        """
        with self._lock:
            if role_name not in self._roles:
                raise KeyError(f"Role {role_name!r} is not defined.")
            self._assignments.setdefault(agent_id, set()).add(role_name)

    def revoke_role(self, agent_id: str, role_name: str) -> None:
        """Remove a role from an agent.

        Parameters
        ----------
        agent_id:
            The agent to remove the role from.
        role_name:
            The role name to revoke. No-op if not assigned.
        """
        with self._lock:
            if agent_id in self._assignments:
                self._assignments[agent_id].discard(role_name)

    def get_agent_roles(self, agent_id: str) -> list[str]:
        """Return sorted list of role names assigned to an agent."""
        with self._lock:
            return sorted(self._assignments.get(agent_id, set()))

    # ------------------------------------------------------------------
    # Permission checking
    # ------------------------------------------------------------------

    def check_permission(self, agent_id: str, permission: str) -> bool:
        """Return True if an agent holds the given permission.

        Checks all assigned roles. If ``allow_privilege_escalation`` is True,
        permissions from lower-privilege built-in roles are also considered for
        any role whose privilege_level is equal or higher.

        Parameters
        ----------
        agent_id:
            The agent to check.
        permission:
            The permission string to verify (e.g. "certificate:issue").

        Returns
        -------
        bool
        """
        with self._lock:
            role_names = set(self._assignments.get(agent_id, set()))
            roles = [self._roles[n] for n in role_names if n in self._roles]

        if not roles:
            return False

        for role in roles:
            if role.has_permission(permission):
                return True

            if self._allow_escalation:
                max_level = role.privilege_level
                with self._lock:
                    all_roles = list(self._roles.values())
                for other in all_roles:
                    if other.privilege_level <= max_level and other.has_permission(permission):
                        return True

        return False

    def require_permission(self, agent_id: str, permission: str) -> None:
        """Raise PermissionError if the agent does not hold the permission.

        Parameters
        ----------
        agent_id:
            The agent to check.
        permission:
            The permission string required.

        Raises
        ------
        PermissionError
            If the agent does not hold the permission.
        """
        if not self.check_permission(agent_id, permission):
            raise PermissionError(
                f"Agent {agent_id!r} does not have permission {permission!r}."
            )
