"""Identity resolution — resolves agent IDs to their binding records.

:class:`BindingStore` is an in-memory registry that maps ``agent_id``
strings to :class:`~agent_identity.native.binding.IdentityBinding` records.
It acts as the commodity persistence layer; a production deployment would
replace it with a database-backed or distributed store via the plugin
registry.

:func:`resolve_binding` is a convenience function that combines a store
lookup with live verification in a single call.

Extension points
----------------
``BindingStore`` intentionally exposes a minimal interface (store /
lookup / remove / list / clear) so that a persistent backend can be
substituted without changing call sites.  The interface mirrors the
pattern used by ``CertStore`` in the certificates subsystem.

Example
-------
::

    from agent_identity.native.binding import NativeIdentityBinder
    from agent_identity.native.resolver import BindingStore, resolve_binding

    store = BindingStore()
    binder = NativeIdentityBinder()
    binding = binder.bind("agent-42")
    store.store(binding)

    result = resolve_binding("agent-42", store)
    assert result.found and result.verified
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from agent_identity.native.binding import IdentityBinding, NativeIdentityBinder


@dataclass
class ResolutionResult:
    """Result of resolving and verifying an agent identity binding.

    Parameters
    ----------
    found:
        ``True`` when a binding record exists in the store for the given
        ``agent_id``.
    binding:
        The :class:`~agent_identity.native.binding.IdentityBinding` that was
        found, or ``None`` when ``found`` is ``False``.
    verified:
        ``True`` when ``found`` is ``True`` *and* the stored fingerprint
        matches the current runtime.  Always ``False`` when ``found`` is
        ``False``.
    error:
        Human-readable error message when resolution or verification fails,
        ``None`` otherwise.
    """

    found: bool
    binding: Optional[IdentityBinding] = None
    verified: bool = False
    error: Optional[str] = None


class BindingStore:
    """In-memory store for :class:`~agent_identity.native.binding.IdentityBinding` records.

    Each agent ID maps to exactly one binding.  Storing a second binding
    for the same agent ID silently replaces the previous one, which is
    consistent with a re-bind (e.g. after a process restart).

    Extension points
    ----------------
    Persistent backends (Redis, SQL, etcd) can implement the same
    ``store`` / ``lookup`` / ``remove`` / ``list_all`` / ``clear`` interface
    and be substituted at the call site without modifying consumers.
    """

    def __init__(self) -> None:
        self._bindings: dict[str, IdentityBinding] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def store(self, binding: IdentityBinding) -> None:
        """Persist a binding record, replacing any previous record for the same agent.

        Parameters
        ----------
        binding:
            The binding to store.  Uses ``binding.agent_id`` as the key.
        """
        self._bindings[binding.agent_id] = binding

    def lookup(self, agent_id: str) -> Optional[IdentityBinding]:
        """Return the binding for *agent_id*, or ``None`` if not found.

        Parameters
        ----------
        agent_id:
            The agent whose binding to retrieve.

        Returns
        -------
        IdentityBinding or None
        """
        return self._bindings.get(agent_id)

    def remove(self, agent_id: str) -> bool:
        """Remove the binding for *agent_id*.

        Parameters
        ----------
        agent_id:
            The agent whose binding to delete.

        Returns
        -------
        bool
            ``True`` when a binding existed and was removed; ``False`` when
            the agent had no stored binding.
        """
        return self._bindings.pop(agent_id, None) is not None

    def list_all(self) -> list[IdentityBinding]:
        """Return all stored bindings as a list (order is insertion order).

        Returns
        -------
        list[IdentityBinding]
            A snapshot; mutating the returned list does not affect the store.
        """
        return list(self._bindings.values())

    def clear(self) -> None:
        """Remove all bindings from the store."""
        self._bindings.clear()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """Return the number of stored bindings."""
        return len(self._bindings)

    def __contains__(self, agent_id: object) -> bool:
        """Support ``agent_id in store`` membership tests."""
        return agent_id in self._bindings


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def resolve_binding(agent_id: str, store: BindingStore) -> ResolutionResult:
    """Look up *agent_id* in *store* and verify it against the current runtime.

    This is a stateless convenience wrapper that combines :meth:`BindingStore.lookup`
    with :meth:`~agent_identity.native.binding.NativeIdentityBinder.verify`.

    Parameters
    ----------
    agent_id:
        The agent whose binding to resolve.
    store:
        The :class:`BindingStore` to search.

    Returns
    -------
    ResolutionResult
        - ``found=False, verified=False, error=<message>`` when no binding
          exists.
        - ``found=True, verified=True/False, binding=<record>`` otherwise.
          ``verified`` reflects whether the current runtime fingerprint
          matches the stored fingerprint.
    """
    binding = store.lookup(agent_id)
    if binding is None:
        return ResolutionResult(
            found=False,
            error=f"No binding found for agent_id={agent_id!r}",
        )

    binder = NativeIdentityBinder(method=binding.binding_method)
    verified = binder.verify(binding)
    return ResolutionResult(found=True, binding=binding, verified=verified)
