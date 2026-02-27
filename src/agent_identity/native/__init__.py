"""native — Native agent identity binding to runtime environment.

Binds an agent identity to observable properties of the host runtime
(process ID, hostname, platform string) so that a binding issued on one
host cannot be trivially replayed on another.

Public API
----------
``NativeIdentityBinder``
    Creates and verifies :class:`IdentityBinding` objects for a given agent.
``IdentityBinding``
    Frozen dataclass representing a point-in-time runtime binding.
``BindingMethod``
    Enum controlling which runtime signals are included in the fingerprint.
``resolve_binding``
    Convenience function: look up a binding in a :class:`BindingStore` and
    verify it against the current runtime.

Extension points
----------------
The fingerprint computation in :class:`NativeIdentityBinder` deliberately
uses only standard-library primitives (``hashlib``, ``os``, ``platform``).
Hardware-backed attestation (TPM, HSM) can be layered on top via the
plugin registry without changing this module's public interface.

Example
-------
::

    from agent_identity.native import NativeIdentityBinder, BindingMethod

    binder = NativeIdentityBinder(BindingMethod.COMPOSITE)
    binding = binder.bind("agent-42")
    assert binder.verify(binding)
"""
from __future__ import annotations

from agent_identity.native.binding import BindingMethod, IdentityBinding, NativeIdentityBinder
from agent_identity.native.resolver import BindingStore, ResolutionResult, resolve_binding

__all__ = [
    "BindingMethod",
    "BindingStore",
    "IdentityBinding",
    "NativeIdentityBinder",
    "ResolutionResult",
    "resolve_binding",
]
