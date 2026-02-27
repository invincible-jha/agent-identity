"""Native agent identity binding — binds agent identity to runtime environment.

A :class:`IdentityBinding` captures a SHA-256 fingerprint of observable
runtime signals (OS process ID, hostname, platform string) at the moment
``bind()`` is called. :meth:`NativeIdentityBinder.verify` recomputes the
same fingerprint and compares it to the stored value, confirming that the
current process matches the one that created the binding.

This is a commodity implementation suitable for single-host deployments.
Multi-host and hardware-backed attestation are extension points that can
be added via the plugin registry without modifying this module.

Design notes
------------
- No external dependencies — only stdlib (``hashlib``, ``os``, ``platform``).
- :class:`IdentityBinding` is a frozen dataclass; it is safe to cache and
  pass across thread boundaries without defensive copying.
- Fingerprints are truncated to 32 hex characters (128-bit) — sufficient
  for runtime correlation, not intended as a cryptographic secret.
"""
from __future__ import annotations

import hashlib
import os
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class BindingMethod(Enum):
    """Controls which runtime signals contribute to the fingerprint.

    PROCESS
        Include the OS process ID (``os.getpid()``).  Useful for isolating
        a specific process run; the binding is invalidated when the process
        restarts.
    HOSTNAME
        Include the machine hostname (``platform.node()``).  Stable across
        restarts on the same host but not across containers or VMs.
    ENVIRONMENT
        Include the platform string (``platform.platform()``).  Differentiates
        OS versions and CPU architectures on the same logical host.
    COMPOSITE
        Include all three signals.  Provides the strongest binding; any one
        signal changing (new PID, new host, new OS) will invalidate the
        binding.
    """

    PROCESS = "process"
    HOSTNAME = "hostname"
    ENVIRONMENT = "environment"
    COMPOSITE = "composite"


@dataclass(frozen=True)
class IdentityBinding:
    """A point-in-time binding between an agent identity and the runtime.

    Parameters
    ----------
    agent_id:
        The identifier of the agent whose identity is bound.
    binding_method:
        The set of runtime signals used to compute ``fingerprint``.
    fingerprint:
        32-hex-character truncated SHA-256 digest of the runtime signals.
    timestamp:
        ISO 8601 UTC timestamp of when the binding was created.
    metadata:
        Optional free-form key-value pairs (e.g. correlation IDs, labels).

    Notes
    -----
    This dataclass is frozen — all attributes are read-only after creation.
    Attempt to mutate any attribute raises :class:`dataclasses.FrozenInstanceError`.
    """

    agent_id: str
    binding_method: BindingMethod
    fingerprint: str
    timestamp: str  # ISO 8601
    metadata: dict[str, str] = field(default_factory=dict)


class NativeIdentityBinder:
    """Binds agent identity to the native runtime environment.

    Uses standard-library primitives to compute a deterministic fingerprint
    of the current runtime based on the configured :class:`BindingMethod`.

    Parameters
    ----------
    method:
        Which runtime signals to incorporate.  Defaults to
        :attr:`BindingMethod.COMPOSITE` (all signals).

    Extension points
    ----------------
    Subclasses or wrappers can override :meth:`_compute_fingerprint` to
    incorporate hardware-backed attestation tokens (TPM, HSM) for
    environments that require stronger binding guarantees.

    Examples
    --------
    ::

        binder = NativeIdentityBinder(BindingMethod.HOSTNAME)
        binding = binder.bind("agent-99")
        assert binder.verify(binding)
    """

    def __init__(self, method: BindingMethod = BindingMethod.COMPOSITE) -> None:
        self._method: BindingMethod = method

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def bind(self, agent_id: str, metadata: Optional[dict[str, str]] = None) -> IdentityBinding:
        """Create an :class:`IdentityBinding` for the given agent.

        The fingerprint is computed from the *current* runtime at the
        moment this method is called.

        Parameters
        ----------
        agent_id:
            Identifier of the agent to bind.
        metadata:
            Optional extra key-value pairs to attach to the binding record.

        Returns
        -------
        IdentityBinding
            A frozen binding record capturing the runtime fingerprint.
        """
        fingerprint = self._compute_fingerprint()
        timestamp = datetime.now(timezone.utc).isoformat()
        return IdentityBinding(
            agent_id=agent_id,
            binding_method=self._method,
            fingerprint=fingerprint,
            timestamp=timestamp,
            metadata=dict(metadata) if metadata else {},
        )

    def verify(self, binding: IdentityBinding) -> bool:
        """Verify that the current runtime matches the stored binding.

        Recomputes the fingerprint using ``binding.binding_method`` and
        compares it to ``binding.fingerprint``.

        Parameters
        ----------
        binding:
            The previously created binding to check.

        Returns
        -------
        bool
            ``True`` when the current runtime fingerprint equals the stored
            fingerprint; ``False`` otherwise.

        Notes
        -----
        A binder configured with a different ``method`` than the one stored
        in ``binding`` will use the *binding's* method for recomputation,
        ensuring correct cross-method verification.
        """
        # Use the method recorded in the binding, not self._method, so that
        # a composite binder can still verify a hostname-only binding.
        recomputed = _compute_fingerprint_for_method(binding.binding_method)
        return recomputed == binding.fingerprint

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_fingerprint(self) -> str:
        """Compute a runtime fingerprint using this binder's configured method."""
        return _compute_fingerprint_for_method(self._method)


# ---------------------------------------------------------------------------
# Module-level helper — separated so resolver.py can reuse it without
# instantiating a binder.
# ---------------------------------------------------------------------------

def _compute_fingerprint_for_method(method: BindingMethod) -> str:
    """Compute a 32-hex-character fingerprint for the given binding method.

    Parameters
    ----------
    method:
        The binding method controlling which signals are included.

    Returns
    -------
    str
        First 32 hex characters of the SHA-256 digest of the combined
        runtime signals, joined with ``"|"`` separators.
    """
    parts: list[str] = []

    if method in (BindingMethod.PROCESS, BindingMethod.COMPOSITE):
        parts.append(f"pid:{os.getpid()}")

    if method in (BindingMethod.HOSTNAME, BindingMethod.COMPOSITE):
        parts.append(f"host:{platform.node()}")

    if method in (BindingMethod.ENVIRONMENT, BindingMethod.COMPOSITE):
        parts.append(f"platform:{platform.platform()}")

    combined = "|".join(parts)
    return hashlib.sha256(combined.encode()).hexdigest()[:32]
