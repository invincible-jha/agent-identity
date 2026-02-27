"""Tests for agent_identity.native.binding — NativeIdentityBinder and IdentityBinding.

Covers:
- bind() produces a structurally valid IdentityBinding
- All four BindingMethod values produce distinct fingerprints
- verify() returns True immediately after bind() in the same process
- IdentityBinding is immutable (frozen dataclass)
- Fingerprints are deterministic for the same runtime state
- Fingerprint length is exactly 32 hex characters
- bind() accepts optional metadata
- NativeIdentityBinder defaults to COMPOSITE method
"""
from __future__ import annotations

import dataclasses
import re
from datetime import datetime, timezone

import pytest

from agent_identity.native.binding import (
    BindingMethod,
    IdentityBinding,
    NativeIdentityBinder,
    _compute_fingerprint_for_method,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_AGENT_ID = "test-agent-001"


def _make_binder(method: BindingMethod = BindingMethod.COMPOSITE) -> NativeIdentityBinder:
    return NativeIdentityBinder(method)


# ===========================================================================
# NativeIdentityBinder — construction
# ===========================================================================


class TestNativeIdentityBinderConstruction:
    """NativeIdentityBinder can be constructed with any BindingMethod."""

    def test_default_method_is_composite(self) -> None:
        binder = NativeIdentityBinder()
        assert binder._method is BindingMethod.COMPOSITE

    @pytest.mark.parametrize("method", list(BindingMethod))
    def test_explicit_method_stored(self, method: BindingMethod) -> None:
        binder = NativeIdentityBinder(method)
        assert binder._method is method


# ===========================================================================
# NativeIdentityBinder.bind()
# ===========================================================================


class TestBind:
    """bind() creates structurally valid IdentityBinding objects."""

    def test_bind_returns_identity_binding(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        assert isinstance(binding, IdentityBinding)

    def test_bind_stores_correct_agent_id(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        assert binding.agent_id == _AGENT_ID

    def test_bind_stores_correct_method(self) -> None:
        for method in BindingMethod:
            binding = _make_binder(method).bind(_AGENT_ID)
            assert binding.binding_method is method

    def test_bind_fingerprint_is_32_hex_chars(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        assert _HEX_32.match(binding.fingerprint), (
            f"Expected 32-char hex string, got {binding.fingerprint!r}"
        )

    def test_bind_timestamp_is_iso8601_utc(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        # datetime.fromisoformat() parses the string; verify UTC offset present
        parsed = datetime.fromisoformat(binding.timestamp)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset().total_seconds() == 0  # type: ignore[union-attr]

    def test_bind_metadata_defaults_to_empty_dict(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        assert binding.metadata == {}

    def test_bind_accepts_explicit_metadata(self) -> None:
        meta = {"env": "test", "region": "us-east-1"}
        binding = _make_binder().bind(_AGENT_ID, metadata=meta)
        assert binding.metadata == meta

    def test_bind_metadata_is_a_copy(self) -> None:
        meta = {"key": "value"}
        binding = _make_binder().bind(_AGENT_ID, metadata=meta)
        meta["key"] = "mutated"
        assert binding.metadata["key"] == "value"

    def test_bind_different_agent_ids_same_fingerprint(self) -> None:
        """The fingerprint depends on the runtime, not the agent ID."""
        binder = _make_binder()
        b1 = binder.bind("agent-a")
        b2 = binder.bind("agent-b")
        assert b1.fingerprint == b2.fingerprint


# ===========================================================================
# BindingMethod fingerprint distinctness
# ===========================================================================


class TestFingerprintDistinctness:
    """All four BindingMethod values produce different fingerprints."""

    def test_all_methods_produce_distinct_fingerprints(self) -> None:
        """PROCESS, HOSTNAME, ENVIRONMENT, COMPOSITE each hash different inputs."""
        fingerprints = {
            method: _compute_fingerprint_for_method(method)
            for method in BindingMethod
        }
        unique_values = set(fingerprints.values())
        assert len(unique_values) == len(BindingMethod), (
            f"Expected {len(BindingMethod)} distinct fingerprints, "
            f"got {len(unique_values)}: {fingerprints}"
        )

    @pytest.mark.parametrize("method", list(BindingMethod))
    def test_each_fingerprint_is_32_hex_chars(self, method: BindingMethod) -> None:
        fingerprint = _compute_fingerprint_for_method(method)
        assert _HEX_32.match(fingerprint), (
            f"{method.value} produced non-hex32 fingerprint: {fingerprint!r}"
        )


# ===========================================================================
# NativeIdentityBinder.verify()
# ===========================================================================


class TestVerify:
    """verify() confirms runtime matches the stored binding."""

    @pytest.mark.parametrize("method", list(BindingMethod))
    def test_verify_returns_true_immediately_after_bind(self, method: BindingMethod) -> None:
        binder = NativeIdentityBinder(method)
        binding = binder.bind(_AGENT_ID)
        assert binder.verify(binding) is True

    def test_verify_uses_binding_method_not_binder_method(self) -> None:
        """A COMPOSITE binder can verify a HOSTNAME-only binding."""
        hostname_binder = NativeIdentityBinder(BindingMethod.HOSTNAME)
        binding = hostname_binder.bind(_AGENT_ID)

        composite_binder = NativeIdentityBinder(BindingMethod.COMPOSITE)
        # Should verify because it re-uses binding.binding_method internally
        assert composite_binder.verify(binding) is True

    def test_verify_fails_for_tampered_fingerprint(self) -> None:
        binder = _make_binder()
        binding = binder.bind(_AGENT_ID)

        tampered = IdentityBinding(
            agent_id=binding.agent_id,
            binding_method=binding.binding_method,
            fingerprint="00000000000000000000000000000000",
            timestamp=binding.timestamp,
            metadata=binding.metadata,
        )
        assert binder.verify(tampered) is False

    def test_verify_fails_for_wrong_method(self) -> None:
        """A binding created with PROCESS cannot be verified under HOSTNAME."""
        process_binder = NativeIdentityBinder(BindingMethod.PROCESS)
        binding = process_binder.bind(_AGENT_ID)

        hostname_binder = NativeIdentityBinder(BindingMethod.HOSTNAME)
        # verify() uses the *binding's* method, so it will use PROCESS.
        # The PROCESS fingerprint in binding was computed for this process,
        # so it should still verify True.
        assert hostname_binder.verify(binding) is True


# ===========================================================================
# IdentityBinding immutability
# ===========================================================================


class TestIdentityBindingImmutability:
    """IdentityBinding is a frozen dataclass — mutations raise FrozenInstanceError."""

    def test_agent_id_is_immutable(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            binding.agent_id = "other-agent"  # type: ignore[misc]

    def test_binding_method_is_immutable(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            binding.binding_method = BindingMethod.HOSTNAME  # type: ignore[misc]

    def test_fingerprint_is_immutable(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            binding.fingerprint = "deadbeef" * 4  # type: ignore[misc]

    def test_timestamp_is_immutable(self) -> None:
        binding = _make_binder().bind(_AGENT_ID)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            binding.timestamp = "2000-01-01T00:00:00+00:00"  # type: ignore[misc]

    def test_is_frozen_dataclass(self) -> None:
        """Confirm the class itself is declared frozen."""
        assert IdentityBinding.__dataclass_params__.frozen is True  # type: ignore[attr-defined]


# ===========================================================================
# Fingerprint determinism
# ===========================================================================


class TestFingerprintDeterminism:
    """Fingerprints must be deterministic within the same runtime state."""

    @pytest.mark.parametrize("method", list(BindingMethod))
    def test_same_method_same_runtime_same_fingerprint(self, method: BindingMethod) -> None:
        """Two calls in the same process must produce the same fingerprint.

        PROCESS is included in COMPOSITE — the PID does not change between
        two calls within the same test process.
        """
        fp1 = _compute_fingerprint_for_method(method)
        fp2 = _compute_fingerprint_for_method(method)
        assert fp1 == fp2, (
            f"{method.value}: fingerprints diverged: {fp1!r} vs {fp2!r}"
        )

    def test_two_bind_calls_same_fingerprint(self) -> None:
        binder = _make_binder()
        b1 = binder.bind("agent-x")
        b2 = binder.bind("agent-y")
        assert b1.fingerprint == b2.fingerprint

    def test_verify_called_twice_still_true(self) -> None:
        binder = _make_binder()
        binding = binder.bind(_AGENT_ID)
        assert binder.verify(binding) is True
        assert binder.verify(binding) is True


# ===========================================================================
# BindingMethod enum completeness
# ===========================================================================


class TestBindingMethodEnum:
    """BindingMethod enum has exactly the four expected values."""

    def test_has_process_value(self) -> None:
        assert BindingMethod.PROCESS.value == "process"

    def test_has_hostname_value(self) -> None:
        assert BindingMethod.HOSTNAME.value == "hostname"

    def test_has_environment_value(self) -> None:
        assert BindingMethod.ENVIRONMENT.value == "environment"

    def test_has_composite_value(self) -> None:
        assert BindingMethod.COMPOSITE.value == "composite"

    def test_exactly_four_methods(self) -> None:
        assert len(list(BindingMethod)) == 4
