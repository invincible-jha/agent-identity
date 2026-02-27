"""Tests for Restriction — action restriction with configurable enforcement."""
from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from agent_identity.native.restriction import (
    Enforcement,
    Restriction,
    RestrictionResult,
    RestrictionViolationError,
)


# ---------------------------------------------------------------------------
# Enforcement enum
# ---------------------------------------------------------------------------


class TestEnforcement:
    def test_block_value(self) -> None:
        assert Enforcement.BLOCK.value == "block"

    def test_alert_value(self) -> None:
        assert Enforcement.ALERT.value == "alert"

    def test_log_value(self) -> None:
        assert Enforcement.LOG.value == "log"


# ---------------------------------------------------------------------------
# RestrictionViolationError
# ---------------------------------------------------------------------------


class TestRestrictionViolationError:
    def test_error_message(self) -> None:
        err = RestrictionViolationError(action="delete", reason="no deletions allowed")
        assert "delete" in str(err)
        assert "no deletions allowed" in str(err)

    def test_action_attribute(self) -> None:
        err = RestrictionViolationError(action="write", reason="read-only")
        assert err.action == "write"

    def test_reason_attribute(self) -> None:
        err = RestrictionViolationError(action="execute", reason="not permitted")
        assert err.reason == "not permitted"


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_enforcement_is_block(self) -> None:
        rest = Restriction(action="delete")
        assert rest.enforcement == Enforcement.BLOCK

    def test_custom_enforcement(self) -> None:
        rest = Restriction(action="read", enforcement=Enforcement.ALERT)
        assert rest.enforcement == Enforcement.ALERT

    def test_default_reason_empty(self) -> None:
        rest = Restriction(action="write")
        assert rest.reason == ""

    def test_with_reason(self) -> None:
        rest = Restriction(action="delete", reason="Compliance requirement")
        assert rest.reason == "Compliance requirement"

    def test_default_metadata_empty(self) -> None:
        rest = Restriction(action="write")
        assert rest.metadata == {}


# ---------------------------------------------------------------------------
# applies_to()
# ---------------------------------------------------------------------------


class TestAppliesTo:
    def test_matching_action(self) -> None:
        rest = Restriction(action="delete")
        assert rest.applies_to("delete")

    def test_non_matching_action(self) -> None:
        rest = Restriction(action="delete")
        assert not rest.applies_to("read")

    def test_wildcard_matches_any(self) -> None:
        rest = Restriction(action="*")
        assert rest.applies_to("delete")
        assert rest.applies_to("read")
        assert rest.applies_to("execute")


# ---------------------------------------------------------------------------
# evaluate() — returns RestrictionResult
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_no_match_returns_unmatched_result(self) -> None:
        rest = Restriction(action="delete")
        result = rest.evaluate("read")
        assert not result.matched
        assert result.enforcement is None
        assert not result.blocked

    def test_block_match_returns_blocked(self) -> None:
        rest = Restriction(action="delete", enforcement=Enforcement.BLOCK)
        result = rest.evaluate("delete")
        assert result.matched
        assert result.blocked
        assert result.enforcement == Enforcement.BLOCK

    def test_alert_match_not_blocked(self) -> None:
        rest = Restriction(action="delete", enforcement=Enforcement.ALERT)
        result = rest.evaluate("delete")
        assert result.matched
        assert not result.blocked
        assert result.enforcement == Enforcement.ALERT

    def test_log_match_not_blocked(self) -> None:
        rest = Restriction(action="delete", enforcement=Enforcement.LOG)
        result = rest.evaluate("delete")
        assert result.matched
        assert not result.blocked

    def test_alert_logs_warning(self) -> None:
        rest = Restriction(
            action="delete",
            enforcement=Enforcement.ALERT,
            reason="audit required",
        )
        with patch.object(
            logging.getLogger("agent_identity.native.restriction"),
            "warning",
        ) as mock_warn:
            rest.evaluate("delete")
            mock_warn.assert_called_once()

    def test_log_logs_info(self) -> None:
        rest = Restriction(
            action="read",
            enforcement=Enforcement.LOG,
            reason="tracking reads",
        )
        with patch.object(
            logging.getLogger("agent_identity.native.restriction"),
            "info",
        ) as mock_info:
            rest.evaluate("read")
            mock_info.assert_called_once()

    def test_reason_included_in_result(self) -> None:
        rest = Restriction(action="delete", reason="GDPR compliance")
        result = rest.evaluate("delete")
        assert result.reason == "GDPR compliance"


# ---------------------------------------------------------------------------
# enforce() — raises on BLOCK
# ---------------------------------------------------------------------------


class TestEnforce:
    def test_block_raises_violation_error(self) -> None:
        rest = Restriction(action="delete", reason="no deletions")
        with pytest.raises(RestrictionViolationError) as exc_info:
            rest.enforce("delete")
        assert exc_info.value.action == "delete"
        assert "no deletions" in str(exc_info.value)

    def test_alert_does_not_raise(self) -> None:
        rest = Restriction(action="delete", enforcement=Enforcement.ALERT)
        rest.enforce("delete")  # should not raise

    def test_log_does_not_raise(self) -> None:
        rest = Restriction(action="delete", enforcement=Enforcement.LOG)
        rest.enforce("delete")  # should not raise

    def test_non_matching_does_not_raise(self) -> None:
        rest = Restriction(action="delete", enforcement=Enforcement.BLOCK)
        rest.enforce("read")  # different action — should not raise


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_dict_round_trip(self) -> None:
        rest = Restriction(
            action="execute",
            enforcement=Enforcement.ALERT,
            reason="monitoring",
            metadata={"ticket": "SEC-123"},
        )
        d = rest.to_dict()
        recovered = Restriction.from_dict(d)
        assert recovered.action == rest.action
        assert recovered.enforcement == rest.enforcement
        assert recovered.reason == rest.reason
        assert recovered.metadata == rest.metadata

    def test_from_dict_defaults(self) -> None:
        d = {"action": "write"}
        rest = Restriction.from_dict(d)
        assert rest.enforcement == Enforcement.BLOCK
        assert rest.reason == ""
        assert rest.metadata == {}

    def test_to_dict_keys(self) -> None:
        rest = Restriction(action="delete")
        d = rest.to_dict()
        assert "action" in d
        assert "enforcement" in d
        assert "reason" in d
        assert "metadata" in d


# ---------------------------------------------------------------------------
# Repr
# ---------------------------------------------------------------------------


class TestRepr:
    def test_repr_contains_action(self) -> None:
        rest = Restriction(action="delete", enforcement=Enforcement.BLOCK)
        assert "delete" in repr(rest)
        assert "block" in repr(rest)
