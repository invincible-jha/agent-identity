"""Tests for CrossOrgVerifier — E15.5."""

from __future__ import annotations

import pytest

from agent_identity.did.cross_org import (
    CrossOrgVerifier,
    TrustAnchor,
    VerificationOutcome,
)
from agent_identity.did.document import DIDDocument, VerificationMethod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_document(org: str = "acme", name: str = "invoicer") -> DIDDocument:
    did = f"did:agent:{org}:{name}"
    vm = VerificationMethod(
        id=f"{did}#key-1",
        type="Ed25519VerificationKey2020",
        controller=did,
        public_key_multibase="zFakePublicKeyForTesting",
    )
    return DIDDocument(
        id=did,
        controller=did,
        verification_method=[vm],
    )


# ---------------------------------------------------------------------------
# TrustAnchor
# ---------------------------------------------------------------------------


class TestTrustAnchor:
    def test_root_anchor_has_no_trusted_by(self) -> None:
        anchor = TrustAnchor(org="platform", display_name="Platform Org")
        assert anchor.is_root() is True
        assert anchor.trusted_by is None

    def test_delegated_anchor_has_trusted_by(self) -> None:
        anchor = TrustAnchor(
            org="partner",
            display_name="Partner Org",
            trusted_by="platform",
        )
        assert anchor.is_root() is False

    def test_to_dict_structure(self) -> None:
        anchor = TrustAnchor(org="acme", display_name="Acme Corp")
        data = anchor.to_dict()
        assert data["org"] == "acme"
        assert data["display_name"] == "Acme Corp"
        assert data["is_root"] is True
        assert data["trusted_by"] is None


# ---------------------------------------------------------------------------
# CrossOrgVerifier — anchor management
# ---------------------------------------------------------------------------


class TestAnchorManagement:
    def test_add_root_anchor(self) -> None:
        verifier = CrossOrgVerifier()
        anchor = verifier.add_root_anchor("platform", "Platform")
        assert anchor.is_root()
        assert len(verifier.list_anchors()) == 1

    def test_add_delegated_anchor(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        anchor = verifier.add_delegated_anchor("acme", "Acme Corp", trusted_by="platform")
        assert anchor.trusted_by == "platform"

    def test_delegated_anchor_unknown_trusted_by_raises(self) -> None:
        verifier = CrossOrgVerifier()
        with pytest.raises(ValueError, match="not a known trust anchor"):
            verifier.add_delegated_anchor("acme", "Acme", trusted_by="unknown")

    def test_remove_anchor(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        assert verifier.remove_anchor("platform") is True
        assert len(verifier.list_anchors()) == 0

    def test_remove_nonexistent_returns_false(self) -> None:
        verifier = CrossOrgVerifier()
        assert verifier.remove_anchor("ghost") is False


# ---------------------------------------------------------------------------
# Verification — trusted orgs
# ---------------------------------------------------------------------------


class TestVerification:
    def test_root_org_is_trusted(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        doc = _make_document(org="platform")
        outcome = verifier.verify_document(doc)
        assert outcome.trusted is True
        assert outcome.trust_path == ["platform"]

    def test_delegated_org_is_trusted(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        verifier.add_delegated_anchor("acme", "Acme Corp", trusted_by="platform")
        doc = _make_document(org="acme")
        outcome = verifier.verify_document(doc)
        assert outcome.trusted is True
        assert "acme" in outcome.trust_path
        assert "platform" in outcome.trust_path

    def test_transitive_trust_three_levels(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("root", "Root Org")
        verifier.add_delegated_anchor("mid", "Mid Org", trusted_by="root")
        verifier.add_delegated_anchor("leaf", "Leaf Org", trusted_by="mid")
        outcome = verifier.verify_did("did:agent:leaf:some-agent")
        assert outcome.trusted is True
        assert outcome.trust_path == ["leaf", "mid", "root"]

    def test_unknown_org_not_trusted(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        doc = _make_document(org="unknown-org")
        outcome = verifier.verify_document(doc)
        assert outcome.trusted is False
        assert outcome.trust_path == []

    def test_no_anchors_configured(self) -> None:
        verifier = CrossOrgVerifier()
        doc = _make_document(org="acme")
        outcome = verifier.verify_document(doc)
        assert outcome.trusted is False
        assert "No trust anchors" in outcome.reason

    def test_invalid_did_format(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        outcome = verifier.verify_did("not-a-valid-did")
        assert outcome.trusted is False
        assert "Invalid DID" in outcome.reason

    def test_outcome_org_extracted_correctly(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("acme", "Acme")
        outcome = verifier.verify_did("did:agent:acme:bot")
        assert outcome.org == "acme"
        assert outcome.did == "did:agent:acme:bot"

    def test_outcome_to_dict_structure(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("acme", "Acme")
        outcome = verifier.verify_did("did:agent:acme:bot")
        data = outcome.to_dict()
        assert "did" in data
        assert "org" in data
        assert "trusted" in data
        assert "trust_path" in data
        assert "reason" in data
        assert "verified_at" in data


# ---------------------------------------------------------------------------
# is_trusted_org and trust_path_for
# ---------------------------------------------------------------------------


class TestIsTrustedOrg:
    def test_root_org_trusted(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        assert verifier.is_trusted_org("platform") is True

    def test_unknown_org_not_trusted(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("platform", "Platform")
        assert verifier.is_trusted_org("stranger") is False

    def test_trust_path_for_returns_correct_chain(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("root", "Root")
        verifier.add_delegated_anchor("child", "Child", trusted_by="root")
        path = verifier.trust_path_for("child")
        assert path == ["child", "root"]

    def test_trust_path_for_unknown_returns_empty(self) -> None:
        verifier = CrossOrgVerifier()
        verifier.add_root_anchor("root", "Root")
        assert verifier.trust_path_for("nobody") == []
