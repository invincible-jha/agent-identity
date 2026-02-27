"""Tests for agent_identity.did — W3C DID Core implementation.

Covers DIDDocument, DIDRegistry, VerifiableCredential, CredentialIssuer,
DIDVerifier, VerificationResult, and the ``did`` CLI command group.

140+ tests organized by class.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_identity.cli.main import cli
from agent_identity.did.credentials import (
    CredentialIssuer,
    CredentialSubject,
    CredentialType,
    VerifiableCredential,
)
from agent_identity.did.document import (
    DID_METHOD,
    DIDDocument,
    ServiceEndpoint,
    VerificationMethod,
    _parse_did_agent,
)
from agent_identity.did.registry import (
    DIDAlreadyRegisteredError,
    DIDNotFoundError,
    DIDRegistry,
)
from agent_identity.did.verification import DIDVerifier, VerificationResult


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def registry() -> DIDRegistry:
    return DIDRegistry()


@pytest.fixture()
def issuer_doc() -> DIDDocument:
    return DIDDocument(id="did:agent:acme:issuer", controller="did:agent:acme:issuer")


@pytest.fixture()
def subject_doc() -> DIDDocument:
    return DIDDocument(id="did:agent:acme:worker", controller="did:agent:acme:worker")


@pytest.fixture()
def populated_registry(
    registry: DIDRegistry,
    issuer_doc: DIDDocument,
    subject_doc: DIDDocument,
) -> DIDRegistry:
    registry.register(issuer_doc)
    registry.register(subject_doc)
    return registry


@pytest.fixture()
def cred_issuer() -> CredentialIssuer:
    return CredentialIssuer()


@pytest.fixture()
def basic_credential(cred_issuer: CredentialIssuer) -> VerifiableCredential:
    return cred_issuer.issue(
        issuer_did="did:agent:acme:issuer",
        subject_did="did:agent:acme:worker",
        credential_type=CredentialType.CAPABILITY_CLAIM,
        claims={"capability": "data.read"},
    )


@pytest.fixture()
def verifier() -> DIDVerifier:
    return DIDVerifier()


@pytest.fixture()
def vm_key() -> VerificationMethod:
    return VerificationMethod(
        id="did:agent:acme:issuer#key-1",
        type="Ed25519VerificationKey2020",
        controller="did:agent:acme:issuer",
        public_key_multibase="z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8sisDArDJF",
    )


@pytest.fixture()
def service_ep() -> ServiceEndpoint:
    return ServiceEndpoint(
        id="did:agent:acme:issuer#messaging",
        type="AgentMessaging",
        endpoint="https://acme.example.com/agent/messaging",
    )


# ===========================================================================
# DID_METHOD constant
# ===========================================================================


class TestDIDMethodConstant:
    def test_did_method_value(self) -> None:
        assert DID_METHOD == "agent"

    def test_did_method_is_string(self) -> None:
        assert isinstance(DID_METHOD, str)


# ===========================================================================
# _parse_did_agent helper
# ===========================================================================


class TestParseDIDAgent:
    def test_parses_simple_did(self) -> None:
        org, name = _parse_did_agent("did:agent:acme:bot")
        assert org == "acme"
        assert name == "bot"

    def test_parses_did_with_hyphens(self) -> None:
        org, name = _parse_did_agent("did:agent:my-org:my-agent")
        assert org == "my-org"
        assert name == "my-agent"

    def test_parses_did_with_underscores(self) -> None:
        org, name = _parse_did_agent("did:agent:my_org:my_agent")
        assert org == "my_org"
        assert name == "my_agent"

    def test_parses_did_with_dots(self) -> None:
        org, name = _parse_did_agent("did:agent:acme.corp:agent.v2")
        assert org == "acme.corp"
        assert name == "agent.v2"

    def test_invalid_format_no_name_raises(self) -> None:
        with pytest.raises(ValueError, match="Malformed"):
            _parse_did_agent("did:agent:acme")

    def test_invalid_format_wrong_method_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_did_agent("did:web:acme:bot")

    def test_not_a_did_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_did_agent("not-a-did")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_did_agent("")


# ===========================================================================
# VerificationMethod
# ===========================================================================


class TestVerificationMethod:
    def test_create_ed25519(self, vm_key: VerificationMethod) -> None:
        assert vm_key.type == "Ed25519VerificationKey2020"
        assert vm_key.id == "did:agent:acme:issuer#key-1"

    def test_create_jwk(self) -> None:
        vm = VerificationMethod(
            id="did:agent:acme:bot#jwk-1",
            type="JsonWebKey2020",
            controller="did:agent:acme:bot",
            public_key_multibase="zABC123",
        )
        assert vm.type == "JsonWebKey2020"

    def test_invalid_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            VerificationMethod(
                id="did:agent:acme:bot#key-1",
                type="RsaVerificationKey2018",
                controller="did:agent:acme:bot",
                public_key_multibase="zABC123",
            )

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="id must not be empty"):
            VerificationMethod(
                id="",
                type="Ed25519VerificationKey2020",
                controller="did:agent:acme:bot",
                public_key_multibase="zABC123",
            )

    def test_empty_controller_raises(self) -> None:
        with pytest.raises(ValueError, match="controller must not be empty"):
            VerificationMethod(
                id="did:agent:acme:bot#key-1",
                type="Ed25519VerificationKey2020",
                controller="",
                public_key_multibase="zABC123",
            )

    def test_empty_public_key_raises(self) -> None:
        with pytest.raises(ValueError, match="public_key_multibase must not be empty"):
            VerificationMethod(
                id="did:agent:acme:bot#key-1",
                type="Ed25519VerificationKey2020",
                controller="did:agent:acme:bot",
                public_key_multibase="",
            )

    def test_to_dict_structure(self, vm_key: VerificationMethod) -> None:
        result = vm_key.to_dict()
        assert result["id"] == vm_key.id
        assert result["type"] == vm_key.type
        assert result["controller"] == vm_key.controller
        assert result["publicKeyMultibase"] == vm_key.public_key_multibase

    def test_is_frozen(self, vm_key: VerificationMethod) -> None:
        with pytest.raises((AttributeError, TypeError)):
            vm_key.id = "modified"  # type: ignore[misc]


# ===========================================================================
# ServiceEndpoint
# ===========================================================================


class TestServiceEndpoint:
    def test_create_service(self, service_ep: ServiceEndpoint) -> None:
        assert service_ep.type == "AgentMessaging"
        assert service_ep.endpoint.startswith("https://")

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="id must not be empty"):
            ServiceEndpoint(id="", type="Messaging", endpoint="https://example.com")

    def test_empty_type_raises(self) -> None:
        with pytest.raises(ValueError, match="type must not be empty"):
            ServiceEndpoint(
                id="did:agent:acme:bot#svc",
                type="",
                endpoint="https://example.com",
            )

    def test_empty_endpoint_raises(self) -> None:
        with pytest.raises(ValueError, match="endpoint must not be empty"):
            ServiceEndpoint(id="did:agent:acme:bot#svc", type="Messaging", endpoint="")

    def test_to_dict_structure(self, service_ep: ServiceEndpoint) -> None:
        result = service_ep.to_dict()
        assert result["id"] == service_ep.id
        assert result["type"] == service_ep.type
        assert result["serviceEndpoint"] == service_ep.endpoint

    def test_is_frozen(self, service_ep: ServiceEndpoint) -> None:
        with pytest.raises((AttributeError, TypeError)):
            service_ep.type = "Other"  # type: ignore[misc]


# ===========================================================================
# DIDDocument
# ===========================================================================


class TestDIDDocumentCreation:
    def test_minimal_document(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        assert doc.id == "did:agent:acme:bot"
        assert doc.controller == "did:agent:acme:bot"

    def test_default_context(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        assert "https://www.w3.org/ns/did/v1" in doc.context

    def test_invalid_did_format_raises(self) -> None:
        with pytest.raises(ValueError):
            DIDDocument(id="did:web:example.com", controller="did:web:example.com")

    def test_invalid_did_no_name_raises(self) -> None:
        with pytest.raises(ValueError):
            DIDDocument(id="did:agent:acme", controller="did:agent:acme")

    def test_empty_context_raises(self) -> None:
        with pytest.raises(ValueError):
            DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot", context=[])

    def test_list_controller(self) -> None:
        doc = DIDDocument(
            id="did:agent:acme:bot",
            controller=["did:agent:acme:bot", "did:agent:acme:admin"],
        )
        assert isinstance(doc.controller, list)
        assert len(doc.controller) == 2

    def test_created_and_updated_defaults_to_utc(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        assert doc.created.tzinfo is not None
        assert doc.updated.tzinfo is not None

    def test_with_verification_method(self, vm_key: VerificationMethod) -> None:
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            verification_method=[vm_key],
            authentication=[vm_key.id],
        )
        assert len(doc.verification_method) == 1
        assert vm_key.id in doc.authentication

    def test_invalid_authentication_ref_raises(self, vm_key: VerificationMethod) -> None:
        with pytest.raises(ValueError):
            DIDDocument(
                id="did:agent:acme:issuer",
                controller="did:agent:acme:issuer",
                verification_method=[vm_key],
                authentication=["did:agent:acme:issuer#nonexistent"],
            )

    def test_invalid_assertion_ref_raises(self, vm_key: VerificationMethod) -> None:
        with pytest.raises(ValueError):
            DIDDocument(
                id="did:agent:acme:issuer",
                controller="did:agent:acme:issuer",
                verification_method=[vm_key],
                assertion_method=["did:agent:acme:issuer#nonexistent"],
            )

    def test_with_service_endpoint(self, service_ep: ServiceEndpoint) -> None:
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            service=[service_ep],
        )
        assert len(doc.service) == 1


class TestDIDDocumentHelpers:
    def test_org_extraction(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        assert doc.org() == "acme"

    def test_name_extraction(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        assert doc.name() == "bot"

    def test_resolve_verification_method_found(self, vm_key: VerificationMethod) -> None:
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            verification_method=[vm_key],
            authentication=[vm_key.id],
        )
        result = doc.resolve_verification_method(vm_key.id)
        assert result == vm_key

    def test_resolve_verification_method_not_found(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        result = doc.resolve_verification_method("did:agent:acme:bot#missing")
        assert result is None

    def test_resolve_verification_method_returns_correct_key(
        self, vm_key: VerificationMethod
    ) -> None:
        other_key = VerificationMethod(
            id="did:agent:acme:issuer#key-2",
            type="JsonWebKey2020",
            controller="did:agent:acme:issuer",
            public_key_multibase="zOtherKey123",
        )
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            verification_method=[vm_key, other_key],
            authentication=[vm_key.id, other_key.id],
        )
        assert doc.resolve_verification_method(vm_key.id) == vm_key
        assert doc.resolve_verification_method(other_key.id) == other_key


class TestDIDDocumentSerialization:
    def test_to_json_is_valid_json(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        parsed = json.loads(doc.to_json())
        assert parsed["id"] == "did:agent:acme:bot"

    def test_to_json_uses_context_key(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        parsed = json.loads(doc.to_json())
        assert "@context" in parsed

    def test_to_json_includes_created_updated(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        parsed = json.loads(doc.to_json())
        assert "created" in parsed
        assert "updated" in parsed

    def test_from_json_roundtrip(self) -> None:
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        restored = DIDDocument.from_json(doc.to_json())
        assert restored.id == doc.id
        assert restored.controller == doc.controller

    def test_from_json_preserves_verification_method(
        self, vm_key: VerificationMethod
    ) -> None:
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            verification_method=[vm_key],
            authentication=[vm_key.id],
        )
        restored = DIDDocument.from_json(doc.to_json())
        assert len(restored.verification_method) == 1
        assert restored.verification_method[0].id == vm_key.id

    def test_from_json_preserves_service(self, service_ep: ServiceEndpoint) -> None:
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            service=[service_ep],
        )
        restored = DIDDocument.from_json(doc.to_json())
        assert len(restored.service) == 1
        assert restored.service[0].endpoint == service_ep.endpoint

    def test_from_json_invalid_json_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON"):
            DIDDocument.from_json("not valid json {{")

    def test_from_json_invalid_did_format_raises(self) -> None:
        bad_doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
            "controller": "did:web:example.com",
            "verificationMethod": [],
            "authentication": [],
            "assertionMethod": [],
            "service": [],
            "created": datetime.now(timezone.utc).isoformat(),
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        with pytest.raises((ValueError, Exception)):
            DIDDocument.from_json(json.dumps(bad_doc))

    def test_to_json_with_assertion_method(self, vm_key: VerificationMethod) -> None:
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            verification_method=[vm_key],
            assertion_method=[vm_key.id],
        )
        parsed = json.loads(doc.to_json())
        assert vm_key.id in parsed["assertionMethod"]


# ===========================================================================
# DIDRegistry
# ===========================================================================


class TestDIDRegistryCRUD:
    def test_register_returns_did(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        result = registry.register(issuer_doc)
        assert result == issuer_doc.id

    def test_register_stores_document(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        resolved = registry.resolve(issuer_doc.id)
        assert resolved is not None
        assert resolved.id == issuer_doc.id

    def test_register_duplicate_raises(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        with pytest.raises(DIDAlreadyRegisteredError):
            registry.register(issuer_doc)

    def test_resolve_unregistered_returns_none(self, registry: DIDRegistry) -> None:
        result = registry.resolve("did:agent:acme:ghost")
        assert result is None

    def test_update_replaces_document(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        updated_doc = DIDDocument(
            id=issuer_doc.id,
            controller=[issuer_doc.id, "did:agent:acme:admin"],
        )
        success = registry.update(issuer_doc.id, updated_doc)
        assert success is True
        resolved = registry.resolve(issuer_doc.id)
        assert isinstance(resolved, DIDDocument)
        assert isinstance(resolved.controller, list)

    def test_update_non_existent_returns_false(self, registry: DIDRegistry) -> None:
        ghost_doc = DIDDocument(
            id="did:agent:acme:ghost", controller="did:agent:acme:ghost"
        )
        success = registry.update("did:agent:acme:ghost", ghost_doc)
        assert success is False

    def test_update_mismatched_did_raises(
        self, registry: DIDRegistry, issuer_doc: DIDDocument, subject_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        with pytest.raises(ValueError):
            registry.update(issuer_doc.id, subject_doc)

    def test_deactivate_marks_did(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        success = registry.deactivate(issuer_doc.id)
        assert success is True
        assert registry.is_deactivated(issuer_doc.id)

    def test_deactivate_non_existent_returns_false(self, registry: DIDRegistry) -> None:
        success = registry.deactivate("did:agent:acme:ghost")
        assert success is False

    def test_is_deactivated_false_for_active(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        assert registry.is_deactivated(issuer_doc.id) is False

    def test_resolve_still_returns_deactivated_document(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        registry.deactivate(issuer_doc.id)
        resolved = registry.resolve(issuer_doc.id)
        assert resolved is not None


class TestDIDRegistryQuery:
    def test_list_dids_empty(self, registry: DIDRegistry) -> None:
        assert registry.list_dids() == []

    def test_list_dids_returns_sorted(
        self,
        registry: DIDRegistry,
        issuer_doc: DIDDocument,
        subject_doc: DIDDocument,
    ) -> None:
        registry.register(issuer_doc)
        registry.register(subject_doc)
        dids = registry.list_dids()
        assert dids == sorted(dids)

    def test_list_dids_includes_deactivated(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        registry.deactivate(issuer_doc.id)
        assert issuer_doc.id in registry.list_dids()

    def test_search_by_org(self, populated_registry: DIDRegistry) -> None:
        results = populated_registry.search(org="acme")
        assert len(results) == 2
        for doc in results:
            assert doc.org() == "acme"

    def test_search_by_name(self, populated_registry: DIDRegistry) -> None:
        results = populated_registry.search(name="issuer")
        assert len(results) == 1
        assert results[0].id == "did:agent:acme:issuer"

    def test_search_by_org_and_name(self, populated_registry: DIDRegistry) -> None:
        results = populated_registry.search(org="acme", name="worker")
        assert len(results) == 1
        assert results[0].id == "did:agent:acme:worker"

    def test_search_no_filters_returns_all(self, populated_registry: DIDRegistry) -> None:
        results = populated_registry.search()
        assert len(results) == 2

    def test_search_nonexistent_org_returns_empty(
        self, populated_registry: DIDRegistry
    ) -> None:
        results = populated_registry.search(org="nonexistent")
        assert results == []

    def test_search_results_sorted(self, populated_registry: DIDRegistry) -> None:
        results = populated_registry.search()
        ids = [doc.id for doc in results]
        assert ids == sorted(ids)

    def test_len_counts_all_documents(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        assert len(registry) == 0
        registry.register(issuer_doc)
        assert len(registry) == 1

    def test_contains_registered_did(
        self, registry: DIDRegistry, issuer_doc: DIDDocument
    ) -> None:
        registry.register(issuer_doc)
        assert issuer_doc.id in registry

    def test_does_not_contain_unregistered_did(self, registry: DIDRegistry) -> None:
        assert "did:agent:acme:ghost" not in registry


class TestDIDRegistryPersistence:
    def test_export_creates_file(
        self,
        registry: DIDRegistry,
        issuer_doc: DIDDocument,
        tmp_path: Path,
    ) -> None:
        registry.register(issuer_doc)
        export_path = tmp_path / "registry.ndjson"
        registry.export_registry(export_path)
        assert export_path.exists()

    def test_export_import_roundtrip(
        self,
        registry: DIDRegistry,
        issuer_doc: DIDDocument,
        subject_doc: DIDDocument,
        tmp_path: Path,
    ) -> None:
        registry.register(issuer_doc)
        registry.register(subject_doc)
        export_path = tmp_path / "registry.ndjson"
        registry.export_registry(export_path)

        fresh_registry = DIDRegistry()
        fresh_registry.import_registry(export_path)

        assert issuer_doc.id in fresh_registry
        assert subject_doc.id in fresh_registry

    def test_export_preserves_deactivated_status(
        self,
        registry: DIDRegistry,
        issuer_doc: DIDDocument,
        tmp_path: Path,
    ) -> None:
        registry.register(issuer_doc)
        registry.deactivate(issuer_doc.id)
        export_path = tmp_path / "registry.ndjson"
        registry.export_registry(export_path)

        fresh_registry = DIDRegistry()
        fresh_registry.import_registry(export_path)
        assert fresh_registry.is_deactivated(issuer_doc.id)

    def test_import_skips_duplicates(
        self,
        registry: DIDRegistry,
        issuer_doc: DIDDocument,
        tmp_path: Path,
    ) -> None:
        registry.register(issuer_doc)
        export_path = tmp_path / "registry.ndjson"
        registry.export_registry(export_path)

        # Import into a registry that already has the same doc
        registry.import_registry(export_path)
        assert len(registry) == 1  # No duplicate added

    def test_import_empty_file_is_noop(
        self, registry: DIDRegistry, tmp_path: Path
    ) -> None:
        empty_path = tmp_path / "empty.ndjson"
        empty_path.write_text("", encoding="utf-8")
        registry.import_registry(empty_path)
        assert len(registry) == 0

    def test_import_missing_file_raises(
        self, registry: DIDRegistry, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            registry.import_registry(tmp_path / "nonexistent.ndjson")

    def test_import_invalid_json_raises(
        self, registry: DIDRegistry, tmp_path: Path
    ) -> None:
        bad_file = tmp_path / "bad.ndjson"
        bad_file.write_text("not json at all", encoding="utf-8")
        with pytest.raises(ValueError):
            registry.import_registry(bad_file)


# ===========================================================================
# CredentialSubject
# ===========================================================================


class TestCredentialSubject:
    def test_create_with_claims(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:bot", claims={"role": "reader"})
        assert cs.id == "did:agent:acme:bot"
        assert cs.claims["role"] == "reader"

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError):
            CredentialSubject(id="", claims={})

    def test_to_dict_includes_id_and_claims(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:bot", claims={"x": 1})
        result = cs.to_dict()
        assert result["id"] == "did:agent:acme:bot"
        assert result["x"] == 1

    def test_is_frozen(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:bot", claims={})
        with pytest.raises((AttributeError, TypeError)):
            cs.id = "changed"  # type: ignore[misc]


# ===========================================================================
# CredentialType
# ===========================================================================


class TestCredentialType:
    def test_all_types_defined(self) -> None:
        assert CredentialType.SECURITY_CERTIFICATION
        assert CredentialType.COMPLIANCE_ATTESTATION
        assert CredentialType.TRUST_SCORE
        assert CredentialType.CAPABILITY_CLAIM

    def test_values_are_strings(self) -> None:
        for ctype in CredentialType:
            assert isinstance(ctype.value, str)

    def test_from_string(self) -> None:
        ctype = CredentialType("CapabilityClaim")
        assert ctype == CredentialType.CAPABILITY_CLAIM


# ===========================================================================
# VerifiableCredential
# ===========================================================================


class TestVerifiableCredential:
    def test_create_minimal(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=datetime.now(timezone.utc),
            credential_subject=cs,
            credential_type=CredentialType.CAPABILITY_CLAIM,
        )
        assert vc.issuer == "did:agent:acme:issuer"
        assert "VerifiableCredential" in vc.type

    def test_type_always_includes_base(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=datetime.now(timezone.utc),
            credential_subject=cs,
            credential_type=CredentialType.CAPABILITY_CLAIM,
        )
        assert "VerifiableCredential" in vc.type

    def test_type_without_base_raises(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        with pytest.raises(ValueError, match="VerifiableCredential"):
            VerifiableCredential(
                issuer="did:agent:acme:issuer",
                issuance_date=datetime.now(timezone.utc),
                credential_subject=cs,
                credential_type=CredentialType.CAPABILITY_CLAIM,
                type=["CapabilityClaim"],
            )

    def test_empty_issuer_raises(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        with pytest.raises(ValueError, match="issuer"):
            VerifiableCredential(
                issuer="",
                issuance_date=datetime.now(timezone.utc),
                credential_subject=cs,
                credential_type=CredentialType.CAPABILITY_CLAIM,
            )

    def test_auto_generated_id(self, basic_credential: VerifiableCredential) -> None:
        assert basic_credential.id.startswith("urn:uuid:")

    def test_is_expired_no_expiry(self, basic_credential: VerifiableCredential) -> None:
        assert basic_credential.is_expired() is False

    def test_is_expired_future_expiry(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=datetime.now(timezone.utc),
            expiration_date=datetime.now(timezone.utc) + timedelta(days=30),
            credential_subject=cs,
            credential_type=CredentialType.CAPABILITY_CLAIM,
        )
        assert vc.is_expired() is False

    def test_is_expired_past_expiry(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=datetime.now(timezone.utc) - timedelta(days=2),
            expiration_date=datetime.now(timezone.utc) - timedelta(days=1),
            credential_subject=cs,
            credential_type=CredentialType.CAPABILITY_CLAIM,
        )
        assert vc.is_expired() is True

    def test_to_json_roundtrip(self, basic_credential: VerifiableCredential) -> None:
        restored = VerifiableCredential.from_json(basic_credential.to_json())
        assert restored.id == basic_credential.id
        assert restored.issuer == basic_credential.issuer
        assert restored.credential_type == basic_credential.credential_type

    def test_to_json_contains_context(self, basic_credential: VerifiableCredential) -> None:
        parsed = json.loads(basic_credential.to_json())
        assert "@context" in parsed

    def test_to_json_with_expiration(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=datetime.now(timezone.utc),
            expiration_date=datetime.now(timezone.utc) + timedelta(days=30),
            credential_subject=cs,
            credential_type=CredentialType.CAPABILITY_CLAIM,
        )
        parsed = json.loads(vc.to_json())
        assert "expirationDate" in parsed

    def test_from_json_invalid_json_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON"):
            VerifiableCredential.from_json("{broken json")

    def test_from_json_preserves_expiration(self) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=datetime.now(timezone.utc),
            expiration_date=datetime.now(timezone.utc) + timedelta(days=10),
            credential_subject=cs,
            credential_type=CredentialType.TRUST_SCORE,
        )
        restored = VerifiableCredential.from_json(vc.to_json())
        assert restored.expiration_date is not None


# ===========================================================================
# CredentialIssuer
# ===========================================================================


class TestCredentialIssuer:
    def test_issue_returns_credential(self, cred_issuer: CredentialIssuer) -> None:
        credential = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.CAPABILITY_CLAIM,
            claims={"capability": "read"},
        )
        assert isinstance(credential, VerifiableCredential)

    def test_issue_sets_issuer(self, cred_issuer: CredentialIssuer) -> None:
        credential = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.COMPLIANCE_ATTESTATION,
            claims={},
        )
        assert credential.issuer == "did:agent:acme:issuer"

    def test_issue_sets_subject(self, cred_issuer: CredentialIssuer) -> None:
        credential = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.TRUST_SCORE,
            claims={"score": 95},
        )
        assert credential.credential_subject.id == "did:agent:acme:worker"

    def test_issue_with_expiration_days(self, cred_issuer: CredentialIssuer) -> None:
        credential = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.SECURITY_CERTIFICATION,
            claims={},
            expiration_days=30,
        )
        assert credential.expiration_date is not None
        assert credential.expiration_date > credential.issuance_date

    def test_issue_without_expiration(self, cred_issuer: CredentialIssuer) -> None:
        credential = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.CAPABILITY_CLAIM,
            claims={},
        )
        assert credential.expiration_date is None

    def test_verify_structure_valid(
        self, cred_issuer: CredentialIssuer, basic_credential: VerifiableCredential
    ) -> None:
        assert cred_issuer.verify_structure(basic_credential) is True

    def test_verify_structure_invalid_expiry_before_issuance(
        self, cred_issuer: CredentialIssuer
    ) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        now = datetime.now(timezone.utc)
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=now,
            expiration_date=now - timedelta(seconds=1),
            credential_subject=cs,
            credential_type=CredentialType.CAPABILITY_CLAIM,
        )
        assert cred_issuer.verify_structure(vc) is False

    def test_revoke_and_is_revoked(
        self, cred_issuer: CredentialIssuer, basic_credential: VerifiableCredential
    ) -> None:
        assert cred_issuer.is_revoked(basic_credential.id) is False
        cred_issuer.revoke(basic_credential.id)
        assert cred_issuer.is_revoked(basic_credential.id) is True

    def test_revoke_idempotent(
        self, cred_issuer: CredentialIssuer, basic_credential: VerifiableCredential
    ) -> None:
        cred_issuer.revoke(basic_credential.id)
        cred_issuer.revoke(basic_credential.id)
        assert cred_issuer.is_revoked(basic_credential.id) is True

    def test_revoked_credential_ids_sorted(
        self, cred_issuer: CredentialIssuer
    ) -> None:
        ids = ["urn:uuid:zzz", "urn:uuid:aaa", "urn:uuid:mmm"]
        for cid in ids:
            cred_issuer.revoke(cid)
        result = cred_issuer.revoked_credential_ids()
        assert result == sorted(ids)


# ===========================================================================
# VerificationResult
# ===========================================================================


class TestVerificationResult:
    def test_valid_when_no_failures(self) -> None:
        result = VerificationResult(
            valid=True, checks_passed=["check_a"], checks_failed=[]
        )
        assert result.valid is True

    def test_invalid_when_failures_present(self) -> None:
        result = VerificationResult(
            valid=True, checks_passed=[], checks_failed=["check_b"]
        )
        # __post_init__ overrides valid to False
        assert result.valid is False

    def test_is_frozen(self) -> None:
        result = VerificationResult(valid=True, checks_passed=["a"], checks_failed=[])
        with pytest.raises((AttributeError, TypeError)):
            result.valid = False  # type: ignore[misc]

    def test_empty_details_by_default(self) -> None:
        result = VerificationResult(valid=True, checks_passed=[], checks_failed=[])
        assert result.details == {}


# ===========================================================================
# DIDVerifier — verify_document
# ===========================================================================


class TestDIDVerifierDocument:
    def test_valid_minimal_document_passes(
        self, verifier: DIDVerifier, issuer_doc: DIDDocument
    ) -> None:
        result = verifier.verify_document(issuer_doc)
        assert result.valid is True

    def test_checks_passed_listed(
        self, verifier: DIDVerifier, issuer_doc: DIDDocument
    ) -> None:
        result = verifier.verify_document(issuer_doc)
        assert "did_format_valid" in result.checks_passed
        assert "context_present" in result.checks_passed
        assert "controller_present" in result.checks_passed

    def test_w3c_context_check(
        self, verifier: DIDVerifier, issuer_doc: DIDDocument
    ) -> None:
        result = verifier.verify_document(issuer_doc)
        assert "w3c_context_included" in result.checks_passed

    def test_document_with_verification_methods_passes(
        self,
        verifier: DIDVerifier,
        vm_key: VerificationMethod,
    ) -> None:
        doc = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
            verification_method=[vm_key],
            authentication=[vm_key.id],
        )
        result = verifier.verify_document(doc)
        assert result.valid is True
        assert "verification_methods_valid" in result.checks_passed

    def test_details_contains_did(
        self, verifier: DIDVerifier, issuer_doc: DIDDocument
    ) -> None:
        result = verifier.verify_document(issuer_doc)
        assert result.details.get("did") == issuer_doc.id

    def test_details_contains_method_count(
        self, verifier: DIDVerifier, issuer_doc: DIDDocument
    ) -> None:
        result = verifier.verify_document(issuer_doc)
        assert result.details.get("method_count") == 0


# ===========================================================================
# DIDVerifier — verify_credential
# ===========================================================================


class TestDIDVerifierCredential:
    def test_valid_credential_passes(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
        cred_issuer: CredentialIssuer,
    ) -> None:
        result = verifier.verify_credential(
            basic_credential, populated_registry, cred_issuer
        )
        assert result.valid is True

    def test_issuer_not_registered_fails(
        self,
        verifier: DIDVerifier,
        registry: DIDRegistry,
        basic_credential: VerifiableCredential,
    ) -> None:
        result = verifier.verify_credential(basic_credential, registry)
        assert "issuer_registered" in result.checks_failed

    def test_subject_not_registered_fails(
        self,
        verifier: DIDVerifier,
        registry: DIDRegistry,
        issuer_doc: DIDDocument,
        basic_credential: VerifiableCredential,
    ) -> None:
        registry.register(issuer_doc)
        result = verifier.verify_credential(basic_credential, registry)
        assert "subject_registered" in result.checks_failed

    def test_expired_credential_fails(
        self,
        verifier: DIDVerifier,
        populated_registry: DIDRegistry,
    ) -> None:
        cs = CredentialSubject(id="did:agent:acme:worker", claims={})
        vc = VerifiableCredential(
            issuer="did:agent:acme:issuer",
            issuance_date=datetime.now(timezone.utc) - timedelta(days=2),
            expiration_date=datetime.now(timezone.utc) - timedelta(days=1),
            credential_subject=cs,
            credential_type=CredentialType.CAPABILITY_CLAIM,
        )
        result = verifier.verify_credential(vc, populated_registry)
        assert "not_expired" in result.checks_failed

    def test_revoked_credential_fails(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
        cred_issuer: CredentialIssuer,
    ) -> None:
        cred_issuer.revoke(basic_credential.id)
        result = verifier.verify_credential(
            basic_credential, populated_registry, cred_issuer
        )
        assert "not_revoked" in result.checks_failed

    def test_deactivated_issuer_fails(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
    ) -> None:
        populated_registry.deactivate("did:agent:acme:issuer")
        result = verifier.verify_credential(basic_credential, populated_registry)
        assert "issuer_not_deactivated" in result.checks_failed

    def test_no_revocation_check_without_issuer(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
    ) -> None:
        result = verifier.verify_credential(basic_credential, populated_registry)
        # Without issuer, "not_revoked" should not appear in either list
        assert "not_revoked" not in result.checks_failed
        assert "not_revoked" not in result.checks_passed

    def test_details_include_credential_info(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
    ) -> None:
        result = verifier.verify_credential(basic_credential, populated_registry)
        assert result.details.get("credential_id") == basic_credential.id
        assert result.details.get("issuer") == basic_credential.issuer


# ===========================================================================
# DIDVerifier — verify_chain
# ===========================================================================


class TestDIDVerifierChain:
    def test_empty_chain_fails(
        self, verifier: DIDVerifier, populated_registry: DIDRegistry
    ) -> None:
        result = verifier.verify_chain([], populated_registry)
        assert result.valid is False
        assert "chain_non_empty" in result.checks_failed

    def test_single_credential_chain(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
        cred_issuer: CredentialIssuer,
    ) -> None:
        result = verifier.verify_chain(
            [basic_credential], populated_registry, cred_issuer
        )
        assert result.valid is True

    def test_two_credential_chain_valid(
        self,
        verifier: DIDVerifier,
        populated_registry: DIDRegistry,
        cred_issuer: CredentialIssuer,
    ) -> None:
        # Register intermediate agent
        intermediate = DIDDocument(
            id="did:agent:acme:issuer",
            controller="did:agent:acme:issuer",
        )

        # Credential 1: root issues to issuer (subject = did:agent:acme:issuer)
        cred1 = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.CAPABILITY_CLAIM,
            claims={"level": 1},
        )
        # Credential 2: issuer (now acting as subject's endorser) issues another
        # For chain linkage: subject of cred1 == issuer of cred2
        cred2 = cred_issuer.issue(
            issuer_did="did:agent:acme:worker",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.TRUST_SCORE,
            claims={"level": 2},
        )
        # Register worker as both issuer doc and subject doc
        worker_doc = DIDDocument(
            id="did:agent:acme:worker", controller="did:agent:acme:worker"
        )
        if "did:agent:acme:worker" not in populated_registry:
            populated_registry.register(worker_doc)

        result = verifier.verify_chain([cred1, cred2], populated_registry)
        assert "chain_linkage_valid" in result.checks_passed

    def test_chain_broken_linkage_fails(
        self,
        verifier: DIDVerifier,
        populated_registry: DIDRegistry,
        cred_issuer: CredentialIssuer,
    ) -> None:
        cred1 = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.CAPABILITY_CLAIM,
            claims={},
        )
        # cred2's issuer does NOT match cred1's subject
        cred2 = cred_issuer.issue(
            issuer_did="did:agent:acme:issuer",  # should be "worker" for linkage
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.TRUST_SCORE,
            claims={},
        )
        result = verifier.verify_chain([cred1, cred2], populated_registry)
        assert "linkage_0_to_1" in result.checks_failed

    def test_chain_details_contain_root_and_terminal(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
    ) -> None:
        result = verifier.verify_chain([basic_credential], populated_registry)
        assert result.details.get("root_issuer") == basic_credential.issuer
        assert (
            result.details.get("terminal_subject")
            == basic_credential.credential_subject.id
        )

    def test_chain_length_in_details(
        self,
        verifier: DIDVerifier,
        basic_credential: VerifiableCredential,
        populated_registry: DIDRegistry,
    ) -> None:
        result = verifier.verify_chain([basic_credential], populated_registry)
        assert result.details.get("chain_length") == 1


# ===========================================================================
# CLI — did command group
# ===========================================================================


class TestDIDCLICreate:
    def test_create_minimal(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["did", "create", "--org", "acme", "--name", "bot"])
        assert result.exit_code == 0
        assert "did:agent:acme:bot" in result.output

    def test_create_with_output_file(self, runner: CliRunner, tmp_path: Path) -> None:
        output_file = tmp_path / "doc.json"
        result = runner.invoke(
            cli,
            ["did", "create", "--org", "acme", "--name", "bot", "--output", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        doc_data = json.loads(output_file.read_text())
        assert doc_data["id"] == "did:agent:acme:bot"

    def test_create_persists_to_registry_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        registry_file = tmp_path / "registry.ndjson"
        result = runner.invoke(
            cli,
            [
                "did",
                "create",
                "--org",
                "acme",
                "--name",
                "bot",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert registry_file.exists()

    def test_create_duplicate_exits_nonzero(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        registry_file = tmp_path / "registry.ndjson"
        args = [
            "did",
            "create",
            "--org",
            "acme",
            "--name",
            "bot",
            "--registry-file",
            str(registry_file),
        ]
        runner.invoke(cli, args)
        result = runner.invoke(cli, args)
        assert result.exit_code != 0

    def test_create_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["did", "create", "--help"])
        assert result.exit_code == 0


class TestDIDCLIResolve:
    def test_resolve_registered_did(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        registry_file = tmp_path / "registry.ndjson"
        runner.invoke(
            cli,
            [
                "did",
                "create",
                "--org",
                "acme",
                "--name",
                "bot",
                "--registry-file",
                str(registry_file),
            ],
        )
        result = runner.invoke(
            cli,
            [
                "did",
                "resolve",
                "did:agent:acme:bot",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert "did:agent:acme:bot" in result.output

    def test_resolve_unknown_did_exits_nonzero(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["did", "resolve", "did:agent:acme:ghost"])
        assert result.exit_code != 0

    def test_resolve_deactivated_shows_warning(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        registry_file = tmp_path / "registry.ndjson"
        # Create a registry with a deactivated DID
        from agent_identity.did.document import DIDDocument as D
        from agent_identity.did.registry import DIDRegistry as R

        reg = R()
        doc = D(id="did:agent:acme:retired", controller="did:agent:acme:retired")
        reg.register(doc)
        reg.deactivate(doc.id)
        reg.export_registry(registry_file)

        result = runner.invoke(
            cli,
            [
                "did",
                "resolve",
                "did:agent:acme:retired",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert "deactivated" in result.output.lower() or "Warning" in result.output

    def test_resolve_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["did", "resolve", "--help"])
        assert result.exit_code == 0


class TestDIDCLIIssue:
    def test_issue_minimal(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "did",
                "issue",
                "--issuer",
                "did:agent:acme:issuer",
                "--subject",
                "did:agent:acme:worker",
                "--type",
                "CapabilityClaim",
                "--claims",
                '{"capability": "read"}',
            ],
        )
        assert result.exit_code == 0
        assert "issuer" in result.output.lower() or "urn:uuid" in result.output

    def test_issue_with_expiration(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "did",
                "issue",
                "--issuer",
                "did:agent:acme:issuer",
                "--subject",
                "did:agent:acme:worker",
                "--type",
                "TrustScore",
                "--claims",
                "{}",
                "--expiration-days",
                "30",
            ],
        )
        assert result.exit_code == 0

    def test_issue_writes_to_file(self, runner: CliRunner, tmp_path: Path) -> None:
        output_file = tmp_path / "credential.json"
        result = runner.invoke(
            cli,
            [
                "did",
                "issue",
                "--issuer",
                "did:agent:acme:issuer",
                "--subject",
                "did:agent:acme:worker",
                "--type",
                "ComplianceAttestation",
                "--claims",
                "{}",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "VerifiableCredential" in data["type"]

    def test_issue_invalid_type_exits_nonzero(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "did",
                "issue",
                "--issuer",
                "did:agent:acme:issuer",
                "--subject",
                "did:agent:acme:worker",
                "--type",
                "InvalidType",
                "--claims",
                "{}",
            ],
        )
        assert result.exit_code != 0

    def test_issue_invalid_claims_json_exits_nonzero(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "did",
                "issue",
                "--issuer",
                "did:agent:acme:issuer",
                "--subject",
                "did:agent:acme:worker",
                "--type",
                "CapabilityClaim",
                "--claims",
                "not json",
            ],
        )
        assert result.exit_code != 0

    def test_issue_security_certification(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "did",
                "issue",
                "--issuer",
                "did:agent:acme:issuer",
                "--subject",
                "did:agent:acme:worker",
                "--type",
                "SecurityCertification",
                "--claims",
                '{"audit": "passed"}',
            ],
        )
        assert result.exit_code == 0

    def test_issue_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["did", "issue", "--help"])
        assert result.exit_code == 0


class TestDIDCLIVerify:
    def test_verify_valid_credential_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        # Create a registry with issuer and subject
        registry_file = tmp_path / "registry.ndjson"
        from agent_identity.did.document import DIDDocument as D
        from agent_identity.did.registry import DIDRegistry as R

        reg = R()
        reg.register(D(id="did:agent:acme:issuer", controller="did:agent:acme:issuer"))
        reg.register(D(id="did:agent:acme:worker", controller="did:agent:acme:worker"))
        reg.export_registry(registry_file)

        # Issue and write a credential
        from agent_identity.did.credentials import CredentialIssuer as CI

        issuer_obj = CI()
        cred = issuer_obj.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.CAPABILITY_CLAIM,
            claims={},
        )
        cred_file = tmp_path / "credential.json"
        cred_file.write_text(cred.to_json(), encoding="utf-8")

        result = runner.invoke(
            cli,
            [
                "did",
                "verify",
                "--credential",
                str(cred_file),
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_credential_without_registry(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        from agent_identity.did.credentials import CredentialIssuer as CI

        issuer_obj = CI()
        cred = issuer_obj.issue(
            issuer_did="did:agent:acme:issuer",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.CAPABILITY_CLAIM,
            claims={},
        )
        cred_file = tmp_path / "credential.json"
        cred_file.write_text(cred.to_json(), encoding="utf-8")

        result = runner.invoke(
            cli,
            ["did", "verify", "--credential", str(cred_file)],
        )
        # Exit non-zero because issuer not in registry
        assert result.exit_code != 0
        assert "FAIL" in result.output

    def test_verify_invalid_credential_file_exits_nonzero(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all", encoding="utf-8")
        result = runner.invoke(
            cli,
            ["did", "verify", "--credential", str(bad_file)],
        )
        assert result.exit_code != 0

    def test_verify_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["did", "verify", "--help"])
        assert result.exit_code == 0


class TestDIDCLIGroup:
    def test_did_group_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["did", "--help"])
        assert result.exit_code == 0
        assert "create" in result.output
        assert "resolve" in result.output
        assert "issue" in result.output
        assert "verify" in result.output
