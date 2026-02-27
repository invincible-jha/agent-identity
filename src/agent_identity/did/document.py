"""DIDDocument — W3C DID Core compliant document model for the ``did:agent`` method.

DID format
----------
::

    did:agent:<org>:<name>

Examples::

    did:agent:acme:invoicer
    did:agent:platform:audit-bot
    did:agent:research:summarizer-v2

Specification reference
-----------------------
This module follows the W3C DID Core data model:
https://www.w3.org/TR/did-core/#data-model
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator, model_validator

# ------------------------------------------------------------------
# DID method constant
# ------------------------------------------------------------------

DID_METHOD: str = "agent"

# Pattern for the did:agent method: did:agent:<org>:<name>
# Both org and name are non-empty strings containing alphanumeric chars,
# hyphens, underscores, dots, or forward slashes.
_DID_AGENT_PATTERN = re.compile(
    r"^did:agent:(?P<org>[A-Za-z0-9._\-]+):(?P<name>[A-Za-z0-9._\-/]+)$"
)


def _parse_did_agent(did: str) -> tuple[str, str]:
    """Parse a ``did:agent:<org>:<name>`` string into ``(org, name)``.

    Parameters
    ----------
    did:
        The fully-qualified DID string.

    Returns
    -------
    tuple[str, str]
        ``(org, name)`` extracted from the DID.

    Raises
    ------
    ValueError
        If the DID does not match the ``did:agent`` format.
    """
    match = _DID_AGENT_PATTERN.match(did)
    if not match:
        raise ValueError(
            f"Malformed did:agent DID {did!r}. "
            "Expected format: did:agent:<org>:<name> "
            "(org and name are alphanumeric with hyphens/underscores/dots allowed)."
        )
    return match.group("org"), match.group("name")


# ------------------------------------------------------------------
# Verification method
# ------------------------------------------------------------------

_ALLOWED_VERIFICATION_TYPES = frozenset(
    {"Ed25519VerificationKey2020", "JsonWebKey2020"}
)


@dataclass(frozen=True)
class VerificationMethod:
    """A cryptographic verification method attached to a DID document.

    This is a structural container. Cryptographic key material is stored
    in ``public_key_multibase`` as a multibase-encoded string. Actual
    signature verification is handled by external plugin hooks — this
    class intentionally contains no cryptographic logic.

    Parameters
    ----------
    id:
        The verification method identifier (e.g. ``did:agent:org:name#key-1``).
    type:
        Key type: ``"Ed25519VerificationKey2020"`` or ``"JsonWebKey2020"``.
    controller:
        The DID that controls this key.
    public_key_multibase:
        The public key encoded in multibase format (placeholder value
        accepted for testing and extension — no crypto validation here).
    """

    id: str
    type: str
    controller: str
    public_key_multibase: str

    def __post_init__(self) -> None:
        if self.type not in _ALLOWED_VERIFICATION_TYPES:
            raise ValueError(
                f"Unsupported verification method type {self.type!r}. "
                f"Allowed: {sorted(_ALLOWED_VERIFICATION_TYPES)}"
            )
        if not self.id:
            raise ValueError("VerificationMethod.id must not be empty.")
        if not self.controller:
            raise ValueError("VerificationMethod.controller must not be empty.")
        if not self.public_key_multibase:
            raise ValueError("VerificationMethod.public_key_multibase must not be empty.")

    def to_dict(self) -> dict[str, object]:
        """Serialize to a W3C-compatible plain dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "controller": self.controller,
            "publicKeyMultibase": self.public_key_multibase,
        }


# ------------------------------------------------------------------
# Service endpoint
# ------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceEndpoint:
    """A service endpoint advertised in a DID document.

    Parameters
    ----------
    id:
        The service identifier (e.g. ``did:agent:org:name#messaging``).
    type:
        Service type string (e.g. ``"AgentMessaging"``, ``"LinkedDomains"``).
    endpoint:
        The URL or URI for this service.
    """

    id: str
    type: str
    endpoint: str

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("ServiceEndpoint.id must not be empty.")
        if not self.type:
            raise ValueError("ServiceEndpoint.type must not be empty.")
        if not self.endpoint:
            raise ValueError("ServiceEndpoint.endpoint must not be empty.")

    def to_dict(self) -> dict[str, str]:
        """Serialize to a W3C-compatible plain dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "serviceEndpoint": self.endpoint,
        }


# ------------------------------------------------------------------
# DID Document (Pydantic v2)
# ------------------------------------------------------------------


class DIDDocument(BaseModel):
    """A W3C DID Core compliant DID document for the ``did:agent`` method.

    The document follows the structure defined in:
    https://www.w3.org/TR/did-core/#did-documents

    Parameters
    ----------
    context:
        JSON-LD context URIs. Defaults to the W3C DID v1 context.
    id:
        The DID subject identifier in ``did:agent:<org>:<name>`` format.
    controller:
        DID(s) authorized to make changes to this document. May be a single
        DID string or a list of DID strings.
    verification_method:
        Cryptographic public keys associated with this DID.
    authentication:
        List of verification method IDs authorized for authentication.
    assertion_method:
        List of verification method IDs authorized for assertions.
    service:
        Service endpoints associated with this DID subject.
    created:
        UTC datetime when this document was first created.
    updated:
        UTC datetime of the most recent update to this document.
    """

    model_config = {"arbitrary_types_allowed": True}

    context: list[str] = Field(
        default_factory=lambda: ["https://www.w3.org/ns/did/v1"]
    )
    id: str
    controller: str | list[str]
    verification_method: list[VerificationMethod] = Field(default_factory=list)
    authentication: list[str] = Field(default_factory=list)
    assertion_method: list[str] = Field(default_factory=list)
    service: list[ServiceEndpoint] = Field(default_factory=list)
    created: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("id")
    @classmethod
    def validate_did_format(cls, value: str) -> str:
        """Validate the DID id is a well-formed did:agent DID."""
        _parse_did_agent(value)  # raises ValueError on bad format
        return value

    @field_validator("context")
    @classmethod
    def validate_context_not_empty(cls, value: list[str]) -> list[str]:
        """Ensure context has at least one entry."""
        if not value:
            raise ValueError("context must contain at least one URI.")
        return value

    @model_validator(mode="after")
    def validate_authentication_references(self) -> "DIDDocument":
        """Validate authentication references point to declared methods."""
        method_ids = {vm.id for vm in self.verification_method}
        for auth_ref in self.authentication:
            if method_ids and auth_ref not in method_ids:
                raise ValueError(
                    f"authentication reference {auth_ref!r} does not match "
                    "any declared verification_method id. "
                    "Add the verification method first or use a valid reference."
                )
        return self

    @model_validator(mode="after")
    def validate_assertion_references(self) -> "DIDDocument":
        """Validate assertion_method references point to declared methods."""
        method_ids = {vm.id for vm in self.verification_method}
        for assert_ref in self.assertion_method:
            if method_ids and assert_ref not in method_ids:
                raise ValueError(
                    f"assertion_method reference {assert_ref!r} does not match "
                    "any declared verification_method id."
                )
        return self

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def resolve_verification_method(self, method_id: str) -> VerificationMethod | None:
        """Return the VerificationMethod with the given id, or None.

        Parameters
        ----------
        method_id:
            The ``id`` field of the VerificationMethod to look up.

        Returns
        -------
        VerificationMethod | None
            The matching method, or ``None`` if not found.
        """
        for method in self.verification_method:
            if method.id == method_id:
                return method
        return None

    def org(self) -> str:
        """Return the ``org`` segment of this document's DID.

        Returns
        -------
        str
            The organization portion extracted from ``self.id``.
        """
        org, _ = _parse_did_agent(self.id)
        return org

    def name(self) -> str:
        """Return the ``name`` segment of this document's DID.

        Returns
        -------
        str
            The name portion extracted from ``self.id``.
        """
        _, agent_name = _parse_did_agent(self.id)
        return agent_name

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialize this document to a JSON string.

        The output follows W3C DID Core JSON representation conventions,
        including camelCase property names where the spec requires them.

        Returns
        -------
        str
            JSON representation of this DID document.
        """
        data: dict[str, object] = {
            "@context": self.context,
            "id": self.id,
            "controller": self.controller,
            "verificationMethod": [vm.to_dict() for vm in self.verification_method],
            "authentication": self.authentication,
            "assertionMethod": self.assertion_method,
            "service": [svc.to_dict() for svc in self.service],
            "created": self.created.isoformat(),
            "updated": self.updated.isoformat(),
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "DIDDocument":
        """Deserialize a DIDDocument from a JSON string.

        Parameters
        ----------
        json_str:
            A JSON string as produced by :meth:`to_json`.

        Returns
        -------
        DIDDocument
            The reconstructed document.

        Raises
        ------
        ValueError
            If the JSON is malformed or the document fails validation.
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

        verification_methods = [
            VerificationMethod(
                id=vm["id"],
                type=vm["type"],
                controller=vm["controller"],
                public_key_multibase=vm["publicKeyMultibase"],
            )
            for vm in data.get("verificationMethod", [])
        ]
        service_endpoints = [
            ServiceEndpoint(
                id=svc["id"],
                type=svc["type"],
                endpoint=svc["serviceEndpoint"],
            )
            for svc in data.get("service", [])
        ]

        created_raw = data.get("created")
        updated_raw = data.get("updated")

        return cls(
            context=data.get("@context", ["https://www.w3.org/ns/did/v1"]),
            id=data["id"],
            controller=data["controller"],
            verification_method=verification_methods,
            authentication=data.get("authentication", []),
            assertion_method=data.get("assertionMethod", []),
            service=service_endpoints,
            created=(
                datetime.fromisoformat(created_raw)
                if created_raw
                else datetime.now(timezone.utc)
            ),
            updated=(
                datetime.fromisoformat(updated_raw)
                if updated_raw
                else datetime.now(timezone.utc)
            ),
        )
