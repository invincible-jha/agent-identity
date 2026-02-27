"""Verifiable Credentials for agent identity.

Implements the W3C Verifiable Credentials Data Model:
https://www.w3.org/TR/vc-data-model/

This module provides structural credential issuance and verification.
Cryptographic proof generation is deliberately excluded and left as an
extension point — see ``proof`` field and ``_crypto_proof_hook`` below.

Credential types
----------------
``CredentialType`` enumerates the domain-specific credential categories
used within agent identity management:

- ``SECURITY_CERTIFICATION``  — agent passed a security review
- ``COMPLIANCE_ATTESTATION``  — agent is compliant with a policy
- ``TRUST_SCORE``             — attested trust score at a point in time
- ``CAPABILITY_CLAIM``        — agent is authorized for a capability
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ------------------------------------------------------------------
# CredentialType
# ------------------------------------------------------------------


class CredentialType(str, Enum):
    """Enumeration of supported verifiable credential types."""

    SECURITY_CERTIFICATION = "SecurityCertification"
    COMPLIANCE_ATTESTATION = "ComplianceAttestation"
    TRUST_SCORE = "TrustScore"
    CAPABILITY_CLAIM = "CapabilityClaim"


# ------------------------------------------------------------------
# CredentialSubject
# ------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialSubject:
    """The entity described by a verifiable credential.

    Parameters
    ----------
    id:
        The DID of the subject being described.
    claims:
        Arbitrary key-value claims about the subject.
    """

    id: str
    claims: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("CredentialSubject.id must not be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a W3C-compatible plain dictionary."""
        return {"id": self.id, **self.claims}


# ------------------------------------------------------------------
# VerifiableCredential (Pydantic v2)
# ------------------------------------------------------------------


class VerifiableCredential(BaseModel):
    """A W3C Verifiable Credential describing an agent's attributes.

    The ``proof`` field is intentionally left as an opaque dictionary
    placeholder. Populating it with a real cryptographic proof is an
    extension point — integrate a signing library and populate this field
    via :attr:`_crypto_proof_hook` or by directly assigning a proof dict.

    Parameters
    ----------
    context:
        JSON-LD context URIs.
    id:
        Unique identifier for this credential (UUID-based URI by default).
    type:
        Credential type list. Always includes ``"VerifiableCredential"``.
    issuer:
        DID of the issuing agent.
    issuance_date:
        UTC datetime when the credential was issued.
    expiration_date:
        Optional UTC datetime after which the credential is no longer valid.
    credential_subject:
        The subject and their claims.
    credential_type:
        Domain-specific credential category.
    proof:
        Optional cryptographic proof dict (extension point, not validated here).
    """

    model_config = {"arbitrary_types_allowed": True}

    context: list[str] = Field(
        default_factory=lambda: [
            "https://www.w3.org/2018/credentials/v1",
        ]
    )
    id: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    type: list[str] = Field(default_factory=lambda: ["VerifiableCredential"])
    issuer: str
    issuance_date: datetime
    expiration_date: datetime | None = None
    credential_subject: CredentialSubject
    credential_type: CredentialType
    proof: dict[str, Any] | None = None

    @field_validator("issuer")
    @classmethod
    def validate_issuer_not_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("issuer must not be empty.")
        return value

    @field_validator("type")
    @classmethod
    def validate_type_includes_base(cls, value: list[str]) -> list[str]:
        if "VerifiableCredential" not in value:
            raise ValueError(
                "type list must include 'VerifiableCredential' as required by "
                "the W3C Verifiable Credentials Data Model."
            )
        return value

    # ------------------------------------------------------------------
    # Status checks
    # ------------------------------------------------------------------

    def is_expired(self) -> bool:
        """Return ``True`` if the credential has passed its expiration date.

        A credential with no ``expiration_date`` never expires.

        Returns
        -------
        bool
        """
        if self.expiration_date is None:
            return False
        return datetime.now(timezone.utc) > self.expiration_date

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialize to a JSON string following W3C VC Data Model conventions.

        Returns
        -------
        str
            JSON representation of this credential.
        """
        data: dict[str, Any] = {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date.isoformat(),
            "credentialSubject": self.credential_subject.to_dict(),
            "credentialType": self.credential_type.value,
        }
        if self.expiration_date is not None:
            data["expirationDate"] = self.expiration_date.isoformat()
        if self.proof is not None:
            data["proof"] = self.proof
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "VerifiableCredential":
        """Deserialize a VerifiableCredential from a JSON string.

        Parameters
        ----------
        json_str:
            A JSON string as produced by :meth:`to_json`.

        Returns
        -------
        VerifiableCredential
            The reconstructed credential.

        Raises
        ------
        ValueError
            If the JSON is malformed or fails validation.
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

        subject_raw: dict[str, Any] = data.get("credentialSubject", {})
        subject_id = subject_raw.pop("id", "")
        credential_subject = CredentialSubject(id=subject_id, claims=dict(subject_raw))

        expiration_raw: str | None = data.get("expirationDate")

        return cls(
            context=data.get("@context", ["https://www.w3.org/2018/credentials/v1"]),
            id=data.get("id", f"urn:uuid:{uuid.uuid4()}"),
            type=data.get("type", ["VerifiableCredential"]),
            issuer=data["issuer"],
            issuance_date=datetime.fromisoformat(data["issuanceDate"]),
            expiration_date=(
                datetime.fromisoformat(expiration_raw) if expiration_raw else None
            ),
            credential_subject=credential_subject,
            credential_type=CredentialType(data["credentialType"]),
            proof=data.get("proof"),
        )


# ------------------------------------------------------------------
# Extension hook placeholder
# ------------------------------------------------------------------
# Plugin authors: replace this with a real signing implementation.
# The hook receives the credential dict and should return a proof dict.
# Example::
#
#     from agent_identity.did.credentials import set_crypto_proof_hook
#
#     def my_signer(credential_data: dict) -> dict:
#         ...
#         return {"type": "Ed25519Signature2020", "proofValue": "..."}
#
#     set_crypto_proof_hook(my_signer)
#
_crypto_proof_hook: Any = None  # pragma: no cover


def set_crypto_proof_hook(hook: Any) -> None:  # pragma: no cover
    """Register a cryptographic proof hook for credential signing.

    This is the extension point for adding real cryptographic proofs to
    issued credentials. The hook is called during :meth:`CredentialIssuer.issue`
    and its return value is stored in ``credential.proof``.

    Parameters
    ----------
    hook:
        A callable that accepts a credential data dict and returns a proof dict.
    """
    global _crypto_proof_hook
    _crypto_proof_hook = hook


# ------------------------------------------------------------------
# CredentialIssuer
# ------------------------------------------------------------------


class CredentialIssuer:
    """Issues and revokes verifiable credentials for agent DIDs.

    This class handles the structural lifecycle of credentials (creation,
    tracking, revocation). Cryptographic signing is delegated to the
    registered proof hook (see :func:`set_crypto_proof_hook`).

    Example
    -------
    ::

        issuer = CredentialIssuer()
        credential = issuer.issue(
            issuer_did="did:agent:platform:ca",
            subject_did="did:agent:acme:worker",
            credential_type=CredentialType.CAPABILITY_CLAIM,
            claims={"capability": "data.read"},
        )
        print(issuer.is_revoked(credential.id))  # False
        issuer.revoke(credential.id)
        print(issuer.is_revoked(credential.id))  # True
    """

    def __init__(self) -> None:
        self._revoked: set[str] = set()

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def issue(
        self,
        issuer_did: str,
        subject_did: str,
        credential_type: CredentialType,
        claims: dict[str, Any],
        expiration_days: int | None = None,
    ) -> VerifiableCredential:
        """Issue a new verifiable credential.

        Parameters
        ----------
        issuer_did:
            DID of the agent issuing the credential.
        subject_did:
            DID of the agent the credential is about.
        credential_type:
            The domain-specific category for this credential.
        claims:
            Arbitrary claims to embed in the credential subject.
        expiration_days:
            If provided, the credential expires this many days from now.
            If ``None``, the credential does not expire.

        Returns
        -------
        VerifiableCredential
            A freshly created credential. If a proof hook is registered,
            the ``proof`` field will be populated; otherwise it is ``None``.
        """
        now = datetime.now(timezone.utc)
        expiration_date: datetime | None = None
        if expiration_days is not None:
            expiration_date = now + timedelta(days=expiration_days)

        credential_subject = CredentialSubject(id=subject_did, claims=dict(claims))

        credential = VerifiableCredential(
            type=["VerifiableCredential", credential_type.value],
            issuer=issuer_did,
            issuance_date=now,
            expiration_date=expiration_date,
            credential_subject=credential_subject,
            credential_type=credential_type,
        )

        # Extension point: populate proof if a crypto hook is registered
        if _crypto_proof_hook is not None:  # pragma: no cover
            proof = _crypto_proof_hook(json.loads(credential.to_json()))
            object.__setattr__(credential, "proof", proof)

        return credential

    # ------------------------------------------------------------------
    # Structure validation
    # ------------------------------------------------------------------

    def verify_structure(self, credential: VerifiableCredential) -> bool:
        """Validate the structural integrity of a credential.

        This method checks data completeness and internal consistency only.
        It does NOT perform cryptographic signature verification — that is
        an extension point (see :func:`set_crypto_proof_hook`).

        Parameters
        ----------
        credential:
            The credential to validate.

        Returns
        -------
        bool
            ``True`` if the credential is structurally valid.
        """
        if not credential.issuer:
            return False
        if not credential.credential_subject.id:
            return False
        if "VerifiableCredential" not in credential.type:
            return False
        if credential.expiration_date is not None:
            if credential.expiration_date <= credential.issuance_date:
                return False
        return True

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke(self, credential_id: str) -> None:
        """Revoke a credential by its ID.

        Revocation is in-memory only. For persistent revocation registries,
        call this method and then persist the revoked set externally.

        Parameters
        ----------
        credential_id:
            The ``id`` field of the credential to revoke.
        """
        self._revoked.add(credential_id)

    def is_revoked(self, credential_id: str) -> bool:
        """Return ``True`` if the credential has been revoked.

        Parameters
        ----------
        credential_id:
            The ``id`` field of the credential to check.

        Returns
        -------
        bool
        """
        return credential_id in self._revoked

    def revoked_credential_ids(self) -> list[str]:
        """Return a sorted list of all revoked credential IDs.

        Returns
        -------
        list[str]
        """
        return sorted(self._revoked)
