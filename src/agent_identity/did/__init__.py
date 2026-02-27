"""agent_identity.did — W3C DID Core compliant decentralized identity for agents.

Implements the ``did:agent`` method following the W3C DID Core specification
(https://www.w3.org/TR/did-core/). This is a commodity implementation with
extension points for cryptographic verification plugins.

Submodules
----------
document
    DIDDocument, VerificationMethod, ServiceEndpoint, and DIDMethod constant.
registry
    DIDRegistry for in-memory storage with optional file persistence.
credentials
    VerifiableCredential, CredentialIssuer, CredentialSubject, CredentialType.
verification
    DIDVerifier and VerificationResult for structural validation.

Quick start
-----------
::

    from agent_identity.did import (
        DIDDocument,
        DIDRegistry,
        VerifiableCredential,
        CredentialIssuer,
        CredentialType,
        DIDVerifier,
    )

    # Create and register a DID document
    registry = DIDRegistry()
    doc = DIDDocument(
        id="did:agent:acme:invoicer",
        controller="did:agent:acme:invoicer",
    )
    registry.register(doc)

    # Issue a verifiable credential
    issuer = CredentialIssuer()
    credential = issuer.issue(
        issuer_did="did:agent:acme:invoicer",
        subject_did="did:agent:acme:worker",
        credential_type=CredentialType.CAPABILITY_CLAIM,
        claims={"capability": "invoice.read"},
    )

    # Verify the credential
    verifier = DIDVerifier()
    result = verifier.verify_credential(credential, registry)
    print(result.valid)  # True
"""
from __future__ import annotations

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
)
from agent_identity.did.registry import DIDRegistry
from agent_identity.did.verification import DIDVerifier, VerificationResult

__all__ = [
    # document
    "DID_METHOD",
    "DIDDocument",
    "ServiceEndpoint",
    "VerificationMethod",
    # registry
    "DIDRegistry",
    # credentials
    "CredentialIssuer",
    "CredentialSubject",
    "CredentialType",
    "VerifiableCredential",
    # verification
    "DIDVerifier",
    "VerificationResult",
]
