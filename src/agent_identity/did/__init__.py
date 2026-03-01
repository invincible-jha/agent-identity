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

# did:key support — requires the cryptography package (pip install agent-identity[crypto])
try:
    from agent_identity.did.did_key import (
        DIDKeyDocument,
        DIDKeyProvider,
        _public_key_to_did,
        _validate_did_key_format,
    )
    from agent_identity.did.key_manager import Ed25519KeyManager

    _DID_KEY_AVAILABLE = True
except ImportError:
    _DID_KEY_AVAILABLE = False

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
    # did:key (conditionally available — requires cryptography package)
    "DIDKeyDocument",
    "DIDKeyProvider",
    "Ed25519KeyManager",
    "_public_key_to_did",
    "_validate_did_key_format",
    "_DID_KEY_AVAILABLE",
]
