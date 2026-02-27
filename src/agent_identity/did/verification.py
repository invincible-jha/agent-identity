"""DIDVerifier — structural validation for DID documents and verifiable credentials.

This module provides verification that operates purely on data structure and
registered state. Cryptographic signature verification is an extension point
and is intentionally excluded from this module.

Verification flow
-----------------
1. :meth:`DIDVerifier.verify_document` — validates a :class:`~agent_identity.did.document.DIDDocument`
2. :meth:`DIDVerifier.verify_credential` — validates a :class:`~agent_identity.did.credentials.VerifiableCredential`
3. :meth:`DIDVerifier.verify_chain` — validates a sequence of credentials where
   each credential's subject is the issuer of the next
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from agent_identity.did.credentials import CredentialIssuer, VerifiableCredential
from agent_identity.did.document import DIDDocument, _DID_AGENT_PATTERN
from agent_identity.did.registry import DIDRegistry


# ------------------------------------------------------------------
# VerificationResult
# ------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of a verification operation.

    Parameters
    ----------
    valid:
        Overall pass/fail result. ``True`` only if ``checks_failed`` is empty.
    checks_passed:
        List of check names or descriptions that passed.
    checks_failed:
        List of check names or descriptions that failed.
    details:
        Arbitrary additional context about the verification run.
    """

    valid: bool
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Enforce consistency: valid iff no failed checks
        object.__setattr__(self, "valid", len(self.checks_failed) == 0)


def _build_result(
    passed: list[str],
    failed: list[str],
    details: dict[str, object] | None = None,
) -> VerificationResult:
    """Helper to construct a VerificationResult."""
    return VerificationResult(
        valid=len(failed) == 0,
        checks_passed=passed,
        checks_failed=failed,
        details=details or {},
    )


# ------------------------------------------------------------------
# DIDVerifier
# ------------------------------------------------------------------


class DIDVerifier:
    """Structural verifier for DID documents and verifiable credentials.

    All checks are deterministic and do not perform network I/O or
    cryptographic signature validation. Cryptographic verification is
    an extension point — implement it externally and call it alongside
    :meth:`verify_document` / :meth:`verify_credential`.

    Example
    -------
    ::

        verifier = DIDVerifier()
        result = verifier.verify_document(doc)
        if result.valid:
            print("Document is structurally valid")
        else:
            print("Failed checks:", result.checks_failed)
    """

    # ------------------------------------------------------------------
    # Document verification
    # ------------------------------------------------------------------

    def verify_document(self, document: DIDDocument) -> VerificationResult:
        """Validate a DID document's structural integrity.

        Checks performed
        ----------------
        - ``did_format_valid``       — ``id`` matches ``did:agent:<org>:<name>``
        - ``context_present``        — at least one context URI present
        - ``controller_present``     — controller field is non-empty
        - ``w3c_context_included``   — W3C DID v1 context URI is present
        - ``verification_methods_valid`` — all verification methods have non-empty fields
        - ``authentication_refs_valid``  — authentication refs point to declared methods
        - ``assertion_refs_valid``       — assertion_method refs point to declared methods

        Parameters
        ----------
        document:
            The DID document to verify.

        Returns
        -------
        VerificationResult
        """
        passed: list[str] = []
        failed: list[str] = []

        # Check 1: DID format
        if _DID_AGENT_PATTERN.match(document.id):
            passed.append("did_format_valid")
        else:
            failed.append("did_format_valid")

        # Check 2: context present
        if document.context:
            passed.append("context_present")
        else:
            failed.append("context_present")

        # Check 3: controller present
        controller = document.controller
        controller_present = bool(
            (isinstance(controller, list) and len(controller) > 0)
            or (isinstance(controller, str) and controller)
        )
        if controller_present:
            passed.append("controller_present")
        else:
            failed.append("controller_present")

        # Check 4: W3C DID context included
        w3c_context = "https://www.w3.org/ns/did/v1"
        if w3c_context in document.context:
            passed.append("w3c_context_included")
        else:
            failed.append("w3c_context_included")

        # Check 5: verification methods are well-formed
        method_ids: set[str] = set()
        methods_valid = True
        for vm in document.verification_method:
            if not vm.id or not vm.type or not vm.controller or not vm.public_key_multibase:
                methods_valid = False
                break
            method_ids.add(vm.id)

        if methods_valid:
            passed.append("verification_methods_valid")
        else:
            failed.append("verification_methods_valid")

        # Check 6: authentication references
        auth_valid = True
        if document.authentication and method_ids:
            for auth_ref in document.authentication:
                if auth_ref not in method_ids:
                    auth_valid = False
                    break
        if auth_valid:
            passed.append("authentication_refs_valid")
        else:
            failed.append("authentication_refs_valid")

        # Check 7: assertion_method references
        assert_valid = True
        if document.assertion_method and method_ids:
            for assert_ref in document.assertion_method:
                if assert_ref not in method_ids:
                    assert_valid = False
                    break
        if assert_valid:
            passed.append("assertion_refs_valid")
        else:
            failed.append("assertion_refs_valid")

        return _build_result(
            passed,
            failed,
            details={"did": document.id, "method_count": len(document.verification_method)},
        )

    # ------------------------------------------------------------------
    # Credential verification
    # ------------------------------------------------------------------

    def verify_credential(
        self,
        credential: VerifiableCredential,
        registry: DIDRegistry,
        issuer: CredentialIssuer | None = None,
    ) -> VerificationResult:
        """Validate a verifiable credential against the DID registry.

        Checks performed
        ----------------
        - ``structure_valid``    — credential has all required fields
        - ``issuer_registered``  — issuer DID is present in the registry
        - ``subject_registered`` — subject DID is present in the registry
        - ``not_expired``        — credential has not passed its expiration date
        - ``not_revoked``        — credential is not in the issuer's revocation list
        - ``base_type_present``  — ``"VerifiableCredential"`` is in the type list
        - ``issuer_not_deactivated`` — issuer DID is not deactivated

        Parameters
        ----------
        credential:
            The credential to verify.
        registry:
            The DID registry to look up issuer and subject DIDs.
        issuer:
            Optional :class:`~agent_identity.did.credentials.CredentialIssuer`
            instance to check revocation status. If ``None``, revocation
            checking is skipped.

        Returns
        -------
        VerificationResult
        """
        passed: list[str] = []
        failed: list[str] = []

        # Check 1: structural validity
        if (
            credential.issuer
            and credential.credential_subject.id
            and "VerifiableCredential" in credential.type
        ):
            passed.append("structure_valid")
        else:
            failed.append("structure_valid")

        # Check 2: base type present
        if "VerifiableCredential" in credential.type:
            passed.append("base_type_present")
        else:
            failed.append("base_type_present")

        # Check 3: issuer registered
        issuer_doc = registry.resolve(credential.issuer)
        if issuer_doc is not None:
            passed.append("issuer_registered")
        else:
            failed.append("issuer_registered")

        # Check 4: issuer not deactivated
        if not registry.is_deactivated(credential.issuer):
            passed.append("issuer_not_deactivated")
        else:
            failed.append("issuer_not_deactivated")

        # Check 5: subject registered
        subject_doc = registry.resolve(credential.credential_subject.id)
        if subject_doc is not None:
            passed.append("subject_registered")
        else:
            failed.append("subject_registered")

        # Check 6: not expired
        if not credential.is_expired():
            passed.append("not_expired")
        else:
            failed.append("not_expired")

        # Check 7: not revoked (only if issuer provided)
        if issuer is not None:
            if not issuer.is_revoked(credential.id):
                passed.append("not_revoked")
            else:
                failed.append("not_revoked")

        return _build_result(
            passed,
            failed,
            details={
                "credential_id": credential.id,
                "issuer": credential.issuer,
                "subject": credential.credential_subject.id,
                "credential_type": credential.credential_type.value,
            },
        )

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    def verify_chain(
        self,
        credentials: list[VerifiableCredential],
        registry: DIDRegistry,
        issuer: CredentialIssuer | None = None,
    ) -> VerificationResult:
        """Validate a chain of credentials for structural coherence.

        A valid chain satisfies these properties:
        - Each individual credential passes :meth:`verify_credential`
        - The subject of credential N is the issuer of credential N+1
          (subject-to-issuer linkage throughout the chain)
        - The chain is non-empty

        Parameters
        ----------
        credentials:
            An ordered list of credentials forming the chain. The first
            credential's issuer is the root; the last credential's subject
            is the terminal entity.
        registry:
            DID registry for issuer and subject lookups.
        issuer:
            Optional credential issuer for revocation checks on each link.

        Returns
        -------
        VerificationResult
        """
        passed: list[str] = []
        failed: list[str] = []

        # Check 1: chain is non-empty
        if not credentials:
            failed.append("chain_non_empty")
            return _build_result(passed, failed, details={"chain_length": 0})

        passed.append("chain_non_empty")

        # Check 2: each individual credential is valid
        all_valid = True
        for index, credential in enumerate(credentials):
            individual_result = self.verify_credential(credential, registry, issuer)
            if not individual_result.valid:
                all_valid = False
                failed.append(f"credential_{index}_valid")
            else:
                passed.append(f"credential_{index}_valid")

        if all_valid:
            passed.append("all_credentials_valid")
        else:
            failed.append("all_credentials_valid")

        # Check 3: subject-to-issuer linkage
        linkage_valid = True
        for index in range(len(credentials) - 1):
            current_subject = credentials[index].credential_subject.id
            next_issuer = credentials[index + 1].issuer
            if current_subject != next_issuer:
                linkage_valid = False
                failed.append(f"linkage_{index}_to_{index + 1}")
            else:
                passed.append(f"linkage_{index}_to_{index + 1}")

        if len(credentials) == 1 or linkage_valid:
            passed.append("chain_linkage_valid")
        else:
            failed.append("chain_linkage_valid")

        return _build_result(
            passed,
            failed,
            details={
                "chain_length": len(credentials),
                "root_issuer": credentials[0].issuer,
                "terminal_subject": credentials[-1].credential_subject.id,
            },
        )
