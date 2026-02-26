"""agent-identity — Agent identity management, trust scoring, and certificate management.

Public API
----------
The stable public surface is everything exported from this module.
Anything inside submodules not re-exported here is considered private
and may change without notice.

Example
-------
>>> import agent_identity
>>> agent_identity.__version__
'0.1.0'

Quick start
-----------
::

    from agent_identity import (
        # Trust
        TrustScorer, TrustScore, TrustHistory, TrustLevel, TrustPolicy, TrustDimension,
        # Registry
        IdentityRegistry, AgentIdentityRecord, DIDProvider,
        # Delegation
        DelegationToken, DelegationChain, DelegationRevocation,
        # Middleware
        AuthMiddleware, RBACMiddleware, IdentityAuditLogger,
        # Certificates
        CertificateAuthority, AgentCertificate,
    )
"""
from __future__ import annotations

__version__: str = "0.1.0"

# ------------------------------------------------------------------
# Trust subsystem
# ------------------------------------------------------------------
from agent_identity.trust.dimensions import TrustDimension
from agent_identity.trust.history import TrustHistory
from agent_identity.trust.level import TrustLevel, derive_level
from agent_identity.trust.policy import TrustPolicy
from agent_identity.trust.scorer import TrustScore, TrustScorer

# ------------------------------------------------------------------
# Registry subsystem
# ------------------------------------------------------------------
from agent_identity.registry.did import DIDDocument, DIDProvider, DIDResolutionError
from agent_identity.registry.identity_registry import (
    AgentAlreadyRegisteredError,
    AgentIdentityRecord,
    AgentNotFoundError,
    IdentityRegistry,
)

# ------------------------------------------------------------------
# Delegation subsystem
# ------------------------------------------------------------------
from agent_identity.delegation.chain import DelegationChain, DelegationChainError
from agent_identity.delegation.revocation import DelegationRevocation
from agent_identity.delegation.token import DelegationToken

# ------------------------------------------------------------------
# Middleware subsystem
# ------------------------------------------------------------------
from agent_identity.middleware.audit import AuditEvent, IdentityAuditLogger
from agent_identity.middleware.auth import AuthMechanism, AuthMiddleware, AuthResult
from agent_identity.middleware.rbac import BUILTIN_ROLES, PrivilegeLevel, RBACMiddleware, Role

# ------------------------------------------------------------------
# Certificate subsystem (optional — cryptography package required)
# ------------------------------------------------------------------
try:
    from agent_identity.certificates.agent_cert import AgentCertificate
    from agent_identity.certificates.ca import CertificateAuthority
    from agent_identity.certificates.revocation import RevocationList
    from agent_identity.certificates.store import CertStore, FilesystemCertStore
    from agent_identity.certificates.verifier import CertVerifier

    _CERTS_AVAILABLE = True
except ImportError:
    _CERTS_AVAILABLE = False

# ------------------------------------------------------------------
# Behavioral subsystem
# ------------------------------------------------------------------
from agent_identity.behavioral.fingerprint import BehavioralFingerprint
from agent_identity.behavioral.features import FeatureExtractor, Observation

__all__ = [
    # version
    "__version__",
    # trust
    "TrustDimension",
    "TrustHistory",
    "TrustLevel",
    "TrustPolicy",
    "TrustScore",
    "TrustScorer",
    "derive_level",
    # registry
    "AgentAlreadyRegisteredError",
    "AgentIdentityRecord",
    "AgentNotFoundError",
    "DIDDocument",
    "DIDProvider",
    "DIDResolutionError",
    "IdentityRegistry",
    # delegation
    "DelegationChain",
    "DelegationChainError",
    "DelegationRevocation",
    "DelegationToken",
    # middleware
    "AuditEvent",
    "AuthMechanism",
    "AuthMiddleware",
    "AuthResult",
    "BUILTIN_ROLES",
    "IdentityAuditLogger",
    "PrivilegeLevel",
    "RBACMiddleware",
    "Role",
    # certificates (conditionally available)
    "AgentCertificate",
    "CertificateAuthority",
    "CertStore",
    "CertVerifier",
    "FilesystemCertStore",
    "RevocationList",
    # behavioral
    "BehavioralFingerprint",
    "FeatureExtractor",
    "Observation",
]
