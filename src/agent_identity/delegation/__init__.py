"""Capability delegation between agents.

Provides cryptographically signed delegation tokens that carry scoped
capabilities from an issuing agent to a delegate agent. Delegation chains
enforce scope narrowing: a delegate may never hold more authority than
the issuing ancestor.

Quick start
-----------
::

    from agent_identity.delegation import (
        DelegationToken,
        DelegationChain,
        DelegationRevocation,
    )

    secret = b"shared-signing-secret"

    root_token = DelegationToken.create_token(
        issuer_id="agent-a",
        delegate_id="agent-b",
        scopes=["read", "write"],
        secret_key=secret,
    )

    chain = DelegationChain()
    chain.add_delegation(root_token)

    revocation = DelegationRevocation()
    print(revocation.is_revoked(root_token.token_id))  # False
"""
from __future__ import annotations

from agent_identity.delegation.chain import DelegationChain, DelegationChainError
from agent_identity.delegation.revocation import DelegationRevocation
from agent_identity.delegation.token import DelegationToken

__all__ = [
    "DelegationChain",
    "DelegationChainError",
    "DelegationRevocation",
    "DelegationToken",
]
