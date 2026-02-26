"""DelegationChain — tracks and validates chains of delegation tokens.

A delegation chain starts with a root token (no parent) and extends through
sub-delegations. Each hop in the chain must not claim scopes that the parent
token did not hold (scope narrowing). A configurable maximum depth prevents
runaway chain growth.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from agent_identity.delegation.token import DelegationToken


class DelegationChainError(Exception):
    """Raised when a delegation chain constraint is violated."""


@dataclass
class ChainEntry:
    """A single link in a delegation chain.

    Parameters
    ----------
    token:
        The delegation token at this chain position.
    depth:
        Zero-based depth of this token in the chain (root = 0).
    """

    token: DelegationToken
    depth: int


class DelegationChain:
    """Tracks and validates chains of delegation tokens.

    Tokens are stored keyed by their ``token_id``. A root token has no
    ``parent_token_id``. Sub-delegations reference a parent that must
    already exist in this chain.

    Scope narrowing is enforced: a child token's scopes must be a subset
    of its parent's scopes.

    Parameters
    ----------
    max_depth:
        Maximum allowed chain depth (number of hops from root). Defaults to 5.
    """

    def __init__(self, max_depth: int = 5) -> None:
        self._max_depth = max_depth
        self._tokens: dict[str, DelegationToken] = {}
        self._depths: dict[str, int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_delegation(self, token: DelegationToken) -> None:
        """Add a delegation token to the chain.

        Root tokens (``parent_token_id`` is None) are inserted at depth 0.
        Sub-delegation tokens must reference an existing parent token and
        may not claim scopes not present in the parent.

        Parameters
        ----------
        token:
            The DelegationToken to add.

        Raises
        ------
        DelegationChainError
            If the parent token is not found, if scope narrowing is violated,
            or if the maximum chain depth would be exceeded.
        ValueError
            If a token with the same ``token_id`` already exists in the chain.
        """
        with self._lock:
            if token.token_id in self._tokens:
                raise ValueError(
                    f"Token {token.token_id!r} is already present in this chain."
                )

            if token.parent_token_id is None:
                depth = 0
            else:
                if token.parent_token_id not in self._tokens:
                    raise DelegationChainError(
                        f"Parent token {token.parent_token_id!r} not found in chain."
                    )
                parent = self._tokens[token.parent_token_id]
                depth = self._depths[parent.token_id] + 1

                if depth > self._max_depth:
                    raise DelegationChainError(
                        f"Max delegation chain depth ({self._max_depth}) would be "
                        f"exceeded at depth {depth}."
                    )

                parent_scopes = set(parent.scopes)
                child_scopes = set(token.scopes)
                excess = child_scopes - parent_scopes
                if excess:
                    raise DelegationChainError(
                        f"Child token claims scopes not present in parent: {excess!r}. "
                        "Delegation may not expand scopes."
                    )

            self._tokens[token.token_id] = token
            self._depths[token.token_id] = depth

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_chain(self, token_id: str) -> list[DelegationToken]:
        """Return the full delegation chain from root to the given token.

        Parameters
        ----------
        token_id:
            The token at the end (leaf) of the chain to retrieve.

        Returns
        -------
        list[DelegationToken]
            Ordered from root to the specified token (inclusive).

        Raises
        ------
        KeyError
            If ``token_id`` is not present in this chain.
        """
        with self._lock:
            if token_id not in self._tokens:
                raise KeyError(f"Token {token_id!r} not found in chain.")
            return self._build_chain(token_id)

    def _build_chain(self, token_id: str) -> list[DelegationToken]:
        """Walk parent links from the leaf up to root and return root-first list."""
        chain: list[DelegationToken] = []
        current_id: str | None = token_id
        while current_id is not None:
            token = self._tokens[current_id]
            chain.append(token)
            current_id = token.parent_token_id
        chain.reverse()
        return chain

    def effective_scopes(self, token_id: str) -> frozenset[str]:
        """Compute the effective scopes for a token by intersecting the full chain.

        The effective scopes at any point in a chain are the intersection of all
        ancestor tokens' scopes. This guarantees that a delegate can never hold
        more authority than any of its delegating ancestors.

        Parameters
        ----------
        token_id:
            The token to compute effective scopes for.

        Returns
        -------
        frozenset[str]
            The intersection of all scopes along the chain from root to token.

        Raises
        ------
        KeyError
            If ``token_id`` is not present in this chain.
        """
        chain = self.get_chain(token_id)
        if not chain:
            return frozenset()

        scope_sets = [frozenset(t.scopes) for t in chain]
        result = scope_sets[0]
        for scope_set in scope_sets[1:]:
            result = result & scope_set
        return result

    def get_depth(self, token_id: str) -> int:
        """Return the depth of a token in the chain (root = 0).

        Parameters
        ----------
        token_id:
            The token to query.

        Raises
        ------
        KeyError
            If ``token_id`` is not present.
        """
        with self._lock:
            if token_id not in self._depths:
                raise KeyError(f"Token {token_id!r} not found in chain.")
            return self._depths[token_id]

    def token_ids(self) -> list[str]:
        """Return sorted list of all token IDs in this chain."""
        with self._lock:
            return sorted(self._tokens.keys())

    def __len__(self) -> int:
        """Return the number of tokens tracked by this chain."""
        with self._lock:
            return len(self._tokens)
