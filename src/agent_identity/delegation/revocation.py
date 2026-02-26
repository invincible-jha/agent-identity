"""DelegationRevocation — revocation management for delegation tokens.

Maintains an in-memory set of revoked token IDs. Supports cascading revocation
of an entire chain rooted at a given token via integration with DelegationChain.
"""
from __future__ import annotations

import threading


class DelegationRevocation:
    """Manages revocation of delegation tokens.

    Thread-safe. Revoked token IDs are stored in memory; for persistence,
    callers should serialise the result of :meth:`revoked_token_ids` and
    restore via :meth:`restore`.
    """

    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def revoke(self, token_id: str) -> None:
        """Revoke a single delegation token by ID.

        Parameters
        ----------
        token_id:
            The ID of the token to revoke.
        """
        with self._lock:
            self._revoked.add(token_id)

    def revoke_chain(
        self,
        token_id: str,
        all_token_ids: list[str],
        parent_map: dict[str, str | None],
    ) -> list[str]:
        """Revoke a token and all tokens that descend from it.

        Walks ``all_token_ids`` and revokes any token whose ancestor chain
        includes ``token_id``.

        Parameters
        ----------
        token_id:
            The root token ID to start cascading revocation from.
        all_token_ids:
            Complete list of token IDs to consider for cascading revocation.
        parent_map:
            Mapping of token_id -> parent_token_id (None for roots).

        Returns
        -------
        list[str]
            Sorted list of all token IDs that were revoked in this call.
        """
        revoked_now: list[str] = []

        def is_descendant(candidate: str) -> bool:
            """Return True if candidate is a descendant of token_id."""
            current: str | None = candidate
            while current is not None:
                if current == token_id:
                    return True
                current = parent_map.get(current)
            return False

        with self._lock:
            for tid in all_token_ids:
                if tid not in self._revoked and is_descendant(tid):
                    self._revoked.add(tid)
                    revoked_now.append(tid)

        return sorted(revoked_now)

    def unrevoke(self, token_id: str) -> None:
        """Remove a token from the revocation list.

        This is an administrative override — use with caution.

        Parameters
        ----------
        token_id:
            The ID of the token to unrevoke.
        """
        with self._lock:
            self._revoked.discard(token_id)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def is_revoked(self, token_id: str) -> bool:
        """Return True if the given token has been revoked.

        Parameters
        ----------
        token_id:
            The token ID to check.

        Returns
        -------
        bool
        """
        with self._lock:
            return token_id in self._revoked

    def revoked_token_ids(self) -> frozenset[str]:
        """Return a snapshot of all currently revoked token IDs."""
        with self._lock:
            return frozenset(self._revoked)

    def count(self) -> int:
        """Return the number of revoked tokens."""
        with self._lock:
            return len(self._revoked)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def restore(self, token_ids: list[str]) -> None:
        """Restore a previously serialised revocation set.

        Parameters
        ----------
        token_ids:
            List of token IDs to mark as revoked.
        """
        with self._lock:
            self._revoked.update(token_ids)
