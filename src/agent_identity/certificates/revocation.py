"""Certificate Revocation List (CRL) management.

Maintains an in-memory and optionally persisted list of revoked certificate
serial numbers. Revocation checks are performed before trusting any
certificate presented during verification.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path


class RevocationList:
    """Manages revoked certificate serial numbers.

    Thread-safe implementation that stores revoked serials in memory with
    optional JSON persistence to disk.

    Parameters
    ----------
    persist_path:
        If provided, revocations are read from and written to this JSON file.
    """

    def __init__(self, persist_path: Path | None = None) -> None:
        self._revoked: set[int] = set()
        self._lock = threading.Lock()
        self._persist_path = persist_path

        if persist_path is not None and persist_path.exists():
            self._load_from_disk()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def revoke_cert(self, serial_number: int, reason: str = "unspecified") -> None:
        """Revoke a certificate by serial number.

        Parameters
        ----------
        serial_number:
            The certificate serial number to revoke.
        reason:
            Human-readable revocation reason (informational only).
        """
        with self._lock:
            self._revoked.add(serial_number)
            if self._persist_path is not None:
                self._save_to_disk()

    def unrevoke_cert(self, serial_number: int) -> None:
        """Remove a serial from the revocation list.

        This is an administrative operation — use with caution.

        Parameters
        ----------
        serial_number:
            The certificate serial number to unrevoke.
        """
        with self._lock:
            self._revoked.discard(serial_number)
            if self._persist_path is not None:
                self._save_to_disk()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def is_revoked(self, serial_number: int) -> bool:
        """Return True if the given serial number has been revoked.

        Parameters
        ----------
        serial_number:
            The serial number to check.

        Returns
        -------
        bool
            True if revoked, False otherwise.
        """
        with self._lock:
            return serial_number in self._revoked

    def revoked_serials(self) -> frozenset[int]:
        """Return a snapshot of all revoked serial numbers."""
        with self._lock:
            return frozenset(self._revoked)

    def count(self) -> int:
        """Return the number of revoked certificates."""
        with self._lock:
            return len(self._revoked)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_to_disk(self) -> None:
        """Write revoked serials to the persist path as JSON."""
        if self._persist_path is None:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"revoked_serials": sorted(self._revoked)}
        self._persist_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load_from_disk(self) -> None:
        """Read revoked serials from the persist path."""
        if self._persist_path is None or not self._persist_path.exists():
            return
        try:
            payload = json.loads(self._persist_path.read_text(encoding="utf-8"))
            self._revoked = set(payload.get("revoked_serials", []))
        except (json.JSONDecodeError, KeyError):
            self._revoked = set()
