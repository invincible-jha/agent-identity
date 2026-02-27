"""CredentialRotator — schedule and execute API key/token rotation.

Tracks credential expiry windows and auto-rotates before expiry.
LeakageDetector checks whether credential values appear in log text or
agent outputs using simple string matching (no crypto required).
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RotationStatus(str, Enum):
    """Status of a credential's rotation state."""

    ACTIVE = "active"
    PENDING_ROTATION = "pending_rotation"
    ROTATED = "rotated"
    REVOKED = "revoked"
    LEAKED = "leaked"


@dataclass
class Credential:
    """A tracked credential with rotation metadata.

    Parameters
    ----------
    credential_id:
        Unique identifier for this credential.
    credential_type:
        Type label (e.g. ``"api_key"``, ``"bearer_token"``, ``"oauth_token"``).
    value:
        The credential value. Treat as sensitive.
    expires_at:
        UTC datetime when this credential expires. None means no expiry.
    rotation_before_hours:
        How many hours before expiry to trigger pre-emptive rotation.
        Defaults to 24.
    status:
        Current rotation status.
    created_at:
        UTC datetime when this credential was created.
    last_rotated_at:
        UTC datetime when last rotated. None if never rotated.
    metadata:
        Optional key-value metadata (e.g. ``{"service": "payment-api"}``).
    """

    credential_id: str
    credential_type: str
    value: str
    expires_at: Optional[datetime] = None
    rotation_before_hours: float = 24.0
    status: RotationStatus = RotationStatus.ACTIVE
    created_at: datetime = field(default_factory=_utcnow)
    last_rotated_at: Optional[datetime] = None
    metadata: dict[str, str] = field(default_factory=dict)

    def needs_rotation(self, now: Optional[datetime] = None) -> bool:
        """Return True if the credential should be rotated now.

        Rotation is triggered when:
        - The credential has already expired.
        - The credential expires within ``rotation_before_hours``.

        Parameters
        ----------
        now:
            Reference time (defaults to UTC now).

        Returns
        -------
        bool
            True if rotation is needed.
        """
        if self.status in (RotationStatus.REVOKED, RotationStatus.LEAKED):
            return False
        if self.expires_at is None:
            return False
        reference = now or _utcnow()
        rotation_trigger = self.expires_at - timedelta(hours=self.rotation_before_hours)
        return reference >= rotation_trigger

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Return True if this credential has already expired."""
        if self.expires_at is None:
            return False
        reference = now or _utcnow()
        return reference >= self.expires_at

    def to_dict(self, include_value: bool = False) -> dict[str, object]:
        """Serialise to a plain dictionary.

        Parameters
        ----------
        include_value:
            If False (default), the credential value is masked.
        """
        return {
            "credential_id": self.credential_id,
            "credential_type": self.credential_type,
            "value": self.value if include_value else "***REDACTED***",
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotation_before_hours": self.rotation_before_hours,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "last_rotated_at": (
                self.last_rotated_at.isoformat() if self.last_rotated_at else None
            ),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RotationResult:
    """Result of a credential rotation operation.

    Parameters
    ----------
    credential_id:
        The credential that was rotated.
    old_value:
        The previous credential value (masked by default).
    new_value:
        The new credential value (masked by default).
    rotated_at:
        UTC datetime of the rotation.
    success:
        Whether the rotation succeeded.
    error:
        Error message if rotation failed.
    """

    credential_id: str
    old_value: str
    new_value: str
    rotated_at: datetime
    success: bool
    error: str = ""

    def to_dict(self, include_values: bool = False) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "credential_id": self.credential_id,
            "old_value": self.old_value if include_values else "***",
            "new_value": self.new_value if include_values else "***",
            "rotated_at": self.rotated_at.isoformat(),
            "success": self.success,
            "error": self.error,
        }


def _generate_credential_value(length: int = 32) -> str:
    """Generate a random credential value using URL-safe characters."""
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class CredentialRotator:
    """Manages credential lifecycle with automatic pre-expiry rotation.

    Callers register credentials and optionally provide a rotation callback.
    When ``rotate_due()`` is called, all credentials that need rotation are
    processed and the callback (if provided) is invoked.

    Parameters
    ----------
    rotation_callback:
        Optional callable invoked with (credential_id, new_value) when
        rotation occurs. Use this to propagate the new value to external
        systems.
    default_rotation_before_hours:
        Default hours-before-expiry threshold for pre-emptive rotation.
    new_value_generator:
        Callable that generates new credential values. Defaults to the
        built-in random generator.
    """

    def __init__(
        self,
        rotation_callback: Optional[Callable[[str, str], None]] = None,
        default_rotation_before_hours: float = 24.0,
        new_value_generator: Optional[Callable[[], str]] = None,
    ) -> None:
        self._callback = rotation_callback
        self._default_rotation_before = default_rotation_before_hours
        self._generate = new_value_generator or _generate_credential_value
        self._credentials: dict[str, Credential] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, credential: Credential) -> None:
        """Register a credential for lifecycle management.

        Parameters
        ----------
        credential:
            The credential to track.

        Raises
        ------
        ValueError
            If a credential with the same ID is already registered.
        """
        if credential.credential_id in self._credentials:
            raise ValueError(
                f"Credential {credential.credential_id!r} is already registered."
            )
        self._credentials[credential.credential_id] = credential

    def revoke(self, credential_id: str) -> bool:
        """Mark a credential as revoked.

        Parameters
        ----------
        credential_id:
            The credential to revoke.

        Returns
        -------
        bool
            True if revoked, False if not found.
        """
        credential = self._credentials.get(credential_id)
        if credential is None:
            return False
        credential.status = RotationStatus.REVOKED
        return True

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    def rotate(
        self,
        credential_id: str,
        new_value: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> RotationResult:
        """Rotate a specific credential immediately.

        Parameters
        ----------
        credential_id:
            The credential to rotate.
        new_value:
            New value to assign. If None, generates one automatically.
        now:
            Reference time (defaults to UTC now).

        Returns
        -------
        RotationResult
            Outcome of the rotation operation.
        """
        credential = self._credentials.get(credential_id)
        reference = now or _utcnow()

        if credential is None:
            return RotationResult(
                credential_id=credential_id,
                old_value="",
                new_value="",
                rotated_at=reference,
                success=False,
                error=f"Credential {credential_id!r} not found.",
            )

        if credential.status == RotationStatus.REVOKED:
            return RotationResult(
                credential_id=credential_id,
                old_value=credential.value,
                new_value="",
                rotated_at=reference,
                success=False,
                error="Cannot rotate a revoked credential.",
            )

        old_value = credential.value
        generated_value = new_value or self._generate()
        credential.value = generated_value
        credential.status = RotationStatus.ROTATED
        credential.last_rotated_at = reference

        if self._callback:
            self._callback(credential_id, generated_value)

        return RotationResult(
            credential_id=credential_id,
            old_value=old_value,
            new_value=generated_value,
            rotated_at=reference,
            success=True,
        )

    def rotate_due(self, now: Optional[datetime] = None) -> list[RotationResult]:
        """Rotate all credentials that are due for rotation.

        Parameters
        ----------
        now:
            Reference time (defaults to UTC now).

        Returns
        -------
        list[RotationResult]
            One result per credential that was due for rotation.
        """
        reference = now or _utcnow()
        results: list[RotationResult] = []

        for credential_id, credential in self._credentials.items():
            if credential.needs_rotation(now=reference):
                result = self.rotate(credential_id, now=reference)
                results.append(result)

        return results

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get(self, credential_id: str) -> Optional[Credential]:
        """Return the credential with the given ID, or None."""
        return self._credentials.get(credential_id)

    def pending_rotation(self, now: Optional[datetime] = None) -> list[str]:
        """Return IDs of credentials that need rotation.

        Parameters
        ----------
        now:
            Reference time (defaults to UTC now).

        Returns
        -------
        list[str]
            Credential IDs due for rotation.
        """
        reference = now or _utcnow()
        return [
            cid
            for cid, credential in self._credentials.items()
            if credential.needs_rotation(now=reference)
        ]

    def all_credentials(self) -> list[Credential]:
        """Return all registered credentials."""
        return list(self._credentials.values())


# ---------------------------------------------------------------------------
# Leakage detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeakageResult:
    """Result of a credential leakage scan.

    Parameters
    ----------
    credential_id:
        The scanned credential.
    leaked:
        Whether the credential value was found in any scanned text.
    found_in:
        List of context snippets where the value was detected.
    scan_count:
        Number of text sources scanned.
    """

    credential_id: str
    leaked: bool
    found_in: list[str]
    scan_count: int

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "credential_id": self.credential_id,
            "leaked": self.leaked,
            "found_in_count": len(self.found_in),
            "scan_count": self.scan_count,
        }


class LeakageDetector:
    """Detects credential values appearing in log text or agent outputs.

    Uses simple string matching — the credential value is searched for as a
    substring in each scanned text. No external dependencies required.

    Parameters
    ----------
    min_value_length:
        Skip credentials whose value is shorter than this (to avoid false
        positives with very short values). Defaults to 8.
    """

    def __init__(self, min_value_length: int = 8) -> None:
        self._min_value_length = min_value_length

    def scan(
        self,
        credential: Credential,
        texts: list[str],
    ) -> LeakageResult:
        """Scan text sources for the credential value.

        Parameters
        ----------
        credential:
            The credential to search for.
        texts:
            List of text strings (logs, outputs, etc.) to scan.

        Returns
        -------
        LeakageResult
            Whether the credential value was found and where.
        """
        value = credential.value
        if len(value) < self._min_value_length:
            return LeakageResult(
                credential_id=credential.credential_id,
                leaked=False,
                found_in=[],
                scan_count=len(texts),
            )

        found_in: list[str] = []
        for text in texts:
            if value in text:
                # Return a snippet around the match
                idx = text.find(value)
                start = max(0, idx - 20)
                end = min(len(text), idx + len(value) + 20)
                snippet = text[start:end]
                found_in.append(snippet)

        return LeakageResult(
            credential_id=credential.credential_id,
            leaked=len(found_in) > 0,
            found_in=found_in,
            scan_count=len(texts),
        )

    def scan_multiple(
        self,
        credentials: list[Credential],
        texts: list[str],
    ) -> list[LeakageResult]:
        """Scan texts for multiple credentials.

        Parameters
        ----------
        credentials:
            List of credentials to check.
        texts:
            Text sources to scan.

        Returns
        -------
        list[LeakageResult]
            One result per credential.
        """
        return [self.scan(cred, texts) for cred in credentials]


__all__ = [
    "Credential",
    "CredentialRotator",
    "LeakageDetector",
    "LeakageResult",
    "RotationResult",
    "RotationStatus",
]
