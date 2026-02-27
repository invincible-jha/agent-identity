"""DIDRegistry — in-memory DID document store with optional file persistence.

Stores :class:`~agent_identity.did.document.DIDDocument` objects keyed by
their ``id`` field. All public methods are thread-safe via a single
:class:`threading.Lock`.

The registry supports import/export to a newline-delimited JSON file (one
document per line) for simple file-based persistence, suitable for
development and testing scenarios.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from agent_identity.did.document import DIDDocument


class DIDRegistryError(Exception):
    """Base exception for DIDRegistry errors."""


class DIDAlreadyRegisteredError(DIDRegistryError):
    """Raised when attempting to register a DID that already exists."""

    def __init__(self, did: str) -> None:
        super().__init__(
            f"DID {did!r} is already registered. "
            "Use update() to replace an existing document."
        )


class DIDNotFoundError(DIDRegistryError):
    """Raised when a DID is not present in the registry."""

    def __init__(self, did: str) -> None:
        super().__init__(f"DID {did!r} is not registered in this registry.")


class DIDRegistry:
    """In-memory registry for DID documents with optional file persistence.

    All mutations acquire a lock before modifying the internal store, making
    this class safe for use in multithreaded environments.

    Parameters
    ----------
    (none) — instantiate with no arguments for a fresh in-memory registry.

    Example
    -------
    ::

        registry = DIDRegistry()
        doc = DIDDocument(id="did:agent:acme:bot", controller="did:agent:acme:bot")
        did = registry.register(doc)
        resolved = registry.resolve(did)
        print(resolved.id)  # "did:agent:acme:bot"
    """

    def __init__(self) -> None:
        self._documents: dict[str, DIDDocument] = {}
        self._deactivated: set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(self, document: DIDDocument) -> str:
        """Register a new DID document in the registry.

        Parameters
        ----------
        document:
            The DID document to register. ``document.id`` is used as the key.

        Returns
        -------
        str
            The DID string that was registered (``document.id``).

        Raises
        ------
        DIDAlreadyRegisteredError
            If a document with the same DID is already registered.
        """
        with self._lock:
            if document.id in self._documents:
                raise DIDAlreadyRegisteredError(document.id)
            self._documents[document.id] = document
        return document.id

    def resolve(self, did: str) -> DIDDocument | None:
        """Look up a DID document by its DID string.

        Parameters
        ----------
        did:
            The fully-qualified DID to look up.

        Returns
        -------
        DIDDocument | None
            The stored document, or ``None`` if the DID is not registered.
            Deactivated DIDs are still returned — callers that need to
            enforce deactivation policy should also check
            :meth:`is_deactivated`.
        """
        with self._lock:
            return self._documents.get(did)

    def update(self, did: str, document: DIDDocument) -> bool:
        """Replace the document stored for an existing DID.

        The incoming ``document.id`` must match ``did``.

        Parameters
        ----------
        did:
            The DID whose document should be replaced.
        document:
            The new DID document. Its ``id`` must equal ``did``.

        Returns
        -------
        bool
            ``True`` if the update succeeded, ``False`` if the DID is not
            registered.

        Raises
        ------
        ValueError
            If ``document.id`` does not match ``did``.
        """
        if document.id != did:
            raise ValueError(
                f"document.id {document.id!r} does not match the target DID {did!r}."
            )
        with self._lock:
            if did not in self._documents:
                return False
            self._documents[did] = document
        return True

    def deactivate(self, did: str) -> bool:
        """Mark a DID as deactivated (soft-delete).

        The document is retained in the registry but flagged as deactivated.
        :meth:`resolve` still returns the document; callers should check
        :meth:`is_deactivated` when they need to enforce deactivation policy.

        Parameters
        ----------
        did:
            The DID to deactivate.

        Returns
        -------
        bool
            ``True`` if the DID was found and marked deactivated,
            ``False`` if the DID is not registered.
        """
        with self._lock:
            if did not in self._documents:
                return False
            self._deactivated.add(did)
        return True

    def is_deactivated(self, did: str) -> bool:
        """Return ``True`` if the DID has been deactivated.

        Parameters
        ----------
        did:
            The DID to check.

        Returns
        -------
        bool
        """
        with self._lock:
            return did in self._deactivated

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def list_dids(self) -> list[str]:
        """Return a sorted list of all registered DID strings.

        Includes deactivated DIDs.

        Returns
        -------
        list[str]
            Sorted list of DID strings.
        """
        with self._lock:
            return sorted(self._documents.keys())

    def search(
        self,
        org: str | None = None,
        name: str | None = None,
    ) -> list[DIDDocument]:
        """Search for DID documents by org and/or name segments.

        Parameters
        ----------
        org:
            If provided, only documents whose DID org segment matches
            (exact, case-sensitive) are returned.
        name:
            If provided, only documents whose DID name segment matches
            (exact, case-sensitive) are returned.

        Returns
        -------
        list[DIDDocument]
            Matching documents sorted by DID string.
        """
        with self._lock:
            candidates = list(self._documents.values())

        results: list[DIDDocument] = []
        for doc in candidates:
            try:
                doc_org = doc.org()
                doc_name = doc.name()
            except ValueError:
                continue
            if org is not None and doc_org != org:
                continue
            if name is not None and doc_name != name:
                continue
            results.append(doc)

        return sorted(results, key=lambda d: d.id)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def export_registry(self, path: Path) -> None:
        """Export all registered documents to a JSON file.

        Each document is serialized as a JSON object on its own line
        (newline-delimited JSON / NDJSON format).

        Parameters
        ----------
        path:
            File path to write. The file is created or overwritten.
        """
        with self._lock:
            docs = list(self._documents.values())
            deactivated = set(self._deactivated)

        lines: list[str] = []
        for doc in sorted(docs, key=lambda d: d.id):
            entry = json.loads(doc.to_json())
            entry["_deactivated"] = doc.id in deactivated
            lines.append(json.dumps(entry))

        path.write_text("\n".join(lines), encoding="utf-8")

    def import_registry(self, path: Path) -> None:
        """Import documents from a previously exported registry file.

        Existing entries are retained; imported entries with duplicate
        DIDs are silently skipped.

        Parameters
        ----------
        path:
            Path to the NDJSON file produced by :meth:`export_registry`.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ValueError
            If a line cannot be parsed as a valid DID document.
        """
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {exc}"
                ) from exc
            try:
                deactivated_flag: bool = entry.pop("_deactivated", False)
                doc = DIDDocument.from_json(json.dumps(entry))
            except KeyError as exc:
                raise ValueError(
                    f"Missing required field on line {line_number}: {exc}"
                ) from exc
            except (TypeError, AttributeError) as exc:
                raise ValueError(
                    f"Invalid data structure on line {line_number}: {exc}"
                ) from exc
            with self._lock:
                if doc.id not in self._documents:
                    self._documents[doc.id] = doc
                    if deactivated_flag:
                        self._deactivated.add(doc.id)

    def __len__(self) -> int:
        """Return the number of registered documents (including deactivated)."""
        with self._lock:
            return len(self._documents)

    def __contains__(self, did: object) -> bool:
        """Support ``"did:agent:org:name" in registry`` membership test."""
        with self._lock:
            return did in self._documents
