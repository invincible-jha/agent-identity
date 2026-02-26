"""Certificate storage — abstract interface and filesystem implementation.

CertStore defines the storage contract. FilesystemCertStore persists
certificates as PEM files under a configurable base directory, organized
by agent_id.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from agent_identity.certificates.agent_cert import AgentCertificate


class CertStore(ABC):
    """Abstract base class for certificate storage backends."""

    @abstractmethod
    def save(self, cert: AgentCertificate) -> None:
        """Persist a certificate.

        Parameters
        ----------
        cert:
            The certificate to store.
        """

    @abstractmethod
    def load(self, agent_id: str) -> AgentCertificate:
        """Retrieve a certificate by agent ID.

        Parameters
        ----------
        agent_id:
            The agent whose certificate should be loaded.

        Returns
        -------
        AgentCertificate
            The stored certificate.

        Raises
        ------
        KeyError
            If no certificate is stored for the given agent_id.
        """

    @abstractmethod
    def delete(self, agent_id: str) -> None:
        """Remove a certificate from storage.

        Parameters
        ----------
        agent_id:
            The agent whose certificate should be removed.

        Raises
        ------
        KeyError
            If no certificate exists for the given agent_id.
        """

    @abstractmethod
    def list_agents(self) -> list[str]:
        """Return a list of all agent IDs with stored certificates."""

    @abstractmethod
    def exists(self, agent_id: str) -> bool:
        """Return True if a certificate exists for the given agent_id."""


class FilesystemCertStore(CertStore):
    """Filesystem-backed certificate storage.

    Certificates are stored under *base_dir* as per-agent subdirectories
    containing ``cert.pem``, ``key.pem``, and ``meta.json``.

    Parameters
    ----------
    base_dir:
        Root directory for certificate storage.
    """

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # CertStore interface
    # ------------------------------------------------------------------

    def save(self, cert: AgentCertificate) -> None:
        """Write certificate PEM files and metadata JSON to disk."""
        agent_dir = self._agent_dir(cert.agent_id)
        agent_dir.mkdir(parents=True, exist_ok=True)

        (agent_dir / "cert.pem").write_bytes(cert.cert_pem)
        (agent_dir / "key.pem").write_bytes(cert.key_pem)

        meta = {
            "agent_id": cert.agent_id,
            "organization": cert.organization,
            "capabilities": cert.capabilities,
            "trust_level": cert.trust_level,
            "serial_number": cert.serial_number,
            "not_before": cert.not_before.isoformat(),
            "not_after": cert.not_after.isoformat(),
        }
        (agent_dir / "meta.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )

    def load(self, agent_id: str) -> AgentCertificate:
        """Read a certificate from disk.

        Raises
        ------
        KeyError
            If no certificate directory exists for *agent_id*.
        """
        agent_dir = self._agent_dir(agent_id)
        if not agent_dir.exists():
            raise KeyError(f"No certificate stored for agent_id={agent_id!r}")

        import datetime

        cert_pem = (agent_dir / "cert.pem").read_bytes()
        key_pem_path = agent_dir / "key.pem"
        key_pem = key_pem_path.read_bytes() if key_pem_path.exists() else b""
        meta = json.loads((agent_dir / "meta.json").read_text(encoding="utf-8"))

        return AgentCertificate(
            agent_id=meta["agent_id"],
            organization=meta["organization"],
            capabilities=meta["capabilities"],
            trust_level=meta["trust_level"],
            cert_pem=cert_pem,
            key_pem=key_pem,
            serial_number=meta["serial_number"],
            not_before=datetime.datetime.fromisoformat(meta["not_before"]),
            not_after=datetime.datetime.fromisoformat(meta["not_after"]),
        )

    def delete(self, agent_id: str) -> None:
        """Remove all certificate files for an agent.

        Raises
        ------
        KeyError
            If no certificate directory exists for *agent_id*.
        """
        agent_dir = self._agent_dir(agent_id)
        if not agent_dir.exists():
            raise KeyError(f"No certificate stored for agent_id={agent_id!r}")

        for file in agent_dir.iterdir():
            file.unlink()
        agent_dir.rmdir()

    def list_agents(self) -> list[str]:
        """Return sorted list of agent IDs with stored certificates."""
        return sorted(
            d.name for d in self._base_dir.iterdir() if d.is_dir()
        )

    def exists(self, agent_id: str) -> bool:
        """Return True if a certificate directory exists for *agent_id*."""
        return self._agent_dir(agent_id).exists()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _agent_dir(self, agent_id: str) -> Path:
        """Return the directory path for a given agent_id."""
        safe_name = agent_id.replace("/", "_").replace("\\", "_")
        return self._base_dir / safe_name
