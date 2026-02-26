"""Tests for agent_identity.certificates.store — FilesystemCertStore."""
from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from agent_identity.certificates.agent_cert import AgentCertificate
from agent_identity.certificates.ca import CertificateAuthority
from agent_identity.certificates.store import FilesystemCertStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    return CertificateAuthority.generate_ca()


@pytest.fixture()
def base_dir(tmp_path: Path) -> Path:
    return tmp_path / "cert-store"


@pytest.fixture()
def store(base_dir: Path) -> FilesystemCertStore:
    return FilesystemCertStore(base_dir=base_dir)


@pytest.fixture()
def agent_cert(ca: CertificateAuthority) -> AgentCertificate:
    return ca.sign_agent_cert(
        agent_id="agent-store-001",
        organization="TestOrg",
        capabilities=["read", "write"],
        trust_level=2,
        validity_days=365,
    )


@pytest.fixture()
def agent_cert_2(ca: CertificateAuthority) -> AgentCertificate:
    return ca.sign_agent_cert(
        agent_id="agent-store-002",
        organization="OtherOrg",
        capabilities=["execute"],
        trust_level=3,
        validity_days=90,
    )


# ---------------------------------------------------------------------------
# FilesystemCertStore — initialisation
# ---------------------------------------------------------------------------


class TestStoreInit:
    def test_creates_base_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "store"
        assert not target.exists()
        FilesystemCertStore(base_dir=target)
        assert target.is_dir()

    def test_accepts_existing_directory(self, tmp_path: Path) -> None:
        FilesystemCertStore(base_dir=tmp_path)  # must not raise


# ---------------------------------------------------------------------------
# FilesystemCertStore — save
# ---------------------------------------------------------------------------


class TestSave:
    def test_save_creates_agent_directory(
        self, store: FilesystemCertStore, base_dir: Path, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        agent_dir = base_dir / "agent-store-001"
        assert agent_dir.is_dir()

    def test_save_writes_cert_pem(
        self, store: FilesystemCertStore, base_dir: Path, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        cert_file = base_dir / "agent-store-001" / "cert.pem"
        assert cert_file.exists()
        assert cert_file.read_bytes() == agent_cert.cert_pem

    def test_save_writes_key_pem(
        self, store: FilesystemCertStore, base_dir: Path, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        key_file = base_dir / "agent-store-001" / "key.pem"
        assert key_file.exists()
        assert key_file.read_bytes() == agent_cert.key_pem

    def test_save_writes_meta_json(
        self, store: FilesystemCertStore, base_dir: Path, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        meta_file = base_dir / "agent-store-001" / "meta.json"
        assert meta_file.exists()


# ---------------------------------------------------------------------------
# FilesystemCertStore — load
# ---------------------------------------------------------------------------


class TestLoad:
    def test_load_returns_correct_agent_cert(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        loaded = store.load("agent-store-001")
        assert loaded.agent_id == "agent-store-001"
        assert loaded.organization == "TestOrg"
        assert loaded.capabilities == ["read", "write"]
        assert loaded.trust_level == 2

    def test_load_cert_pem_matches(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        loaded = store.load("agent-store-001")
        assert loaded.cert_pem == agent_cert.cert_pem

    def test_load_serial_number_matches(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        loaded = store.load("agent-store-001")
        assert loaded.serial_number == agent_cert.serial_number

    def test_load_not_before_matches(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        loaded = store.load("agent-store-001")
        # Compare as seconds-precision since ISO round-trip may lose sub-second precision
        assert abs((loaded.not_before - agent_cert.not_before).total_seconds()) < 1.0

    def test_load_raises_for_unknown_agent(
        self, store: FilesystemCertStore
    ) -> None:
        with pytest.raises(KeyError, match="agent_id"):
            store.load("ghost-agent")

    def test_load_without_key_pem(
        self, store: FilesystemCertStore, base_dir: Path, agent_cert: AgentCertificate
    ) -> None:
        """Load should succeed when key.pem is absent (key stored separately)."""
        store.save(agent_cert)
        (base_dir / "agent-store-001" / "key.pem").unlink()
        loaded = store.load("agent-store-001")
        assert loaded.key_pem == b""


# ---------------------------------------------------------------------------
# FilesystemCertStore — delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_removes_agent_directory(
        self, store: FilesystemCertStore, base_dir: Path, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        store.delete("agent-store-001")
        assert not (base_dir / "agent-store-001").exists()

    def test_delete_raises_for_unknown_agent(
        self, store: FilesystemCertStore
    ) -> None:
        with pytest.raises(KeyError):
            store.delete("nobody")

    def test_load_after_delete_raises(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        store.delete("agent-store-001")
        with pytest.raises(KeyError):
            store.load("agent-store-001")


# ---------------------------------------------------------------------------
# FilesystemCertStore — exists
# ---------------------------------------------------------------------------


class TestExists:
    def test_exists_false_for_unknown_agent(
        self, store: FilesystemCertStore
    ) -> None:
        assert store.exists("ghost") is False

    def test_exists_true_after_save(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        assert store.exists("agent-store-001") is True

    def test_exists_false_after_delete(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        store.delete("agent-store-001")
        assert store.exists("agent-store-001") is False


# ---------------------------------------------------------------------------
# FilesystemCertStore — list_agents
# ---------------------------------------------------------------------------


class TestListAgents:
    def test_empty_store_returns_empty_list(
        self, store: FilesystemCertStore
    ) -> None:
        assert store.list_agents() == []

    def test_list_returns_saved_agent_ids(
        self,
        store: FilesystemCertStore,
        agent_cert: AgentCertificate,
        agent_cert_2: AgentCertificate,
    ) -> None:
        store.save(agent_cert)
        store.save(agent_cert_2)
        agents = store.list_agents()
        assert "agent-store-001" in agents
        assert "agent-store-002" in agents

    def test_list_is_sorted(
        self,
        store: FilesystemCertStore,
        agent_cert: AgentCertificate,
        agent_cert_2: AgentCertificate,
    ) -> None:
        store.save(agent_cert_2)
        store.save(agent_cert)
        agents = store.list_agents()
        assert agents == sorted(agents)

    def test_deleted_agent_not_in_list(
        self, store: FilesystemCertStore, agent_cert: AgentCertificate
    ) -> None:
        store.save(agent_cert)
        store.delete("agent-store-001")
        assert "agent-store-001" not in store.list_agents()


# ---------------------------------------------------------------------------
# FilesystemCertStore — agent_id path sanitisation
# ---------------------------------------------------------------------------


class TestPathSanitisation:
    def test_forward_slash_replaced_in_path(
        self, store: FilesystemCertStore, base_dir: Path, ca: CertificateAuthority
    ) -> None:
        cert = ca.sign_agent_cert(
            agent_id="org/agent-001",
            organization="TestOrg",
            capabilities=[],
            trust_level=1,
        )
        store.save(cert)
        assert (base_dir / "org_agent-001").is_dir()
