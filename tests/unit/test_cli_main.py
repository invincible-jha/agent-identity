"""Tests for agent_identity.cli.main — CLI commands via Click test runner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_identity.cli.main import cli


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def registry_file(tmp_path: Path) -> Path:
    return tmp_path / "registry.json"


@pytest.fixture()
def revocation_file(tmp_path: Path) -> Path:
    return tmp_path / "revocation.json"


# ---------------------------------------------------------------------------
# Root CLI
# ---------------------------------------------------------------------------


class TestRootCLI:
    def test_help_exits_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_version_command(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "agent-identity" in result.output.lower()

    def test_plugins_command(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# identity register
# ---------------------------------------------------------------------------


class TestRegisterCommand:
    def test_register_minimal_args(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "register",
                "agent-cli-001",
                "--display-name",
                "CLI Test Agent",
                "--organization",
                "TestOrg",
            ],
        )
        assert result.exit_code == 0
        assert "agent-cli-001" in result.output

    def test_register_with_capabilities(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "register",
                "agent-cli-002",
                "--display-name",
                "Agent Two",
                "--organization",
                "OrgA",
                "--capability",
                "read",
                "--capability",
                "write",
            ],
        )
        assert result.exit_code == 0

    def test_register_with_metadata(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "register",
                "agent-cli-003",
                "--display-name",
                "Agent Three",
                "--organization",
                "OrgB",
                "--metadata",
                '{"env": "prod"}',
            ],
        )
        assert result.exit_code == 0

    def test_register_with_invalid_metadata_json_exits_nonzero(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "register",
                "agent-cli-004",
                "--display-name",
                "Agent Four",
                "--organization",
                "OrgC",
                "--metadata",
                "{not valid json}",
            ],
        )
        assert result.exit_code != 0

    def test_register_persists_to_file(
        self, runner: CliRunner, registry_file: Path
    ) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "register",
                "agent-file-001",
                "--display-name",
                "File Agent",
                "--organization",
                "FileOrg",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert registry_file.exists()
        data = json.loads(registry_file.read_text())
        assert any(r["agent_id"] == "agent-file-001" for r in data)

    def test_register_duplicate_exits_nonzero(self, runner: CliRunner) -> None:
        args = [
            "identity",
            "register",
            "agent-dup-001",
            "--display-name",
            "Dup Agent",
            "--organization",
            "Org",
        ]
        runner.invoke(cli, args)
        # Second registration in same process: uses fresh in-memory registry, so no conflict
        # To test actual duplicate, use a file-backed registry
        with runner.isolated_filesystem():
            reg_path = "reg.json"
            runner.invoke(cli, args + ["--registry-file", reg_path])
            result = runner.invoke(cli, args + ["--registry-file", reg_path])
            assert result.exit_code != 0

    def test_register_loads_existing_registry_file(
        self, runner: CliRunner, registry_file: Path, tmp_path: Path
    ) -> None:
        # First registration
        runner.invoke(
            cli,
            [
                "identity",
                "register",
                "existing-agent",
                "--display-name",
                "Existing",
                "--organization",
                "Org",
                "--registry-file",
                str(registry_file),
            ],
        )
        # Second registration with different agent (should load existing file fine)
        result = runner.invoke(
            cli,
            [
                "identity",
                "register",
                "new-agent",
                "--display-name",
                "New",
                "--organization",
                "Org",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# identity verify
# ---------------------------------------------------------------------------


class TestVerifyCommand:
    def test_verify_registered_agent(
        self, runner: CliRunner, registry_file: Path
    ) -> None:
        runner.invoke(
            cli,
            [
                "identity",
                "register",
                "verify-agent",
                "--display-name",
                "Verify Me",
                "--organization",
                "Org",
                "--registry-file",
                str(registry_file),
            ],
        )
        result = runner.invoke(
            cli,
            [
                "identity",
                "verify",
                "verify-agent",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_unregistered_agent_fails(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["identity", "verify", "ghost-agent"])
        assert result.exit_code != 0

    def test_verify_deregistered_agent_shows_issue(
        self, runner: CliRunner, registry_file: Path
    ) -> None:
        # Register then deregister by writing an inactive record directly
        inactive_record = [
            {
                "agent_id": "inactive-agent",
                "display_name": "Inactive",
                "organization": "Org",
                "capabilities": [],
                "metadata": {},
                "did": "",
                "registered_at": "2024-01-01T00:00:00+00:00",
                "updated_at": "2024-01-01T00:00:00+00:00",
                "active": False,
            }
        ]
        registry_file.write_text(json.dumps(inactive_record), encoding="utf-8")
        result = runner.invoke(
            cli,
            [
                "identity",
                "verify",
                "inactive-agent",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code != 0
        assert "FAIL" in result.output or "inactive" in result.output.lower()


# ---------------------------------------------------------------------------
# identity trust
# ---------------------------------------------------------------------------


class TestTrustCommand:
    def test_trust_default_scores(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["identity", "trust", "agent-001"])
        assert result.exit_code == 0

    def test_trust_with_explicit_scores(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "trust",
                "agent-001",
                "--competence",
                "80",
                "--reliability",
                "70",
                "--integrity",
                "90",
            ],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# identity delegate
# ---------------------------------------------------------------------------


class TestDelegateCommand:
    def test_delegate_outputs_json(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "delegate",
                "issuer-001",
                "delegate-001",
                "--scope",
                "read",
                "--scope",
                "write",
                "--secret",
                "my-secret-key",
            ],
        )
        assert result.exit_code == 0
        # Output should contain a JSON token with token_id
        assert "token_id" in result.output

    def test_delegate_writes_to_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        output_file = tmp_path / "token.json"
        result = runner.invoke(
            cli,
            [
                "identity",
                "delegate",
                "issuer-001",
                "delegate-001",
                "--scope",
                "read",
                "--secret",
                "my-secret",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        token_data = json.loads(output_file.read_text())
        assert "token_id" in token_data

    def test_delegate_with_ttl(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "delegate",
                "issuer-001",
                "delegate-001",
                "--scope",
                "read",
                "--secret",
                "my-secret",
                "--ttl",
                "7200",
            ],
        )
        assert result.exit_code == 0

    def test_delegate_with_parent_token_id(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "delegate",
                "issuer-001",
                "delegate-001",
                "--scope",
                "read",
                "--secret",
                "my-secret",
                "--parent-token-id",
                "parent-tok-123",
            ],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# identity revoke
# ---------------------------------------------------------------------------


class TestRevokeCommand:
    def test_revoke_single_token(
        self, runner: CliRunner, revocation_file: Path
    ) -> None:
        result = runner.invoke(
            cli,
            [
                "identity",
                "revoke",
                "token-abc",
                "--revocation-file",
                str(revocation_file),
            ],
        )
        assert result.exit_code == 0
        assert "Revoked" in result.output
        data = json.loads(revocation_file.read_text())
        assert "token-abc" in data["revoked_token_ids"]

    def test_revoke_already_revoked_token_prints_warning(
        self, runner: CliRunner, revocation_file: Path
    ) -> None:
        args = [
            "identity",
            "revoke",
            "token-abc",
            "--revocation-file",
            str(revocation_file),
        ]
        runner.invoke(cli, args)
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "already revoked" in result.output.lower()

    def test_revoke_without_file(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["identity", "revoke", "token-xyz"])
        assert result.exit_code == 0
        assert "Revoked" in result.output

    def test_revoke_cascade_with_chain_file(
        self, runner: CliRunner, revocation_file: Path, tmp_path: Path
    ) -> None:
        chain_file = tmp_path / "chain.json"
        chain_data = {
            "token_ids": ["root-tok", "child-tok"],
            "parent_map": {"root-tok": None, "child-tok": "root-tok"},
        }
        chain_file.write_text(json.dumps(chain_data), encoding="utf-8")

        result = runner.invoke(
            cli,
            [
                "identity",
                "revoke",
                "root-tok",
                "--revocation-file",
                str(revocation_file),
                "--cascade",
                "--chain-file",
                str(chain_file),
            ],
        )
        assert result.exit_code == 0

    def test_revoke_cascade_with_bad_chain_file_exits_nonzero(
        self, runner: CliRunner, revocation_file: Path, tmp_path: Path
    ) -> None:
        chain_file = tmp_path / "chain.json"
        chain_file.write_text("not json", encoding="utf-8")

        result = runner.invoke(
            cli,
            [
                "identity",
                "revoke",
                "root-tok",
                "--revocation-file",
                str(revocation_file),
                "--cascade",
                "--chain-file",
                str(chain_file),
            ],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# identity list
# ---------------------------------------------------------------------------


class TestListCommand:
    def test_list_empty_registry(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["identity", "list"])
        assert result.exit_code == 0
        assert "No agents found" in result.output

    def test_list_shows_registered_agents(
        self, runner: CliRunner, registry_file: Path
    ) -> None:
        runner.invoke(
            cli,
            [
                "identity",
                "register",
                "list-agent-001",
                "--display-name",
                "List Agent One",
                "--organization",
                "ListOrg",
                "--registry-file",
                str(registry_file),
            ],
        )
        result = runner.invoke(
            cli,
            ["identity", "list", "--registry-file", str(registry_file)],
        )
        assert result.exit_code == 0
        assert "list-agent-001" in result.output

    def test_list_filter_by_organization(
        self, runner: CliRunner, registry_file: Path
    ) -> None:
        for i in range(2):
            runner.invoke(
                cli,
                [
                    "identity",
                    "register",
                    f"agent-org-{i}",
                    "--display-name",
                    f"Agent {i}",
                    "--organization",
                    "OrgA" if i == 0 else "OrgB",
                    "--registry-file",
                    str(registry_file),
                ],
            )
        result = runner.invoke(
            cli,
            [
                "identity",
                "list",
                "--organization",
                "OrgA",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert "agent-org-0" in result.output

    def test_list_filter_by_query(
        self, runner: CliRunner, registry_file: Path
    ) -> None:
        runner.invoke(
            cli,
            [
                "identity",
                "register",
                "analytics-bot",
                "--display-name",
                "Analytics Bot",
                "--organization",
                "Org",
                "--registry-file",
                str(registry_file),
            ],
        )
        result = runner.invoke(
            cli,
            [
                "identity",
                "list",
                "--query",
                "analytics",
                "--registry-file",
                str(registry_file),
            ],
        )
        assert result.exit_code == 0
        assert "analytics-bot" in result.output

    def test_list_with_corrupt_registry_file_prints_warning(
        self, runner: CliRunner, registry_file: Path
    ) -> None:
        registry_file.write_text("not json", encoding="utf-8")
        result = runner.invoke(
            cli,
            ["identity", "list", "--registry-file", str(registry_file)],
        )
        assert result.exit_code == 0  # warning only, not fatal
