"""CLI entry point for agent-identity.

Invoked as::

    agent-identity [OPTIONS] COMMAND [ARGS]...

or, during development::

    python -m agent_identity.cli.main

Commands
--------
identity register   Register a new agent identity
identity verify     Verify an agent certificate
identity trust      Display or update trust scores
identity delegate   Create a delegation token
identity revoke     Revoke a delegation token
identity list       List all registered agents
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()


# ------------------------------------------------------------------
# Root group
# ------------------------------------------------------------------


@click.group()
@click.version_option()
def cli() -> None:
    """Agent identity management, trust scoring, and certificate management"""


# ------------------------------------------------------------------
# version / plugins commands (pre-existing)
# ------------------------------------------------------------------


@cli.command(name="version")
def version_command() -> None:
    """Show detailed version information."""
    from agent_identity import __version__

    console.print(f"[bold]agent-identity[/bold] v{__version__}")


@cli.command(name="plugins")
def plugins_command() -> None:
    """List all registered plugins loaded from entry-points."""
    console.print("[bold]Registered plugins:[/bold]")
    console.print("  (No plugins registered. Install a plugin package to see entries here.)")


# ------------------------------------------------------------------
# identity command group
# ------------------------------------------------------------------


@cli.group(name="identity")
def identity_group() -> None:
    """Manage agent identities."""


# ------------------------------------------------------------------
# identity register
# ------------------------------------------------------------------


@identity_group.command(name="register")
@click.argument("agent_id")
@click.option("--display-name", "-n", required=True, help="Human-readable name for the agent.")
@click.option("--organization", "-o", required=True, help="Owning organization or namespace.")
@click.option(
    "--capability",
    "-c",
    multiple=True,
    help="Capability string (repeatable, e.g. -c read -c write).",
)
@click.option(
    "--metadata",
    "-m",
    default=None,
    help="JSON object of arbitrary metadata (e.g. '{\"env\": \"prod\"}').",
)
@click.option(
    "--registry-file",
    type=click.Path(),
    default=None,
    help="Path to a JSON file acting as a persistent registry store.",
)
def register_command(
    agent_id: str,
    display_name: str,
    organization: str,
    capability: tuple[str, ...],
    metadata: str | None,
    registry_file: str | None,
) -> None:
    """Register a new agent identity with AGENT_ID."""
    from agent_identity.registry import IdentityRegistry, AgentAlreadyRegisteredError
    from agent_identity.registry.did import DIDProvider

    parsed_metadata: dict[str, object] = {}
    if metadata:
        try:
            parsed_metadata = json.loads(metadata)
        except json.JSONDecodeError as exc:
            console.print(f"[red]Error:[/red] --metadata is not valid JSON: {exc}")
            sys.exit(1)

    registry = _load_registry(registry_file)
    did_provider = DIDProvider()

    try:
        record = registry.register(
            agent_id=agent_id,
            display_name=display_name,
            organization=organization,
            capabilities=list(capability),
            metadata=parsed_metadata,
        )
        did = did_provider.create_did(agent_id)
        registry.update(agent_id, did=did)

        _save_registry(registry, registry_file)

        console.print(f"[green]Registered[/green] agent [bold]{agent_id}[/bold]")
        console.print(f"  DID:          {did}")
        console.print(f"  Organization: {record.organization}")
        console.print(f"  Capabilities: {', '.join(record.capabilities) or '(none)'}")
        console.print(f"  Registered:   {record.registered_at.isoformat()}")

    except AgentAlreadyRegisteredError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


# ------------------------------------------------------------------
# identity verify
# ------------------------------------------------------------------


@identity_group.command(name="verify")
@click.argument("agent_id")
@click.option(
    "--cert-file",
    type=click.Path(exists=True),
    default=None,
    help="Path to PEM-encoded agent certificate file.",
)
@click.option(
    "--registry-file",
    type=click.Path(),
    default=None,
    help="Path to a JSON registry store to confirm registration.",
)
def verify_command(
    agent_id: str,
    cert_file: str | None,
    registry_file: str | None,
) -> None:
    """Verify an agent identity and optionally its certificate.

    AGENT_ID is the agent to verify.
    """
    registry = _load_registry(registry_file)
    issues: list[str] = []
    passed: list[str] = []

    # Check registration
    try:
        record = registry.get(agent_id)
        if record.active:
            passed.append("Agent is registered and active.")
        else:
            issues.append("Agent is registered but marked inactive (deregistered).")
    except KeyError:
        issues.append(f"Agent {agent_id!r} is not registered.")

    # Optionally verify certificate
    if cert_file:
        try:
            cert_pem = Path(cert_file).read_bytes()
            from agent_identity.middleware.auth import AuthMiddleware

            auth = AuthMiddleware()
            result = auth.authenticate_certificate(cert_pem)
            if result.success:
                if result.agent_id == agent_id:
                    passed.append("Certificate is well-formed and matches agent_id.")
                else:
                    issues.append(
                        f"Certificate agent_id mismatch: expected {agent_id!r}, "
                        f"got {result.agent_id!r}."
                    )
            else:
                issues.append(f"Certificate verification failed: {result.reason}")
        except Exception as exc:
            issues.append(f"Could not read certificate file: {exc}")

    for item in passed:
        console.print(f"  [green]PASS[/green]  {item}")
    for item in issues:
        console.print(f"  [red]FAIL[/red]  {item}")

    if issues:
        sys.exit(1)
    else:
        console.print(f"\n[green]Agent {agent_id!r} verified successfully.[/green]")


# ------------------------------------------------------------------
# identity trust
# ------------------------------------------------------------------


@identity_group.command(name="trust")
@click.argument("agent_id")
@click.option(
    "--competence",
    type=float,
    default=None,
    help="Competence dimension score (0-100).",
)
@click.option(
    "--reliability",
    type=float,
    default=None,
    help="Reliability dimension score (0-100).",
)
@click.option(
    "--integrity",
    type=float,
    default=None,
    help="Integrity dimension score (0-100).",
)
def trust_command(
    agent_id: str,
    competence: float | None,
    reliability: float | None,
    integrity: float | None,
) -> None:
    """Display or compute a trust score for an agent.

    AGENT_ID is the agent to score. If no dimension scores are provided,
    a default score of 50.0 is used for each dimension.
    """
    from agent_identity.trust import TrustDimension, TrustScorer

    scorer = TrustScorer()

    dimensions = {
        TrustDimension.COMPETENCE: competence if competence is not None else 50.0,
        TrustDimension.RELIABILITY: reliability if reliability is not None else 50.0,
        TrustDimension.INTEGRITY: integrity if integrity is not None else 50.0,
    }

    trust_score = scorer.score(agent_id=agent_id, dimensions=dimensions)

    table = Table(title=f"Trust Score — {agent_id}", show_header=True)
    table.add_column("Dimension", style="cyan")
    table.add_column("Score", justify="right")

    for dim, score in trust_score.dimensions.items():
        table.add_row(dim.value.capitalize(), f"{score:.2f}")

    console.print(table)
    console.print(f"\n  Composite: [bold]{trust_score.composite:.2f}[/bold]")
    console.print(f"  Level:     [bold]{trust_score.level.name}[/bold]")
    console.print(f"  Computed:  {trust_score.timestamp.isoformat()}")


# ------------------------------------------------------------------
# identity delegate
# ------------------------------------------------------------------


@identity_group.command(name="delegate")
@click.argument("issuer_id")
@click.argument("delegate_id")
@click.option(
    "--scope",
    "-s",
    multiple=True,
    required=True,
    help="Capability scope to delegate (repeatable).",
)
@click.option(
    "--secret",
    required=True,
    help="Shared HMAC signing secret (base64-encoded or plaintext).",
)
@click.option(
    "--ttl",
    type=int,
    default=3600,
    show_default=True,
    help="Token lifetime in seconds.",
)
@click.option(
    "--parent-token-id",
    default=None,
    help="Parent token ID for sub-delegation chains.",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Write token JSON to this file path.",
)
def delegate_command(
    issuer_id: str,
    delegate_id: str,
    scope: tuple[str, ...],
    secret: str,
    ttl: int,
    parent_token_id: str | None,
    output: str | None,
) -> None:
    """Create a delegation token from ISSUER_ID to DELEGATE_ID."""
    from agent_identity.delegation import DelegationToken

    secret_bytes = secret.encode("utf-8")

    token = DelegationToken.create_token(
        issuer_id=issuer_id,
        delegate_id=delegate_id,
        scopes=list(scope),
        secret_key=secret_bytes,
        ttl_seconds=ttl,
        parent_token_id=parent_token_id,
    )

    token_dict = token.to_dict()
    token_json = json.dumps(token_dict, indent=2)

    if output:
        Path(output).write_text(token_json, encoding="utf-8")
        console.print(f"[green]Token written to[/green] {output}")
    else:
        console.print(token_json)

    console.print(f"\n  Token ID:  [bold]{token.token_id}[/bold]")
    console.print(f"  Issuer:    {token.issuer_id}")
    console.print(f"  Delegate:  {token.delegate_id}")
    console.print(f"  Scopes:    {', '.join(token.scopes)}")
    console.print(f"  Expires:   {token.expires_at.isoformat()}")


# ------------------------------------------------------------------
# identity revoke
# ------------------------------------------------------------------


@identity_group.command(name="revoke")
@click.argument("token_id")
@click.option(
    "--revocation-file",
    type=click.Path(),
    default=None,
    help="Path to a JSON file tracking revoked token IDs.",
)
@click.option(
    "--cascade",
    is_flag=True,
    default=False,
    help="Also revoke all child tokens in the chain (requires --chain-file).",
)
@click.option(
    "--chain-file",
    type=click.Path(exists=False),
    default=None,
    help="Path to a JSON file describing the delegation chain (for --cascade).",
)
def revoke_command(
    token_id: str,
    revocation_file: str | None,
    cascade: bool,
    chain_file: str | None,
) -> None:
    """Revoke a delegation token by TOKEN_ID."""
    from agent_identity.delegation import DelegationRevocation

    revocation = _load_revocation(revocation_file)

    if revocation.is_revoked(token_id):
        console.print(f"[yellow]Token {token_id!r} is already revoked.[/yellow]")
        return

    revoked_ids: list[str] = [token_id]

    if cascade and chain_file:
        try:
            chain_data: dict[str, object] = json.loads(
                Path(chain_file).read_text(encoding="utf-8")
            )
            all_ids: list[str] = [str(tid) for tid in (chain_data.get("token_ids") or [])]
            parent_map: dict[str, str | None] = {
                str(k): (str(v) if v is not None else None)
                for k, v in (chain_data.get("parent_map") or {}).items()
            }
            revocation.revoke(token_id)
            cascade_revoked = revocation.revoke_chain(
                token_id=token_id,
                all_token_ids=all_ids,
                parent_map=parent_map,
            )
            revoked_ids = [token_id] + cascade_revoked
        except Exception as exc:
            console.print(f"[red]Error reading chain file:[/red] {exc}")
            sys.exit(1)
    else:
        revocation.revoke(token_id)

    _save_revocation(revocation, revocation_file)

    for rid in revoked_ids:
        console.print(f"[red]Revoked[/red] token [bold]{rid}[/bold]")


# ------------------------------------------------------------------
# identity list
# ------------------------------------------------------------------


@identity_group.command(name="list")
@click.option(
    "--organization",
    "-o",
    default=None,
    help="Filter by organization.",
)
@click.option(
    "--capability",
    "-c",
    default=None,
    help="Filter by capability.",
)
@click.option(
    "--include-inactive",
    is_flag=True,
    default=False,
    help="Include deregistered agents.",
)
@click.option(
    "--query",
    "-q",
    default="",
    help="Free-text search (matches agent_id and display_name).",
)
@click.option(
    "--registry-file",
    type=click.Path(),
    default=None,
    help="Path to a JSON registry store.",
)
def list_command(
    organization: str | None,
    capability: str | None,
    include_inactive: bool,
    query: str,
    registry_file: str | None,
) -> None:
    """List all registered agent identities."""
    registry = _load_registry(registry_file)

    records = registry.search(
        query=query,
        organization=organization,
        capability=capability,
        include_inactive=include_inactive,
    )

    if not records:
        console.print("[yellow]No agents found matching your criteria.[/yellow]")
        return

    table = Table(title="Registered Agents", show_header=True)
    table.add_column("Agent ID", style="cyan")
    table.add_column("Display Name")
    table.add_column("Organization")
    table.add_column("Active", justify="center")
    table.add_column("Capabilities")

    for record in records:
        active_str = "[green]Yes[/green]" if record.active else "[red]No[/red]"
        caps = ", ".join(record.capabilities) or "(none)"
        table.add_row(
            record.agent_id,
            record.display_name,
            record.organization,
            active_str,
            caps,
        )

    console.print(table)
    console.print(f"\nTotal: {len(records)} agent(s)")


# ------------------------------------------------------------------
# Helpers — simple in-memory or file-backed persistence for CLI use
# ------------------------------------------------------------------


def _load_registry(registry_file: str | None):  # type: ignore[return]
    """Return an IdentityRegistry, optionally pre-populated from a JSON file."""
    from agent_identity.registry import IdentityRegistry

    registry = IdentityRegistry()
    if registry_file and Path(registry_file).exists():
        try:
            data: list[dict[str, object]] = json.loads(
                Path(registry_file).read_text(encoding="utf-8")
            )
            for entry in data:
                agent_id = str(entry["agent_id"])
                try:
                    registry.register(
                        agent_id=agent_id,
                        display_name=str(entry.get("display_name", agent_id)),
                        organization=str(entry.get("organization", "")),
                        capabilities=[str(c) for c in (entry.get("capabilities") or [])],
                        metadata={str(k): v for k, v in (entry.get("metadata") or {}).items()},
                        did=str(entry.get("did", "")),
                    )
                    if not entry.get("active", True):
                        try:
                            registry.deregister(agent_id)
                        except KeyError:
                            pass
                except Exception:
                    pass
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Could not load registry file: {exc}")
    return registry


def _save_registry(registry, registry_file: str | None) -> None:  # type: ignore[no-untyped-def]
    """Persist registry contents to a JSON file."""
    if not registry_file:
        return
    records = registry.list_all(include_inactive=True)
    data = [r.to_dict() for r in records]
    Path(registry_file).write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_revocation(revocation_file: str | None):  # type: ignore[return]
    """Return a DelegationRevocation, optionally pre-populated from a JSON file."""
    from agent_identity.delegation import DelegationRevocation

    rev = DelegationRevocation()
    if revocation_file and Path(revocation_file).exists():
        try:
            data: dict[str, object] = json.loads(
                Path(revocation_file).read_text(encoding="utf-8")
            )
            token_ids = [str(tid) for tid in (data.get("revoked_token_ids") or [])]
            rev.restore(token_ids)
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Could not load revocation file: {exc}")
    return rev


def _save_revocation(revocation, revocation_file: str | None) -> None:  # type: ignore[no-untyped-def]
    """Persist revoked token IDs to a JSON file."""
    if not revocation_file:
        return
    data = {"revoked_token_ids": sorted(revocation.revoked_token_ids())}
    Path(revocation_file).write_text(json.dumps(data, indent=2), encoding="utf-8")


if __name__ == "__main__":
    cli()
