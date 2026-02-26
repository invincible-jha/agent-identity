# agent-identity

Agent identity management, trust scoring, and certificate management

[![CI](https://github.com/aumos-ai/agent-identity/actions/workflows/ci.yaml/badge.svg)](https://github.com/aumos-ai/agent-identity/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/agent-identity.svg)](https://pypi.org/project/agent-identity/)
[![Python versions](https://img.shields.io/pypi/pyversions/agent-identity.svg)](https://pypi.org/project/agent-identity/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.

---

## Features

- DID-based identity registry assigns each agent a decentralized identifier with a verifiable credential; `IdentityRegistry` provides lookup and resolution
- `TrustScorer` computes a composite trust score from three weighted dimensions — competence (40%), reliability (35%), and integrity (25%) — updated via outcome observations (success, failure, violation)
- Certificate management with an agent CA, certificate issuance, revocation lists, verification, and automatic rotation on configurable expiry schedules
- Behavioral fingerprinting builds a baseline profile of an agent's interaction patterns and raises alerts when its behavior deviates — useful for detecting compromised or impersonated agents
- Delegation token chain allows an agent to delegate a subset of its permissions to a sub-agent, with revocation propagating down the full chain
- RBAC middleware enforces role-based access at call boundaries; audit middleware records every identity-check decision for compliance review
- Trust history log tracks score trajectories over time so administrators can review how an agent's trust evolved before granting elevated permissions

## Quick Start

Install from PyPI:

```bash
pip install agent-identity
```

Verify the installation:

```bash
agent-identity version
```

Basic usage:

```python
import agent_identity

# See examples/01_quickstart.py for a working example
```

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/README.md)

## Enterprise Upgrade

The open-source edition provides the core foundation. For production
deployments requiring SLA-backed support, advanced integrations, and the full
AgentTrust platform, see [docs/UPGRADE_TO_AgentTrust.md](docs/UPGRADE_TO_AgentTrust.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request.

## License

Apache 2.0 — see [LICENSE](LICENSE) for full terms.

---

Part of [AumOS](https://github.com/aumos-ai) — open-source agent infrastructure.
