# agent-identity

Agent Identity & Trust Scoring — DID-based identity, behavioral trust, certificate management.

[![CI](https://github.com/invincible-jha/agent-identity/actions/workflows/ci.yaml/badge.svg)](https://github.com/invincible-jha/agent-identity/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/agent-identity.svg)](https://pypi.org/project/agent-identity/)
[![Python versions](https://img.shields.io/pypi/pyversions/agent-identity.svg)](https://pypi.org/project/agent-identity/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/invincible-jha/agent-identity/blob/main/LICENSE)

---

## Installation

```bash
pip install agent-identity
```

Verify the installation:

```bash
agent-identity version
```

---

## Quick Start

```python
import agent_identity

# See examples/01_quickstart.py for a complete working example
```

---

## Key Features

- **DID-based identity registry** assigns each agent a decentralized identifier with a verifiable credential; `IdentityRegistry` provides lookup and resolution
- **`TrustScorer`** computes a composite trust score from three weighted dimensions — competence (40%), reliability (35%), and integrity (25%) — updated via outcome observations (success, failure, violation)
- **Certificate management** with an agent CA, certificate issuance, revocation lists, verification, and automatic rotation on configurable expiry schedules
- **Behavioral fingerprinting** builds a baseline profile of an agent's interaction patterns and raises alerts when its behavior deviates — useful for detecting compromised or impersonated agents
- **Delegation token chain** allows an agent to delegate a subset of its permissions to a sub-agent, with revocation propagating down the full chain
- **RBAC middleware** enforces role-based access at call boundaries; audit middleware records every identity-check decision for compliance review
- **Trust history log** tracks score trajectories over time so administrators can review how an agent's trust evolved before granting elevated permissions

---

## Links

- [GitHub Repository](https://github.com/invincible-jha/agent-identity)
- [PyPI Package](https://pypi.org/project/agent-identity/)
- [Architecture](architecture.md)
- [Contributing](https://github.com/invincible-jha/agent-identity/blob/main/CONTRIBUTING.md)
- [Changelog](https://github.com/invincible-jha/agent-identity/blob/main/CHANGELOG.md)

---

## License

Apache 2.0 — see [LICENSE](https://github.com/invincible-jha/agent-identity/blob/main/LICENSE) for full terms.

---

Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure.
