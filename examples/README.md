# Examples

| # | Example | Description |
|---|---------|-------------|
| 01 | [Quickstart](01_quickstart.py) | Minimal working example with the Identity convenience class |
| 02 | [Trust Scoring](02_trust_scoring.py) | Multi-dimensional trust scoring with TrustHistory |
| 03 | [Registry and Delegation](03_registry_delegation.py) | Register agents and create delegation tokens |
| 04 | [RBAC Middleware](04_rbac_middleware.py) | Role-based access control and auth middleware |
| 05 | [Behavioral Fingerprint](05_behavioral_fingerprint.py) | Detect anomalous agent behaviour patterns |
| 06 | [LangChain Identity](06_langchain_identity.py) | Identity-gated LangChain chain execution |
| 07 | [Native Binding](07_native_binding.py) | Bind agent identities to runtime environments |

## Running the examples

```bash
pip install agent-identity
python examples/01_quickstart.py
```

For framework integrations:

```bash
pip install langchain   # for example 06
```
