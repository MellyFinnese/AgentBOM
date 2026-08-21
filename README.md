# AgentBOM

AI agent security and attack-surface intelligence.

AgentBOM models autonomous AI systems as relationships between agents, models, tools, identities, credentials, capabilities, data, and deployments. The project is designed to answer not only **what exists**, but **what an agent can do, what it can reach, and what happens if that access is abused**.

## Architecture

```text
Discovery -> Normalization -> Graph -> Analysis -> Evidence -> Reporting
                              |
                    +---------+---------+
                    |                   |
                  Risk              Attack Paths
                                        |
                                  Blast Radius
```

## Design principles

- Domain-first: the security model comes before integrations.
- Capability-aware: permissions and capabilities are first-class entities.
- Evidence-backed: important observations retain provenance.
- Graph-native: relationships are part of the security model.
- Deterministic: risk and path analysis are reproducible.
- Backend-neutral: local graph analysis does not require a graph database.
- Extensible discovery: MCP, configuration, runtime, and cloud sources plug into one normalization layer.

## Status

Early foundation. Core domain types and graph boundaries are being established before discovery integrations.
