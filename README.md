# AgentBOM

AI agent security and attack-surface intelligence.

AgentBOM models autonomous AI systems as relationships between agents, models, tools, identities, credentials, capabilities, data, and deployments. The goal is to determine **what exists, what an agent can do, what authority it holds, what it can reach, and what happens if that access is abused**.

## Current vertical slice

AgentBOM can inspect an MCP-style JSON manifest without executing the configured server:

```bash
agentbom scan ./mcp.json
agentbom scan ./mcp.json --paths
agentbom scan ./mcp.json --json --paths
```

Discovery normalizes declared agents, MCP servers, tools, credentials, capabilities, and data resources into the AgentBOM graph. The authorization layer can then represent identities, credentials, explicit permission grants, resource scope, and delegation/assumption relationships. A bounded traversal engine identifies reachable high-impact entities.

Example security chain:

```text
Agent
  -> Identity
      -> Credential
          -> Permission
              -> Production Data
```

## Architecture

```text
                +------------------+
                |    Discovery     |
                +---------+--------+
                          |
                          v
                +------------------+
                |  Normalization    |
                +---------+--------+
                          |
                          v
                +------------------+
                |  Security Graph   |
                +---------+--------+
                          |
             +------------+------------+
             |            |            |
             v            v            v
           Risk      Authorization   Attack Paths
             |            |            |
             +------------+------------+
                          |
                          v
                    Blast Radius
                          |
                          v
                       Evidence
                          |
                          v
                    Reporting / CI
```

## Design principles

- **Domain-first:** the security model comes before integrations.
- **Capability-aware:** capabilities and authorization are modeled explicitly.
- **Authority-aware:** identity, credentials, grants, resource scope, assumption, and delegation are first-class concepts.
- **Evidence-backed:** discoveries retain source and provenance metadata.
- **Graph-native:** relationships are part of the security model, not an enrichment step.
- **Deterministic:** analysis is reproducible and bounded.
- **Backend-neutral:** local analysis does not require a graph database.
- **Extensible discovery:** MCP, configuration, runtime, and cloud sources can feed the same model.
- **Safe discovery:** configuration inspection does not execute arbitrary agent or MCP code.

## Status

Early active development. The discovery-to-graph-to-attack-path pipeline and explicit authorization model are now in place. Next layers are richer authorization ingestion, runtime discovery, policy analysis, blast-radius scoring, and graph backends.
