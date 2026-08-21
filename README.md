# AgentBOM

AI agent security and attack-surface intelligence.

AgentBOM models autonomous AI systems as relationships between agents, models, tools, identities, credentials, capabilities, data, and deployments. The goal is to determine **what exists, what an agent can do, what authority it holds, what it can reach, and what happens if that access is abused**.

## Current vertical slice

AgentBOM can inspect an MCP-style JSON manifest without executing the configured server:

```bash
agentbom scan ./mcp.json
agentbom scan ./mcp.json --auth
agentbom scan ./mcp.json --paths
agentbom scan ./mcp.json --policy
agentbom scan ./mcp.json --auth --paths --policy
agentbom scan ./mcp.json --json --auth --paths --policy
```

Discovery normalizes declared agents, MCP servers, tools, credentials, capabilities, identities, permission grants, and resource scope into the AgentBOM graph.

The deterministic policy engine currently detects:

- wildcard authorization grants
- production write/delete/admin/execute authority
- credentials referenced by configuration
- dangerous tool capabilities
- reachable high-impact resources through graph paths

Every policy finding includes a stable rule ID, severity, affected entity IDs, description, and evidence that can be rendered as JSON for CI or downstream tooling.

Example privilege chain:

```text
Agent
  -> Identity
      -> Credential
          -> Permission
              -> Production Data
```

Example attack path:

```text
Agent
  -> MCP Server
      -> Tool
          -> Identity
              -> Credential
                  -> Permission
                      -> Resource
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
          +---------------+---------------+
          |               |               |
          v               v               v
        Risk        Authorization       Policy
          |               |               |
          +---------------+---------------+
                          |
                          v
                     Attack Paths
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
- **Authority-aware:** identity, credentials, permission grants, effects, conditions, and resource scope are first-class concepts.
- **Evidence-backed:** discoveries retain source and provenance metadata.
- **Graph-native:** relationships are part of the security model, not an enrichment step.
- **Deterministic:** policy and path analysis are reproducible and bounded.
- **Backend-neutral:** local analysis does not require a graph database.
- **Extensible discovery:** MCP, configuration, runtime, and cloud sources can feed the same model.
- **Safe discovery:** configuration inspection does not execute arbitrary agent or MCP code.

## Status

Early active development. The first discovery-to-graph-to-authorization-to-policy pipeline is in place. The next major layers are richer IAM/API authorization ingestion, runtime discovery, blast-radius scoring, and graph backends.
