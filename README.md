# AgentBOM

AI agent security and attack-surface intelligence.

AgentBOM models autonomous AI systems as relationships between agents, models, tools, identities, credentials, capabilities, data, and deployments. The goal is to determine **what exists, what an agent can do, what it can reach, and what happens if that access is abused**.

## Current vertical slice

AgentBOM can now inspect an MCP-style JSON manifest without executing the configured server:

```bash
agentbom scan ./mcp.json
agentbom scan ./mcp.json --paths
agentbom scan ./mcp.json --json --paths
```

Discovery normalizes declared agents, MCP servers, tools, credentials, and data resources into the AgentBOM graph. A bounded traversal engine then identifies reachable high-impact entities such as credentials, data sources, databases, and deployments.

Example flow:

```text
Agent
  -> MCP Server
      -> Tool
          -> Data Source

Agent
  -> MCP Server
      -> Credential
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
           Risk     Attack Paths   Blast Radius
             |            |            |
             +------------+------------+
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
- **Evidence-backed:** discoveries retain source and provenance metadata.
- **Graph-native:** relationships are part of the security model, not an enrichment step.
- **Deterministic:** analysis is reproducible and bounded.
- **Backend-neutral:** local analysis does not require a graph database.
- **Extensible discovery:** MCP, configuration, runtime, and cloud sources can feed the same model.
- **Safe discovery:** configuration inspection does not execute arbitrary agent or MCP code.

## Status

Early active development. The first working discovery-to-graph-to-attack-path pipeline is in place. Next layers are richer MCP discovery, identity/authorization modeling, runtime discovery, policy analysis, and graph backends.
