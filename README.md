# AgentBOM

AI agent security and attack-surface intelligence.

AgentBOM models autonomous AI systems as relationships between agents, models, tools, identities, credentials, capabilities, data, and deployments. The goal is to determine **what exists, what an agent can do, what authority it holds, what it can reach, what is actually happening at runtime, and what changes over time**.

## Rust-native architecture

AgentBOM is now **Rust-first**. The security engine is implemented once in native Rust and exposed through stable bindings:

```text
                           AgentBOM
                              |
                       Rust Security Engine
                              |
             +----------------+----------------+
             |                |                |
          Python             C ABI            WASM* 
          / CLI              / FFI
             |                |
          Tooling        C/C++/Go/etc.
```

`agentbom-core` contains graph primitives. `agentbom-engine` is the stable native API. `agentbom-ffi` publishes the C ABI, and `agentbom-python` exposes the same engine through PyO3. Security-critical graph operations are not reimplemented in Python.

The Rust workspace is tested and built independently by CI, including the C FFI artifact.

## Current vertical slice

AgentBOM can inspect an MCP-style JSON manifest without executing the configured server:

```bash
agentbom scan ./mcp.json
agentbom scan ./mcp.json --auth
agentbom scan ./mcp.json --paths
agentbom scan ./mcp.json --policy
agentbom scan ./mcp.json --blast-radius
agentbom scan ./mcp.json --runtime --reconcile
agentbom scan ./mcp.json --save-baseline .agentbom/baseline.json
agentbom scan ./mcp.json --compare-baseline .agentbom/baseline.json
agentbom scan ./mcp.json --json --auth --paths --policy --blast-radius --runtime --reconcile --compare-baseline .agentbom/baseline.json
```

Discovery normalizes declared agents, MCP servers, tools, credentials, capabilities, identities, permission grants, and resource scope into the AgentBOM graph.

The deterministic policy engine detects wildcard grants, production mutation authority, configuration-referenced credentials, dangerous tool capabilities, and reachable high-impact resources.

The blast-radius engine estimates what an agent can ultimately affect. Runtime discovery compares observed local state with declared authority. Temporal snapshots then compare the normalized security graph across scans, highlighting newly introduced entities, permissions, credentials, tools, and relationships.

Baselines are canonicalized and SHA-256 digested. A baseline must verify successfully before drift analysis is performed.

## Temporal drift

```text
Baseline
   |
   v
Security Graph ----> Current Graph
      \\              /
       \\            /
        +--> Semantic Diff
                 |
                 v
          Drift Findings
```

Drift is reported as added/removed/changed entities and added/removed relationships, with elevated severity for sensitive entity kinds and high-impact authorization relationships.

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
                +-------------------------+
                | Rust Security Engine     |
                | graph / paths / policy   |
                | blast radius / drift     |
                +-----------+-------------+
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
        Authorization      Evidence      Bindings
             |                            |
             v                   +--------+--------+
        Attack Paths             |        |        |
             |                Python     C ABI    WASM*
             v
        Blast Radius
             |
             v
       Reporting / CI

* planned binding; not yet shipped
```

## Design principles

- **Rust-first:** one authoritative native implementation for security-critical analysis.
- **Stable bindings:** C ABI for broad interoperability and PyO3 for Python ergonomics.
- **Domain-first:** the security model comes before integrations.
- **Capability-aware:** capabilities and authorization are modeled explicitly.
- **Authority-aware:** identity, credentials, permission grants, effects, conditions, and resource scope are first-class concepts.
- **Runtime-aware:** observed state can be compared against declared authority.
- **Temporal:** security changes are evaluated against verified baselines rather than raw text diffs.
- **Evidence-backed:** discoveries retain source and provenance metadata.
- **Graph-native:** relationships are part of the security model, not an enrichment step.
- **Deterministic:** policy, path, blast-radius, reconciliation, snapshot, and drift analysis are reproducible and bounded.
- **Backend-neutral:** local analysis does not require a graph database.
- **Extensible discovery:** MCP, configuration, runtime, and cloud sources can feed the same model.
- **Safe discovery:** configuration inspection and runtime discovery do not execute arbitrary agent or MCP code.

## Status

Early active development. The Rust-native graph engine, stable engine API, C FFI boundary, Python binding, discovery, authorization, policy, blast-radius, runtime reconciliation, and temporal drift foundations are in place. Next major layers are moving the remaining policy/blast-radius/drift algorithms fully into Rust, richer IAM/API authorization ingestion, graph backends, continuous monitoring, and signed/attested baseline workflows.
