# AgentBOM

AI agent security and attack-surface intelligence.

AgentBOM models autonomous AI systems as relationships between agents, models, tools, identities, credentials, capabilities, data, and deployments. The goal is to determine **what exists, what an agent can do, what authority it holds, what it can reach, what is actually happening at runtime, and what changes over time**.

## Rust-native architecture

AgentBOM is **Rust-first**. The security engine is implemented once in native Rust and exposed through stable bindings:

```text
                           AgentBOM
                              |
                       Rust Security Engine
                              |
             +----------------+----------------+
             |                |                |
          Python             C ABI            WASM
          / CLI              / FFI
             |                |
          Tooling        C/C++/Go/etc.
```

`agentbom-core` contains graph primitives. `agentbom-engine` is the stable native API and owns graph traversal, authorization, policy, attack paths, blast radius, runtime correlation, attestations, and temporal drift. `agentbom-ffi` publishes the C ABI, `agentbom-python` exposes the same engine through PyO3, and `agentbom-wasm` exposes the analysis API to WebAssembly. Security-critical analysis is not maintained as a second Python implementation.

CI builds the native workspace, C ABI, and WebAssembly target.

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

The native Rust engine evaluates wildcard grants, production mutation authority, configuration-referenced credentials, dangerous tool capabilities, reachable high-impact resources, blast radius, graph drift, and runtime anomalies.

Authorization adapters provide a provider-neutral ingestion boundary for AWS IAM, GCP IAM, Azure RBAC, Kubernetes RBAC, OAuth scopes, and MCP authorization data. The adapters normalize policy JSON into one permission model so the analysis engine stays provider-agnostic.

Runtime monitoring uses a declared-target set and flags observed events aimed at undeclared runtime targets. Attestations are bound to the engine's stable graph digest, with a pluggable signer interface for external signing systems.

Temporal snapshots compare the normalized security graph across scans and highlight newly introduced entities, permissions, credentials, tools, and relationships. Baselines are canonicalized and SHA-256 digested before comparison.

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
                | graph / auth / policy    |
                | paths / blast / drift    |
                | runtime / attestation    |
                +-----------+-------------+
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
        Authorization      Evidence      Bindings
             |                            |
             v                   +--------+--------+
        Attack Paths             |        |        |
             |                Python     C ABI    WASM
             v
        Blast Radius
             |
             v
       Reporting / CI
```

## Design principles

- **Rust-first:** one authoritative native implementation for security-critical analysis.
- **Stable bindings:** C ABI for broad interoperability, PyO3 for Python ergonomics, and WebAssembly for portable embedding.
- **Provider-neutral authorization:** cloud/IAM/OAuth/MCP permissions normalize into the same model.
- **Domain-first:** the security model comes before integrations.
- **Capability-aware:** capabilities and authorization are modeled explicitly.
- **Authority-aware:** identity, credentials, permission grants, effects, conditions, and resource scope are first-class concepts.
- **Runtime-aware:** observed state can be compared against declared authority.
- **Temporal:** security changes are evaluated against verified baselines rather than raw text diffs.
- **Evidence-backed:** discoveries retain source and provenance metadata.
- **Graph-native:** relationships are part of the security model, not an enrichment step.
- **Deterministic:** policy, path, blast-radius, reconciliation, snapshot, drift, and attestation operations are reproducible and bounded.
- **Backend-neutral:** the engine can use JSON locally and can be extended to graph backends without changing the security model.
- **Safe discovery:** configuration inspection and runtime discovery do not execute arbitrary agent or MCP code.

## Status

Early active development. The Rust-native graph engine, authorization abstraction, provider adapter boundary, stable engine API, C FFI, PyO3 binding, WASM binding, discovery, policy, attack-path, blast-radius, runtime monitoring, attestation, and temporal drift foundations are in place. Next major work is production-grade cloud/provider ingestion, concrete Memgraph/Neo4j persistence, continuous monitoring agents, and cryptographic attestation integrations.
