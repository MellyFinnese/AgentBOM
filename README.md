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

`agentbom-core` contains graph primitives. `agentbom-engine` is the stable native API and owns graph traversal, authorization, delegation, policy, attack paths, blast radius, runtime correlation, attestations, and temporal drift. `agentbom-ffi` publishes the C ABI, `agentbom-python` exposes the same engine through PyO3, and `agentbom-wasm` exposes the analysis API to WebAssembly. Security-critical analysis is not maintained as a second Python implementation.

## AgentBOM v1

AgentBOM is also a versioned interchange format, not only a CLI. The current schema is `1.0`:

```text
AgentBOM v1
├── document metadata
├── entities
├── relationships
├── evidence
├── findings
├── attack paths
└── attestation
```

Schema: `schema/agentbom-v1.schema.json`

Specification: `docs/AGENTBOM-V1.md`

Generate a portable AgentBOM document:

```bash
agentbom spec ./mcp.json --output agentbom.json
```

## Current vertical slice

AgentBOM can inspect an MCP-style JSON manifest without executing the configured server:

```bash
agentbom scan ./mcp.json
agentbom scan ./mcp.json --auth --paths --policy --blast-radius
agentbom scan ./mcp.json --runtime --reconcile
agentbom scan ./mcp.json --behavior-events events.json --fail-on-risk
agentbom scan ./mcp.json --save-baseline .agentbom/baseline.json
agentbom scan ./mcp.json --compare-baseline .agentbom/baseline.json
```

### Provider authorization

Normalize provider-specific authorization through the Rust engine:

```bash
agentbom auth-parse aws-iam policy.json
agentbom auth-parse gcp-iam policy.json
agentbom auth-parse azure-rbac policy.json
agentbom auth-parse kubernetes-rbac policy.json
agentbom auth-parse oauth scopes.json
agentbom auth-parse mcp policy.json
```

### Effective authority and delegation

AgentBOM treats delegation as a security relationship, not just metadata:

```text
User
 ↓ delegates
Agent A
 ↓ delegates
Agent B
 ↓ grants
Permission
 ↓ accesses
Resource
```

Resolve what a principal can reach through bounded delegation:

```bash
agentbom authority ./mcp.json agent-a --max-hops 8
agentbom authority ./mcp.json agent-a --findings
```

Correlate that authority with tools, permissions, and reachable resources:

```bash
agentbom attack-paths ./mcp.json agent-a --findings
```

This exposes transitive authority and shows the full graph path behind a risky finding.

### Runtime behavior correlation

Compare observed runtime events against the effective security graph:

```bash
agentbom behavior-check ./mcp.json events.json --findings
agentbom behavior-check ./mcp.json events.json --fail-on-risk
```

Or include behavior correlation in a scan:

```bash
agentbom scan ./mcp.json --behavior-events events.json --fail-on-risk
```

The Rust engine distinguishes between:

- **Observed behavior that matches a reachable attack path**
- **Observed behavior that cannot be explained by the current security graph**

High and critical behavior findings can fail CI with `--fail-on-risk`.

### Runtime, policy, graph, and attestation workflows

```bash
agentbom monitor events.json --declared declared.json
agentbom cypher ./mcp.json
agentbom policy-check write production-db --rules policy.json
agentbom attest ./mcp.json --output attestation.json
```

The native Rust engine evaluates wildcard grants, production mutation authority, configuration-referenced credentials, dangerous tool capabilities, reachable high-impact resources, blast radius, graph drift, runtime anomalies, delegated authority, and observed runtime behavior.

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
                | graph / identity / auth  |
                | delegation / policy      |
                | paths / blast / drift    |
                | runtime / behavior      |
                | attestation             |
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
       Runtime Correlation
             |
             v
       Reporting / CI / Enforcement
```

## Design principles

- **Rust-first:** one authoritative native implementation for security-critical analysis.
- **Stable bindings:** C ABI for broad interoperability, PyO3 for Python ergonomics, and WebAssembly for portable embedding.
- **Versioned format:** AgentBOM v1 defines a stable interchange document independent of the implementation language.
- **Provider-neutral authorization:** cloud/IAM/OAuth/MCP permissions normalize into the same model.
- **Delegation-aware:** effective authority is resolved across bounded delegation, assume, and impersonation relationships.
- **Behavior-aware:** runtime activity is correlated against the modeled authority and attack graph.
- **Domain-first:** the security model comes before integrations.
- **Capability-aware:** capabilities and authorization are modeled explicitly.
- **Authority-aware:** identity, credentials, permission grants, effects, conditions, and resource scope are first-class concepts.
- **Runtime-aware:** observed state can be compared against declared authority.
- **Temporal:** security changes are evaluated against verified baselines rather than raw text diffs.
- **Evidence-backed:** discoveries retain source and provenance metadata.
- **Graph-native:** relationships are part of the security model, not an enrichment step.
- **Deterministic:** policy, path, blast-radius, reconciliation, delegation, behavior, snapshot, drift, and attestation operations are reproducible and bounded.
- **Backend-neutral:** the engine can use JSON locally and can be extended to graph backends without changing the security model.
- **Safe discovery:** configuration inspection and runtime discovery do not execute arbitrary agent or MCP code.

## Status

Early active development. The Rust-native graph engine, AgentBOM v1 schema, authorization/delegation model, provider adapter boundary, stable engine API, C FFI, PyO3 binding, WASM binding, discovery, policy, attack-path, blast-radius, runtime monitoring, behavior correlation, attestation, and temporal drift foundations are in place. Next major work is production-grade cloud/provider ingestion, concrete Memgraph/Neo4j persistence, continuous monitoring agents, enforcement adapters, and cryptographic attestation integrations.
