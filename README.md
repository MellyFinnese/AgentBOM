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

## AgentBOM v1: the format is independent of the tool

AgentBOM is a versioned interchange format, not only a CLI. The current schema is `1.0` and is designed so an independent implementation can produce documents without importing AgentBOM code.

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

Canonical schema: `schema/agentbom-v1.schema.json`  
Schema contract: `schema/README.md`  
Schema changelog: `schema/CHANGELOG.md`  
Specification: `docs/AGENTBOM-V1.md`  
Governance/RFC process: `GOVERNANCE.md`

Validate a document produced by any implementation:

```bash
agentbom validate third-party-agentbom.json
```

Consume and re-emit a validated document without using internal graph classes:

```bash
agentbom ingest third-party-agentbom.json > normalized.json
```

The repository includes a Go-style third-party producer fixture at `examples/spec/go-producer/agentbom.json`; CI validates it against the canonical schema.

## Distribution and CI

A GitHub Action is included at `.github/workflows/agentbom-scan.yml` for a drop-in CI security scan. It validates the format and emits SARIF for GitHub code scanning.

```bash
agentbom sarif ./target --output agentbom.sarif
```

Prebuilt Python/native wheels are produced for common Linux, macOS, and Windows targets by `.github/workflows/release.yml` on version tags.

## Public correctness corpus

`corpus/` contains versioned golden security cases and safe controls. The project uses this corpus to make detection behavior explainable and regression-testable. See `corpus/README.md`.

Threat-model and detection boundaries are documented in `docs/THREAT-MODEL.md`.

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

### MCP capability discovery

Parse a real captured `tools/list` response into normalized tool definitions:

```bash
agentbom mcp-discover tools-list.json --output agentbom-tools.json
```

The MCP gateway can then use the definitions to resolve action/resource context automatically before policy evaluation.

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

### Runtime behavior and enforcement

```bash
agentbom behavior-check ./mcp.json events.json --fail-on-risk
agentbom enforce ./mcp.json request.json --rules policy.json --audit
agentbom mcp-gateway ./mcp.json request.json --tool-definitions agentbom-tools.json --rules policy.json --fail-on-deny
```

The Rust engine distinguishes:

- **CAN** — effective delegated authority and reachable resources.
- **DID** — observed runtime behavior.
- **SHOULD** — policy and enforcement decision.

## Interoperability

AgentBOM intentionally avoids replacing established policy languages or IAM semantics where interoperability is useful. Provider permissions normalize into the AgentBOM authorization model, while future policy integrations can map to existing policy systems such as Cedar or OPA/Rego. The novel semantic layer is the relationship between agent capabilities, delegated authority, MCP tool execution, runtime observations, and attack paths.

## Status

Early active development. The architecture and major native analysis foundations are in place. The immediate project priority is ecosystem validation: third-party producers/consumers, SARIF/CI adoption, a growing public golden corpus, independent review, and production-grade provider integrations.
