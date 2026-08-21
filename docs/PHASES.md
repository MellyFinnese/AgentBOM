# AgentBOM implementation phases

AgentBOM is built as a Rust-first security engine with language bindings and thin discovery/orchestration layers.

## 1. Authorization intelligence

The native engine defines a provider-neutral authorization model containing principals, actions, resources, effects, providers, and conditions. JSON adapters can load normalized permissions and compute effective non-denied grants.

Supported ingestion shape is intentionally provider-neutral so AWS IAM, GCP IAM, Azure RBAC, Kubernetes RBAC, OAuth/OIDC scopes, GitHub permissions, service accounts, and MCP authorization adapters can normalize into the same model.

## 2. Attack graph

The graph is the security model. Bounded traversal identifies reachable high-impact nodes, and native query APIs answer questions such as which paths reach a resource class and which agents can reach a sensitive node type.

## 3. Runtime intelligence

The native runtime model records typed events with timestamps, agents, targets, and metadata. The Python runtime collector remains responsible for safe host observation; normalized events can be fed into the same Rust analysis engine.

## 4. Enforcement

The engine exposes deterministic `Allow`, `Deny`, and `RequireApproval` decisions against policy rules with wildcard matching and stable rule IDs. This is designed to sit in front of tool/API execution rather than modify the underlying agent itself.

## 5. Attestation

An AgentBOM attestation binds a graph digest to a schema version, creation time, engine version, and graph summary. A stable SHA-256 attestation digest is available as the signing payload identifier; external signing keys remain an integration concern.

## 6. Temporal security

Native graph diffs and drift findings compare verified baselines against current graphs. Existing Python snapshot storage can persist these artifacts while the Rust engine performs the security comparison.

## 7. Portability

The authoritative engine is Rust. The stable C ABI targets C/C++ and other FFI consumers, while PyO3 provides Python integration. WebAssembly is treated as an additional binding target rather than a second implementation.

## 8. Enterprise backends

The `GraphBackend` abstraction keeps persistence backend-neutral. JSON is the built-in portable backend. Memgraph/Neo4j adapters can be implemented above the same engine without moving security logic into the database layer.
