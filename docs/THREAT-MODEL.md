# AgentBOM Threat Model

## Purpose

AgentBOM analyzes AI-agent systems and can optionally enforce policy at tool/MCP boundaries. It is not an identity provider, secrets manager, sandbox, or malware detector.

## Assets

- agent identities and delegated authority
- credentials and authorization relationships
- MCP/tool capabilities
- sensitive resources
- runtime observations
- policy decisions and attestations
- AgentBOM documents and evidence

## Trust boundaries

1. **Discovery → AgentBOM graph**: input may be incomplete, stale, or attacker-controlled.
2. **AgentBOM graph → analysis engine**: malformed relationships must not cause privilege to be invented.
3. **Agent/tool runtime → enforcement gateway**: requests are untrusted and must be normalized before policy evaluation.
4. **AgentBOM → external graph backend**: exported queries must remain parameterized.
5. **Attestation output → consumers**: consumers must verify signatures and freshness rather than trusting unsigned metadata.

## Threats AgentBOM is designed to help detect

- excessive or transitive agent authority
- dangerous delegation and impersonation chains
- reachable sensitive resources
- mismatches between declared and observed behavior
- policy violations at tool/MCP boundaries
- configuration drift that increases blast radius
- incomplete or suspicious agent capability declarations

## Explicit non-goals

AgentBOM does not prove that an agent is safe. It cannot observe actions outside the monitored boundary, infer hidden authority that is absent from the input data, or replace a cloud provider's authorization service. Runtime findings depend on telemetry coverage.

## Detection philosophy

Prefer deterministic findings with explicit evidence and a bounded analysis path. When context cannot be resolved confidently, report the uncertainty rather than silently granting or denying authority.

## False-positive / false-negative policy

The project favors explainable findings over opaque aggregate scores. Each high-impact detection should identify the graph relationships and observations that produced it. Test corpora must include both vulnerable and safe fixtures to guard against regressions.
