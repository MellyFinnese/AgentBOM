# AgentBOM Threat Model

## Purpose

AgentBOM analyzes AI-agent systems and can optionally enforce policy at tool/MCP boundaries. It is not an identity provider, secrets manager, sandbox, cloud authorization service, or malware detector.

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

## Explicit authorization boundary

AgentBOM normalizes provider policy, but it does **not** claim to be a byte-for-byte replacement for a cloud provider's authorization engine. Provider-specific conditions, permission boundaries, session policies, service-control policies, resource policies, and other semantics may be represented as conditions or provider metadata.

The native authorization evaluator supports hierarchical `*`/`?` matching, explicit deny precedence, and a conservative subset of common condition operators. An unresolved or unsupported condition makes authorization **indeterminate and non-allowing**. Consumers must not interpret an indeterminate result as proof of access.

## Graph reachability semantics

A graph path is not automatically proof that an agent can execute an action. Relationships may represent declared capability, observed behavior, or desired policy state. Edges can carry `evidence_state=can|did|should`; security-path and blast-radius analysis uses the `can` view, while runtime analysis can explicitly query `did` and policy intent can query `should`.

An agent being graph-reachable to a resource therefore means **the supplied graph evidence supports a path**, not that the external IAM provider would necessarily authorize the action under every runtime condition.

## Blast-radius model

`BlastRadius.score` is an explicit **graph-impact score**, not a probabilistic exploit-risk score. Critical/high sensitivity establish severity floors so one critical resource cannot be diluted by distance or by a larger number of medium resources. Sensitivity should be supplied as explicit metadata where possible; name-based classification is treated as a visible heuristic and is included in finding evidence.

Path enumeration is bounded by an engine-level analysis path cap to prevent adversarial graph structure from forcing unbounded path expansion.

## Evidence and uncertainty

Every high-impact detection should identify the graph relationships and observations that produced it. Provider provenance, sensitivity reasons, and unresolved authorization conditions should be surfaced rather than hidden.

## False-positive / false-negative policy

The project favors explainable findings over opaque aggregate scores. Security-sensitive uncertainty is biased toward **non-allowing / needs-review** rather than silently granting authority. Test corpora must include both vulnerable and safe fixtures to guard against regressions.
