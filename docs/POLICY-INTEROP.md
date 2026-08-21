# Policy Interoperability

AgentBOM does not need to invent a proprietary policy language to model agent security.

## Adapter boundary

AgentBOM normalizes policy inputs into its native decision model:

- principal / agent
- action
- resource
- effect
- conditions
- provenance

Policy engines can remain authoritative for their own policy languages. AgentBOM adapters should translate into or consume a decision at the enforcement boundary rather than reimplementing the full semantics of an external language.

## Cedar / OPA direction

The intended integration model is:

```text
Cedar policy / OPA-Rego policy
          |
          v
 external policy evaluator
          |
          v
 AgentBOM decision adapter
          |
          v
 ALLOW / DENY / REQUIRE_APPROVAL
```

The AgentBOM graph remains responsible for agent identity, delegation, capability, relationship, runtime, and attack-path context. External policy engines can remain responsible for policy-language semantics.

## Novelty budget

The project should spend bespoke semantic complexity on areas that existing IAM and policy engines do not model well together: agent delegation chains, MCP capabilities, effective agent authority, runtime-vs-declared behavior, and attack-path correlation.
