# Contributing to AgentBOM

AgentBOM has two contracts: the **format contract** and the **implementation contract**.

## Format first

Changes under `schema/` are interoperability changes. Do not couple schema evolution to CLI release cadence. Add or update schema fixtures, changelog entries, and compatibility tests with every schema change.

## Implementation

Rust is the authoritative security engine. Python should remain an orchestration, discovery, and presentation layer. New security semantics belong in Rust first and then in bindings.

## RFCs

Use the governance process in `GOVERNANCE.md` for breaking or security-semantic changes.

## Tests

Every new detection should include at least one positive fixture and, where practical, a safe/negative fixture. Security behavior must be deterministic and explainable through evidence.
