# AgentBOM Schema

AgentBOM is a versioned interchange format. The schema is intentionally independent from the AgentBOM CLI and Rust engine.

## Compatibility contract

A producer written in any language can emit an AgentBOM v1 document by following `agentbom-v1.schema.json`. A consumer can validate and ingest that document without using the AgentBOM implementation.

The minimum interoperability requirement is:

1. Emit `schema_version: "1.0"`.
2. Emit the required `document`, `entities`, `relationships`, and `evidence` fields.
3. Preserve stable entity IDs and relationship endpoints.
4. Treat unknown optional fields conservatively and do not rely on implementation-private fields.

## Versioning

Schema versions are independent of CLI releases. Breaking changes require a new major schema version. Backwards-compatible additions may be released as minor versions and documented in `CHANGELOG.md`.

## Multi-implementation test

`examples/spec/go-producer/agentbom.json` is a language-independent compatibility fixture representing a document that could be emitted by a Go producer. CI validates it against the canonical schema.

## Governance

Schema changes follow the RFC process in `GOVERNANCE.md`. The schema directory is the canonical source in this repository until a neutral standalone specification repository is established.
