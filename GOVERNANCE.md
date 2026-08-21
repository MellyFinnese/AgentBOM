# AgentBOM Governance

AgentBOM is developed as an open security specification and implementation. The schema is intended to outlive any single CLI implementation.

## RFC process

Schema or semantic changes should be proposed as an RFC before implementation when they change interoperability, entity semantics, relationship semantics, or security interpretation.

Each RFC should state:

- problem and motivation
- proposed schema/semantic change
- compatibility impact
- migration strategy
- security and privacy impact
- test vectors and expected behavior

Changes that break document compatibility require a new major schema version. Additive compatible fields should be versioned and documented without coupling them to a CLI release.

## Review

Security-sensitive changes should receive at least one independent review before merge. The project welcomes reviewers from application security, identity, agent-security, and supply-chain-security communities.

## Reference implementation

The Rust engine and Python CLI are reference implementations, not the definition of the format. A conforming third-party implementation is valid even if it does not use Rust, Python, or this repository.

## Neutralization roadmap

The current canonical schema lives under `schema/` in this repository. As external implementers appear, the project should move the schema and RFC history into a neutral standalone repository with independent release/version governance.
