# AgentBOM Security Corpus

This directory is a public golden corpus for correctness testing. Each case documents the intended security property, the expected finding IDs, and the minimum evidence required.

The corpus is deliberately versioned independently from implementation code. Adding a case should prefer a minimal reproducer that isolates one security property.

## Current corpus

The v1 corpus contains **12 cases** spanning **MCP, AWS, and GCP** inputs, with both vulnerable cases and safe controls.

Coverage includes:

- excessive MCP filesystem authority
- undeclared MCP shell execution
- AWS wildcard administrator authority
- AWS production data reads
- AWS production writes
- AWS delegated privilege escalation
- AWS credential/secret reads
- AWS least-privilege and explicit-deny safe controls
- GCP owner-level authority
- GCP production data reads
- GCP production writes
- GCP read-only safe control

The corpus is a starting point, not a claim of complete coverage. Every promoted detection should include a safe control case where practical.
