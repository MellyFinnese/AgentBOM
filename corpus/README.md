# AgentBOM Security Corpus

This directory is a public golden corpus for correctness testing. Each case documents the intended security property, the expected finding IDs, and the minimum evidence required.

The corpus is deliberately versioned independently from implementation code. Adding a case should prefer a minimal reproducer that isolates one security property.

Initial corpus themes:

- excessive MCP filesystem authority
- shell execution without declared capability
- production write access through delegation
- safe read-only MCP behavior

The corpus is a starting point, not a claim of complete coverage. Every promoted detection should include a safe control case where practical.
