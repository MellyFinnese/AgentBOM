"""Minimal CLI entrypoint; discovery commands will be added incrementally."""

from __future__ import annotations

import argparse

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentbom",
        description="AI agent security and attack-surface intelligence.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("info", help="Show the AgentBOM foundation status")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "info":
        print("AgentBOM foundation: domain, evidence, graph, capability, and analysis boundaries")
        return 0
    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
