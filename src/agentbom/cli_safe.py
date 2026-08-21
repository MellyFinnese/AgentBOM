"""Safe console entry point that converts engine build failures into clear CLI errors."""

from __future__ import annotations

import sys

from .cli import main as _main


def main() -> int:
    try:
        return _main()
    except RuntimeError as exc:
        print(f"AgentBOM error: {exc}", file=sys.stderr)
        print(
            "Hint: install the native engine with `python -m pip install .` "
            "using the pinned Rust toolchain, or build it with maturin.",
            file=sys.stderr,
        )
        return 2
