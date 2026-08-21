"""Thin Python boundary for the Rust AgentBOM security engine."""

from __future__ import annotations

try:
    from .agentbom_native import NativeGraph
except ImportError as exc:  # pragma: no cover - exercised only in non-built source trees
    NativeGraph = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def require_native() -> type:
    """Return the compiled Rust graph engine or fail with an actionable error."""
    if NativeGraph is None:
        raise RuntimeError(
            "AgentBOM Rust engine is not built. Install the package with `pip install .` "
            "or build the extension with maturin."
        ) from _IMPORT_ERROR
    return NativeGraph
