"""Demo-focused thin MVP lifecycle orchestration.

This package wires the per-module CompliStack services into a single
end-to-end demo flow used by ``POST /lifecycle/run-demo``. Each module
here is intentionally a small, deterministic stub driven by fixture
data so the demo is reliable and easy to reason about.
"""

from app.services.lifecycle.runner import SUPPORTED_SCENARIOS, run_demo_lifecycle

__all__ = ["run_demo_lifecycle", "SUPPORTED_SCENARIOS"]
