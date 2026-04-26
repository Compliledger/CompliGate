"""Factory for selecting the active sanctions provider.

The concrete sanctions provider is chosen at runtime based on the
``SANCTIONS_MODE`` environment variable:

* ``"mock"`` (default) returns a :class:`MockSanctionsProvider`, which
  simulates outcomes deterministically and never makes a network call.
* ``"live"`` is reserved for the real TRM integration. It is not yet
  wired up, so the factory raises :class:`NotImplementedError` to make
  the misconfiguration explicit at startup rather than failing silently
  at request time.
"""

from __future__ import annotations

import os

from app.services.providers.mock_sanctions_provider import MockSanctionsProvider
from app.services.providers.sanctions_provider import SanctionsProvider

#: Default mode used when ``SANCTIONS_MODE`` is unset.
_DEFAULT_SANCTIONS_MODE = "mock"


def _get_sanctions_mode() -> str:
    return os.getenv("SANCTIONS_MODE", _DEFAULT_SANCTIONS_MODE).strip().lower()


def get_sanctions_provider() -> SanctionsProvider:
    """Return the sanctions provider selected by ``SANCTIONS_MODE``."""

    mode = _get_sanctions_mode()
    if mode == "mock":
        return MockSanctionsProvider()
    if mode == "live":
        raise NotImplementedError("TRM provider not yet configured")
    raise ValueError(
        f"Unsupported SANCTIONS_MODE={mode!r}; expected 'mock' or 'live'"
    )


__all__ = ["get_sanctions_provider"]
