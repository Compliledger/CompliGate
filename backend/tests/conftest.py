import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Default the test suite to the explicit `static_allow` compliance
# providers so legacy tests keep exercising the success path. Individual
# tests may patch ``config`` to switch providers and verify fail-closed
# behaviour. The default `null` provider would otherwise cause every
# permit to be issued as ``decision_result=deny``.
import pytest
from app.core import config as _config


@pytest.fixture(autouse=True)
def _default_static_allow_providers(monkeypatch):
    monkeypatch.setattr(_config, "KYC_PROVIDER", "static_allow", raising=False)
    monkeypatch.setattr(_config, "SANCTIONS_PROVIDER", "static_allow", raising=False)
    monkeypatch.setattr(_config, "RESERVE_PROVIDER", "static_allow", raising=False)
    yield
