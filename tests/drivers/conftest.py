"""pytest config for the drivers test suite.

Puts ``src/`` on sys.path so ``import drivers`` resolves without installing the
package, and provides mock transports + raw-output fixtures.
"""
from __future__ import annotations

import os
import sys

import pytest

# tests/drivers/ -> tests/ -> project root -> src/
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


class FakeTransport:
    """A scripted transport. Maps command -> (raw, success) or returns default.

    ``calls`` records every (vendor, command) tuple for assertions.
    """

    def __init__(
        self,
        responses=None,
        *,
        default=("", False),
        via="fake",
    ):
        self.responses = responses or {}
        self.default = default
        self.via = via
        self.calls = []

    def exec(self, vendor, command):
        self.calls.append((vendor, command))
        raw, success = self.responses.get(command, self.default)
        return raw, success, self.via


@pytest.fixture()
def fake_transport_factory():
    """Return the FakeTransport class so tests can build scripted transports."""
    return FakeTransport
