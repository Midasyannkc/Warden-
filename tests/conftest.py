import os

import pytest

# The target app reads its signing key from the environment; tests supply a throwaway value.
os.environ.setdefault("CARELOOP_JWT_SECRET", "test-only-throwaway-value")

from warden.scan import runner  # noqa: E402


@pytest.fixture(scope="session")
def scan_findings():
    """The four real scanners are cached by a hash of the scanned files, so this runs them
    only when the target changed (about 100 seconds when it does)."""
    return runner.run_all()
