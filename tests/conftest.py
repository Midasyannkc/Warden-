import pytest

from warden.scan import runner


@pytest.fixture(scope="session")
def scan_findings():
    """The four real scanners take about a minute; run them once per test session."""
    return runner.run_all()
