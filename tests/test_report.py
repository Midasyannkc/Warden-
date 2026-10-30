import os
import subprocess
import sys

CODE = "import json\nfrom warden import report\nprint(json.dumps(report.build(), default=str))\n"


def build_with_seed(seed):
    p = subprocess.run([sys.executable, "-c", CODE], capture_output=True, text=True, env={**os.environ, "PYTHONHASHSEED": str(seed)})
    assert p.returncode == 0, p.stderr[-500:]
    return p.stdout.strip().splitlines()[-1]


def test_report_is_byte_for_byte_reproducible():
    """A committed report that changes on every run cannot be diffed, reviewed or trusted as evidence."""
    assert build_with_seed(1) == build_with_seed(2)
