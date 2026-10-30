"""Settings for the CareLoop member API (a fictional GI care platform).

Secrets come from the environment (in production, injected from a secrets manager)."""
import os


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


JWT_SECRET = _required("CARELOOP_JWT_SECRET")
DB_PATH = os.environ.get("CARELOOP_DB", ":memory:")
VENDOR_WEBHOOK = "https://hooks.example-vendor.test/ingest"
