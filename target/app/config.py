"""Settings for the CareLoop member API (a fictional GI care platform)."""
import os

# Documented example credentials from the AWS docs, kept here on purpose as a seeded flaw.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "careloop-signing-key-2024"
DB_PATH = os.environ.get("CARELOOP_DB", ":memory:")
VENDOR_WEBHOOK = "https://hooks.example-vendor.test/ingest"
