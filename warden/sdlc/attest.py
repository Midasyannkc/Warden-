"""Out-of-band attestations. CI signs the result of its security checks with an Ed25519 key
that lives in a different identity from anything an author or an AI agent can reach."""
from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def new_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, base64.b64encode(pub).decode()


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign(priv: Ed25519PrivateKey, key_id: str, payload: dict) -> dict:
    sig = priv.sign(canonical(payload))
    return {"key_id": key_id, "payload": payload, "signature": base64.b64encode(sig).decode()}


def verify(att: dict, keyring: dict[str, str]) -> bool:
    pub_b64 = keyring.get(att.get("key_id", ""))
    if not pub_b64:
        return False
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
    try:
        pub.verify(base64.b64decode(att["signature"]), canonical(att["payload"]))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False
