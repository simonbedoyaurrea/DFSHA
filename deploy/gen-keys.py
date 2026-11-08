#!/usr/bin/env python3
"""Genera las claves del clúster: par Ed25519 (firma de tokens), KEK (clave maestra) y token de clúster."""
import base64
import os
import pathlib
import secrets
import sys

from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "keys")
out.mkdir(parents=True, exist_ok=True)
if (out / "control_ed25519.pem").exists():
    print("ya existen claves en", out, "(bórralas si quieres regenerarlas)")
    sys.exit(0)
k = Ed25519PrivateKey.generate()
(out / "control_ed25519.pem").write_bytes(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
(out / "control_ed25519.pub").write_bytes(k.public_key().public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo))
(out / "kek.b64").write_text(base64.b64encode(os.urandom(32)).decode())
(out / "cluster_token").write_text(secrets.token_hex(16))
for f in out.iterdir():
    os.chmod(f, 0o600)
print("claves generadas en", out)
