"""Tokens firmados con Ed25519 (EdDSA): acceso de usuario y permiso de bloque."""
import time

import jwt


def sign(claims, private_pem, ttl, typ):
    now = int(time.time())
    return jwt.encode({**claims, "typ": typ, "iat": now, "exp": now + int(ttl)},
                      private_pem, algorithm="EdDSA")


def verify(token, public_pem, typ):
    c = jwt.decode(token, public_pem, algorithms=["EdDSA"], options={"require": ["exp"]})
    if c.get("typ") != typ:
        raise jwt.InvalidTokenError("tipo de token incorrecto")
    return c
