"""TLS / mTLS. Se activa con TLS=1 y CA_FILE, CERT_FILE, KEY_FILE."""
import ssl

import httpx

from . import config as C


def enabled():
    return C.getb("TLS", False)


def ssl_context(client_cert=False):
    ctx = ssl.create_default_context(cafile=C.get("CA_FILE"))
    if client_cert:
        ctx.load_cert_chain(C.get("CERT_FILE"), C.get("KEY_FILE"))
    return ctx


def http_client(timeout=10.0, mtls=False):
    t = httpx.Timeout(timeout, connect=2.0)
    if enabled():
        return httpx.Client(timeout=t, verify=ssl_context(client_cert=mtls))
    return httpx.Client(timeout=t)


def uvicorn_kwargs(require_client_cert=False):
    if not enabled():
        return {}
    kw = {"ssl_certfile": C.get("CERT_FILE"), "ssl_keyfile": C.get("KEY_FILE")}
    if require_client_cert:
        kw.update(ssl_ca_certs=C.get("CA_FILE"), ssl_cert_reqs=ssl.CERT_REQUIRED)
    return kw
