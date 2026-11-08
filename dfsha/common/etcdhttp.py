"""Cliente mínimo de etcd v3 usando su gateway HTTP/JSON (/v3/...).

Se usa el gateway JSON en lugar de gRPC directo para evitar problemas de
compatibilidad con protobuf; las garantías (Raft, transacciones, leases) son las mismas.
"""
import base64
import json
import ssl
from dataclasses import dataclass

import httpx


def b64e(s):
    if isinstance(s, str):
        s = s.encode()
    return base64.b64encode(s).decode()


def b64d(s):
    return base64.b64decode(s).decode() if s else ""


@dataclass
class KV:
    key: str
    value: str
    create_rev: int
    mod_rev: int
    version: int
    lease: int

    def json(self):
        return json.loads(self.value)


def _kv(d):
    return KV(b64d(d["key"]), b64d(d.get("value", "")), int(d.get("create_revision", 0)),
              int(d.get("mod_revision", 0)), int(d.get("version", 0)), int(d.get("lease", 0)))


def prefix_end(prefix):
    b = bytearray(prefix.encode())
    for i in range(len(b) - 1, -1, -1):
        if b[i] < 0xFF:
            b[i] += 1
            return bytes(b[: i + 1])
    return b"\x00"


# --- constructores de comparaciones y operaciones para transacciones ---
def cmp_mod(key, rev, result="EQUAL"):
    return {"key": b64e(key), "target": "MOD", "result": result, "mod_revision": str(rev)}


def cmp_version(key, ver, result="EQUAL"):
    return {"key": b64e(key), "target": "VERSION", "result": result, "version": str(ver)}


def cmp_create(key, rev, result="EQUAL"):
    return {"key": b64e(key), "target": "CREATE", "result": result, "create_revision": str(rev)}


def put_op(key, value, lease=0):
    return {"request_put": {"key": b64e(key), "value": b64e(value), "lease": str(lease)}}


def del_op(key):
    return {"request_delete_range": {"key": b64e(key)}}


class EtcdError(Exception):
    pass


class Etcd:
    def __init__(self, endpoints, ca=None, cert=None, key=None, timeout=5.0):
        self.endpoints = [e.rstrip("/") for e in endpoints]
        self._i = 0
        verify = True
        if ca:
            verify = ssl.create_default_context(cafile=ca)
            if cert and key:
                verify.load_cert_chain(cert, key)
        self.http = httpx.Client(verify=verify, timeout=httpx.Timeout(timeout, connect=2.0))

    def _post(self, path, body):
        last = None
        n = len(self.endpoints)
        for k in range(n):
            idx = (self._i + k) % n
            try:
                r = self.http.post(self.endpoints[idx] + path, json=body)
                if r.status_code == 200:
                    self._i = idx
                    return r.json()
                last = EtcdError(f"{r.status_code} {r.text}")
            except httpx.HTTPError as e:
                last = e
        raise EtcdError(str(last))

    def put(self, key, value, lease=0):
        self._post("/v3/kv/put", {"key": b64e(key), "value": b64e(value), "lease": str(lease)})

    def get(self, key):
        r = self._post("/v3/kv/range", {"key": b64e(key)})
        kvs = r.get("kvs")
        return _kv(kvs[0]) if kvs else None

    def revision(self):
        """Revisión global observada por una lectura linealizable."""
        r = self._post("/v3/kv/range", {"key": b64e("/catalog/epoch")})
        return int(r["header"]["revision"])

    def get_prefix(self, prefix):
        r = self._post("/v3/kv/range", {"key": b64e(prefix), "range_end": b64e(prefix_end(prefix))})
        return [_kv(x) for x in r.get("kvs", [])]

    def delete(self, key):
        self._post("/v3/kv/deleterange", {"key": b64e(key)})

    def delete_prefix(self, prefix):
        self._post("/v3/kv/deleterange", {"key": b64e(prefix), "range_end": b64e(prefix_end(prefix))})

    def txn(self, compare, success, failure=None):
        """Devuelve (ok, revision, respuestas). Es atómica en todo el clúster (Raft)."""
        r = self._post("/v3/kv/txn", {"compare": compare, "success": success, "failure": failure or []})
        return bool(r.get("succeeded", False)), int(r["header"]["revision"]), r.get("responses", [])

    def lease_grant(self, ttl):
        return int(self._post("/v3/lease/grant", {"TTL": str(int(ttl))})["ID"])

    def lease_keepalive(self, lease_id):
        r = self._post("/v3/lease/keepalive", {"ID": str(lease_id)})
        return int(r.get("result", {}).get("TTL", 0) or 0)

    def lease_revoke(self, lease_id):
        self._post("/v3/lease/revoke", {"ID": str(lease_id)})
