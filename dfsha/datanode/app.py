"""Nodo de datos: guarda bloques cifrados, replica hacia otros nodos y avisa al control que sigue vivo."""
import asyncio
import hashlib
import logging
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response

from ..common import config as C
from ..common import tls
from ..common import tokens as T
from .store import BlockConflictError, Store

log = logging.getLogger("dfsha.datanode")

NODE_ID = C.get("NODE_ID", "dn1")
PUBLIC_URL = C.get("PUBLIC_URL", "http://127.0.0.1:9001")
INTERNAL_URL = C.get("INTERNAL_URL", "http://127.0.0.1:9101")
W = C.geti("W", 2)
PUB = open(C.get("PUBLIC_KEY", "keys/control_ed25519.pub"), "rb").read()
CLUSTER_TOKEN = C.secret("CLUSTER_TOKEN", "")
CONTROL_URLS = C.getl("CONTROL_INTERNAL_URLS", "http://127.0.0.1:8100")
HEARTBEAT_INTERVAL = C.getf("HEARTBEAT_INTERVAL", 3)
BLOCKREPORT_INTERVAL = C.getf("BLOCKREPORT_INTERVAL", 30)
SCRUB_INTERVAL = C.getf("SCRUB_INTERVAL", 300)

store = Store(C.get("DATA_DIR", "./data"))
pub = FastAPI(title="DFSha nodo de datos (público)")
internal = FastAPI(title="DFSha nodo de datos (interno, mTLS)")
_http = None


def http():
    global _http
    if _http is None:
        _http = tls.http_client(timeout=10.0, mtls=True)
    return _http


def err(status, code, message=""):
    raise HTTPException(status, detail={"error": code, "message": message})


def check_token(token, bid, gen, op):
    if not token:
        err(401, "UNAUTHENTICATED", "falta el token de bloque")
    try:
        c = T.verify(token, PUB, "block")
    except jwt.PyJWTError:
        err(401, "UNAUTHENTICATED", "token de bloque inválido o vencido")
    if c["bid"] != bid or int(c["gen"]) != gen or c["op"] != op:
        err(403, "FORBIDDEN", "el token no corresponde a este bloque u operación")
    return c


def check_cluster(token):
    if CLUSTER_TOKEN and not secrets.compare_digest(token or "", CLUSTER_TOKEN):
        err(403, "FORBIDDEN", "token de clúster inválido")


# ------------------------------------------------------------------ API pública (clientes)
@pub.get("/health")
def health():
    return {"ok": True, "id": NODE_ID}


def coordinate(bid, gen, data, sha, nodes):
    """Guarda localmente y reenvía a las demás réplicas; confirma con quórum W."""
    others = [n for n in nodes if n["id"] != NODE_ID]

    def local():
        store.write(bid, gen, data, sha)

    def forward(n):
        r = http().put(n["internal_url"] + f"/internal/replicas/{bid}", params={"gen": gen}, content=data,
                       headers={"X-Sha256": sha, "X-Cluster-Token": CLUSTER_TOKEN})
        r.raise_for_status()

    stored, failed = [], []
    with ThreadPoolExecutor(len(others) + 1) as ex:
        futs = [(NODE_ID, ex.submit(local))] + [(n["id"], ex.submit(forward, n)) for n in others]
        for nid, f in futs:
            try:
                f.result()
                stored.append(nid)
            except Exception as e:  # noqa: BLE001
                log.warning("réplica %s falló para %s: %s", nid, bid, e)
                failed.append(nid)
    need = W
    if len(stored) < need:
        raise HTTPException(503, detail={"error": "INSUFFICIENT_REPLICAS", "stored": stored, "failed": failed,
                                         "message": f"solo {len(stored)} de {need} copias necesarias"})
    return {"stored": stored, "failed": failed, "quorum": True}


@pub.put("/v1/blocks/{bid}", status_code=201)
async def put_block(bid: str, gen: int, request: Request, x_block_token: Optional[str] = Header(None),
                    x_sha256: Optional[str] = Header(None)):
    c = check_token(x_block_token, bid, gen, "w")
    if NODE_ID not in [n["id"] for n in c["nodes"]]:
        err(403, "FORBIDDEN", "este nodo no está en el conjunto de réplicas del token")
    data = await request.body()
    if hashlib.sha256(data).hexdigest() != (x_sha256 or ""):
        err(422, "CHECKSUM_MISMATCH", "la huella SHA-256 no coincide con el contenido recibido")
    return await asyncio.to_thread(coordinate, bid, gen, data, x_sha256, c["nodes"])


@pub.get("/v1/blocks/{bid}")
def get_block(bid: str, gen: int, x_block_token: Optional[str] = Header(None)):
    check_token(x_block_token, bid, gen, "r")
    r = store.read(bid, gen)
    if r is None:
        err(404, "NOT_FOUND", "este nodo no tiene el bloque")
    return Response(r[0], media_type="application/octet-stream", headers={"X-Sha256": r[1]})


# ------------------------------------------------------------------ API interna (nodo <-> nodo)
@internal.put("/internal/replicas/{bid}", status_code=201)
async def put_replica(bid: str, gen: int, request: Request, x_sha256: Optional[str] = Header(None),
                      x_cluster_token: Optional[str] = Header(None)):
    check_cluster(x_cluster_token)
    data = await request.body()
    if hashlib.sha256(data).hexdigest() != (x_sha256 or ""):
        err(422, "CHECKSUM_MISMATCH", "huella inválida en la réplica")
    try:
        await asyncio.to_thread(store.write, bid, gen, data, x_sha256)
    except BlockConflictError:
        err(409, "BLOCK_CONFLICT", "el identificador ya contiene otro bloque")
    return {"stored": NODE_ID}


@internal.get("/internal/blocks/{bid}/verify")
def verify_block(bid: str, gen: int, x_cluster_token: Optional[str] = Header(None)):
    """El control comprueba el contenido persistido por el canal interno autenticado."""
    check_cluster(x_cluster_token)
    r = store.read(bid, gen)
    if r is None:
        err(404, "NOT_FOUND", "este nodo no tiene el bloque completo")
    digest = hashlib.sha256(r[0]).hexdigest()
    if digest != r[1]:
        err(422, "CHECKSUM_MISMATCH", "el bloque persistido está dañado")
    return {"node_id": NODE_ID, "block_id": bid, "gen": gen,
            "stored_size": len(r[0]), "sha256": digest}


@internal.get("/internal/blocks/{bid}")
def get_block_internal(bid: str, gen: int, x_cluster_token: Optional[str] = Header(None)):
    check_cluster(x_cluster_token)
    r = store.read(bid, gen)
    if r is None:
        err(404, "NOT_FOUND", "este nodo no tiene el bloque")
    return Response(r[0], media_type="application/octet-stream", headers={"X-Sha256": r[1]})


@internal.get("/health")
def health_internal():
    return {"ok": True, "id": NODE_ID}


# ------------------------------------------------------------------ agente: latidos, reporte de bloques, tareas
class Agent(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="agent")
        self.pool = ThreadPoolExecutor(4)
        self.reports = ThreadPoolExecutor(1)
        self.preferred = 0

    def post(self, path, body):
        last = None
        for k in range(len(CONTROL_URLS)):
            url = CONTROL_URLS[(self.preferred + k) % len(CONTROL_URLS)]
            try:
                r = http().post(url + path, json=body, headers={"X-Cluster-Token": CLUSTER_TOKEN},
                                timeout=90.0 if path.endswith("blockreport") else 10.0)
                r.raise_for_status()
                self.preferred = (self.preferred + k) % len(CONTROL_URLS)
                return r.json()
            except Exception as e:  # noqa: BLE001
                last = e
        raise RuntimeError(last)

    def execute(self, t):
        try:
            if t["op"] == "delete":
                store.delete(t["block_id"], t["gen"])
                log.info("bloque %s gen %s borrado (limpieza)", t["block_id"], t["gen"])
            elif t["op"] == "copy":
                r = http().get(t["source"] + f"/internal/blocks/{t['block_id']}", params={"gen": t["gen"]},
                               headers={"X-Cluster-Token": CLUSTER_TOKEN})
                r.raise_for_status()
                sha = hashlib.sha256(r.content).hexdigest()
                if t.get("sha256") and sha != t["sha256"]:
                    raise ValueError("huella distinta en la copia")
                store.write(t["block_id"], t["gen"], r.content, sha)
                self.post("/internal/task-done", {"node_id": NODE_ID, "op": "copy", "block_id": t["block_id"],
                                                  "gen": t["gen"], "ok": True})
                log.info("copiado %s gen %s desde %s", t["block_id"], t["gen"], t["source"])
        except Exception as e:  # noqa: BLE001
            log.warning("tarea %s falló: %s", t, e)

    def report(self, revision):
        # Tomar el inventario después de observar la revisión evita declarar
        # ausente un bloque publicado mientras el reporte estaba en tránsito.
        return self.post("/internal/blockreport", {"node_id": NODE_ID,
            "blocks": store.list(), "snapshot_revision": revision})

    def run(self):
        last_br = 0.0
        report = None
        while True:
            try:
                blocks = store.list()
                resp = self.post("/internal/heartbeat", {"node_id": NODE_ID, "public_url": PUBLIC_URL,
                                                         "internal_url": INTERNAL_URL,
                                                         "free_bytes": store.free_bytes(), "blocks": len(blocks)})
                for t in resp.get("tasks", []):
                    self.pool.submit(self.execute, t)
                if time.time() - last_br >= BLOCKREPORT_INTERVAL and (report is None or report.done()):
                    report = self.reports.submit(self.report, resp["catalog_revision"])
                    last_br = time.time()
            except Exception as e:  # noqa: BLE001
                log.warning("sin contacto con el control: %s", e)
            time.sleep(HEARTBEAT_INTERVAL)


def scrub_loop():
    while True:
        time.sleep(SCRUB_INTERVAL)
        try:
            for bid, gen in store.scrub():
                log.error("bloque corrupto %s gen %s eliminado; se reparará desde otra réplica", bid, gen)
        except Exception as e:  # noqa: BLE001
            log.warning("scrubber: %s", e)
