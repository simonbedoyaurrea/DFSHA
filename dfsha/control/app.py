"""Servicio de control de DFSha (equivalente al NameNode, pero sin punto único de falla:
las instancias no guardan estado y todo el catálogo vive en etcd)."""
import base64
import copy
import hashlib
import json
import logging
import os
import posixpath
import re
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..common import config as C
from ..common import etcdhttp as E
from ..common import tokens as T
from ..common import tls
from ..common.hashring import Ring

log = logging.getLogger("dfsha.control")

# ------------------------------------------------------------------ configuración
BLOCK_SIZE = C.geti("BLOCK_SIZE", 4 * 1024 * 1024)
RF = C.geti("RF", 3)                      # factor de replicación N
W = C.geti("W", 2)                        # quórum de escritura
if not 1 <= W <= RF:
    raise ValueError("se requiere 1 <= W <= RF")
LOCK_TTL = C.geti("LOCK_TTL", 30)
BLOCK_TOKEN_TTL = C.geti("BLOCK_TOKEN_TTL", 60)
ACCESS_TTL = C.geti("ACCESS_TTL", 900)
REFRESH_TTL = C.geti("REFRESH_TTL", 8 * 3600)
SUSPECT_AFTER = C.getf("SUSPECT_AFTER", 9)
DEAD_AFTER = C.getf("DEAD_AFTER", 60)
GC_GRACE = C.getf("GC_GRACE", 300)
SESSION_TTL = C.geti("SESSION_TTL", 1800)
MONITOR_INTERVAL = C.getf("MONITOR_INTERVAL", 3)
MAX_COPIES_PER_TICK = C.geti("MAX_COPIES_PER_TICK", 20)
INFLIGHT_TTL = C.geti("INFLIGHT_TTL", 60)
CLUSTER_TOKEN = C.secret("CLUSTER_TOKEN", "")
CONTROL_ID = C.get("CONTROL_ID", "control") + "-" + secrets.token_hex(2)

PRIV = open(C.get("PRIVATE_KEY", "keys/control_ed25519.pem"), "rb").read()
PUB = open(C.get("PUBLIC_KEY", "keys/control_ed25519.pub"), "rb").read()
KEK = base64.b64decode(C.secret("KEK"))

etcd = E.Etcd(C.getl("ETCD_ENDPOINTS", "http://127.0.0.1:2379"),
              ca=C.get("ETCD_CA"), cert=C.get("ETCD_CERT"), key=C.get("ETCD_KEY"))
hasher = PasswordHasher()


def J(o):
    return json.dumps(o, separators=(",", ":"))


def err(status, code, message="", **extra):
    raise HTTPException(status, detail={"error": code, "message": message, **extra})


# ------------------------------------------------------------------ modelos
class Creds(BaseModel):
    username: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str


class PathBody(BaseModel):
    path: str


class OpenBody(BaseModel):
    path: str
    mode: str = "r"
    create: bool = False
    ranges: Optional[list] = None
    session: bool = True
    ttl: Optional[int] = None


class LockBody(BaseModel):
    path: str
    ranges: Optional[list] = None
    mode: str = "w"
    ttl: Optional[int] = None


class AllocBody(BaseModel):
    lock_id: str
    indexes: list


class TokenBody(BaseModel):
    blocks: list
    session_id: Optional[str] = None


class CommitBody(BaseModel):
    lock_id: str
    fencing_token: int
    base_version: int
    changes: list = []
    size: int
    replace_all: bool = False
    session_id: Optional[str] = None
    request_id: Optional[str] = None


class HB(BaseModel):
    node_id: str
    public_url: str
    internal_url: str
    free_bytes: int = 0
    blocks: int = 0


class BlockReport(BaseModel):
    node_id: str
    blocks: list
    snapshot_revision: int = 0


class TaskDone(BaseModel):
    node_id: str
    op: str
    block_id: str
    gen: int
    ok: bool


# ------------------------------------------------------------------ autenticación
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_fails = {}
_fails_lock = threading.Lock()


def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        err(401, "UNAUTHENTICATED", "falta el token")
    try:
        return T.verify(authorization[7:], PUB, "access")
    except jwt.PyJWTError:
        err(401, "UNAUTHENTICATED", "token inválido o vencido")


def norm(path):
    """Normaliza la ruta y rechaza intentos de salir del espacio del usuario."""
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path or len(path) > 1024:
        err(400, "BAD_PATH", "la ruta debe ser absoluta y válida")
    if ".." in path.split("/"):
        err(403, "FORBIDDEN", "ruta fuera del espacio del usuario")
    n = posixpath.normpath(path)
    if n.startswith("//"):
        n = "/" + n.lstrip("/")
    if any(len(s) > 255 for s in n.split("/")):
        err(400, "BAD_PATH", "nombre demasiado largo")
    return n


def ns_key(uid, path):
    return f"/ns/{uid}{path}"


def guard_cmp(key, kv):
    return E.cmp_mod(key, kv.mod_rev) if kv else E.cmp_version(key, 0)


def epoch_op():
    return E.put_op("/catalog/epoch", J({"revision": uuid.uuid4().hex}))


def parent_of(path):
    return posixpath.dirname(path) or "/"


def require_dir(uid, path):
    if path == "/":
        return
    kv = etcd.get(ns_key(uid, path))
    if kv is None:
        err(404, "NOT_FOUND", f"no existe la carpeta {path}")
    if kv.json()["type"] != "dir":
        err(409, "NOT_A_DIR", f"{path} no es una carpeta")


# ------------------------------------------------------------------ cifrado de claves de archivo
def wrap_dek(fid, dek):
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(KEK).encrypt(nonce, dek, fid.encode())).decode()


def unwrap_dek(fid, wrapped):
    raw = base64.b64decode(wrapped)
    return AESGCM(KEK).decrypt(raw[:12], raw[12:], fid.encode())


# ------------------------------------------------------------------ nodos
def all_nodes():
    return {n["id"]: n for n in (kv.json() for kv in etcd.get_prefix("/nodes/"))}


def node_view(n):
    return {"id": n["id"], "url": n["url"]}


# ------------------------------------------------------------------ manifiestos
def load_manifest(fid):
    kv = etcd.get(f"/files/{fid}")
    if kv is None:
        err(404, "NOT_FOUND", "archivo inexistente")
    return kv, kv.json()


def own_manifest(fid, uid):
    kv, m = load_manifest(fid)
    if m["uid"] != uid:
        err(403, "FORBIDDEN", "ese archivo no es tuyo")
    if m["state"] == "DELETED":
        err(404, "NOT_FOUND", "archivo borrado")
    return kv, m


def view(m, nodes=None):
    nodes = nodes if nodes is not None else all_nodes()
    blocks = []
    for b in m["blocks"]:
        blocks.append({"index": b["index"], "block_id": b["block_id"], "gen": b["gen"],
                       "size": b["size"], "sha256": b["sha256"],
                       "nodes": [node_view(nodes[x]) for x in b["in_sync"]
                                 if x in nodes and nodes[x]["state"] != "DEAD"]})
    return {"fid": m["fid"], "version": m["version"], "size": m["size"],
            "block_size": m["block_size"], "dek": base64.b64encode(unwrap_dek(m["fid"], m["wrapped_dek"])).decode(),
            "blocks": blocks}


def update_manifest(fid, fn, max_revision=None):
    """Lee-modifica-escribe con comparar-y-reemplazar sobre la revisión del manifiesto."""
    for _ in range(10):
        kv = etcd.get(f"/files/{fid}")
        if kv is None:
            return False
        if max_revision is not None and kv.mod_rev > max_revision:
            return False  # el inventario se tomó antes de la última publicación
        m = kv.json()
        if not fn(m):
            return False
        ok, _, _ = etcd.txn([E.cmp_mod(kv.key, kv.mod_rev)], [E.put_op(kv.key, J(m))])
        if ok:
            return True
    return False


# ------------------------------------------------------------------ locks
def _ov(r1, r2):
    a1, b1 = r1
    a2, b2 = r2
    b1 = float("inf") if b1 is None else b1
    b2 = float("inf") if b2 is None else b2
    return a1 <= b2 and a2 <= b1


def _conflicts(existing, mode, ranges):
    if existing["mode"] == "r" and mode == "r":
        return False
    return any(_ov(x, y) for x in existing["ranges"] for y in ranges)


def _covered(ranges, idx):
    return any(a <= idx and (b is None or idx <= b) for a, b in ranges)


def acquire_lock(fid, uid, ranges, mode, ttl=None):
    ttl = ttl or LOCK_TTL
    if not 1 <= ttl <= 3600:
        err(400, "BAD_TTL", "la duración debe estar entre 1 y 3600 segundos")
    try:
        ranges = [[int(a), (None if b is None else int(b))] for a, b in (ranges or [[0, None]])]
    except (ValueError, TypeError):
        err(400, "BAD_RANGE", "se requieren rangos de índices enteros")
    if any(a < 0 or (b is not None and b < a) for a, b in ranges):
        err(400, "BAD_RANGE", "rango de bloques inválido")
    guard = f"/lockguard/{fid}"
    for _ in range(8):
        g = etcd.get(guard)
        for kv in etcd.get_prefix(f"/locks/{fid}/"):
            if _conflicts(kv.json(), mode, ranges):
                err(409, "LOCKED", "esos bloques están reservados por otro cliente", retry_after=2)
        lease = etcd.lease_grant(ttl)
        lock_id = f"{fid}.{secrets.token_hex(4)}"
        key = f"/locks/{fid}/{lock_id}"
        cmp = [E.cmp_mod(guard, g.mod_rev)] if g else [E.cmp_version(guard, 0)]
        val = J({"uid": uid, "ranges": ranges, "mode": mode, "ttl": ttl})
        ok, rev, _ = etcd.txn(cmp, [E.put_op(key, val, lease), E.put_op(guard, J({"t": time.time()}))])
        if ok:
            # el fencing token es la revisión de etcd en la que se creó el lock (siempre creciente)
            return {"lock_id": lock_id, "fencing_token": rev, "ttl": ttl, "fid": fid, "ranges": ranges}
        etcd.lease_revoke(lease)
    err(503, "BUSY", "demasiada contención, reintenta")


def validate_lock(lock_id, uid, fid, fencing=None):
    if not lock_id.startswith(fid + "."):
        err(403, "FORBIDDEN", "lock de otro archivo")
    kv = etcd.get(f"/locks/{fid}/{lock_id}")
    if kv is None or (fencing is not None and kv.create_rev != fencing):
        err(412, "STALE_FENCING_TOKEN", "el lock venció o fue reemplazado")
    lock = kv.json()
    if lock["uid"] != uid:
        err(403, "FORBIDDEN", "ese lock no es tuyo")
    return kv, lock


# ------------------------------------------------------------------ aplicación pública
@asynccontextmanager
async def lifespan(app):
    threading.Thread(target=monitor_loop, daemon=True, name="monitor").start()
    yield


pub = FastAPI(title="DFSha control (API pública)", lifespan=lifespan)
internal = FastAPI(title="DFSha control (API interna, mTLS)")


async def metadata_unavailable(request, exc):
    return JSONResponse(status_code=503, content={"detail": {
        "error": "METADATA_UNAVAILABLE", "message": "el catálogo no tiene una mayoría accesible"}})


pub.add_exception_handler(E.EtcdError, metadata_unavailable)
internal.add_exception_handler(E.EtcdError, metadata_unavailable)


@pub.get("/health")
def health():
    return {"ok": True, "id": CONTROL_ID}


# ---- autenticación
@pub.post("/v1/auth/register", status_code=201)
def register(b: Creds):
    if not USER_RE.match(b.username):
        err(400, "BAD_USERNAME", "usuario de 3 a 32 caracteres (letras, números, _ . -)")
    if len(b.password) < 8:
        err(400, "WEAK_PASSWORD", "la contraseña debe tener al menos 8 caracteres")
    uid = uuid.uuid4().hex[:12]
    key = f"/users/{b.username}"
    ok, _, _ = etcd.txn([E.cmp_version(key, 0)],
                        [E.put_op(key, J({"uid": uid, "pw": hasher.hash(b.password), "created": time.time()}))])
    if not ok:
        err(409, "EXISTS", "ese usuario ya existe")
    return {"uid": uid, "username": b.username}


def _issue(uid, username):
    return {"access_token": T.sign({"sub": uid, "name": username}, PRIV, ACCESS_TTL, "access"),
            "refresh_token": T.sign({"sub": uid, "name": username}, PRIV, REFRESH_TTL, "refresh"),
            "expires_in": ACCESS_TTL}


@pub.post("/v1/auth/login")
def login(b: Creds):
    now = time.time()
    with _fails_lock:
        recent = [t for t in _fails.get(b.username, []) if now - t < 60]
        _fails[b.username] = recent
        if len(recent) >= 5:
            err(429, "TOO_MANY_ATTEMPTS", "demasiados intentos; espera un minuto")
    kv = etcd.get(f"/users/{b.username}")
    try:
        if kv is None:
            raise VerifyMismatchError()
        u = kv.json()
        hasher.verify(u["pw"], b.password)
    except VerifyMismatchError:
        with _fails_lock:
            _fails.setdefault(b.username, []).append(now)
        err(401, "UNAUTHENTICATED", "usuario o contraseña incorrectos")
    return _issue(u["uid"], b.username)


@pub.post("/v1/auth/refresh")
def refresh(b: RefreshBody):
    try:
        c = T.verify(b.refresh_token, PUB, "refresh")
    except jwt.PyJWTError:
        err(401, "UNAUTHENTICATED", "refresh token inválido o vencido")
    return _issue(c["sub"], c["name"])


# ---- RF1: sistema de archivos jerárquico
@pub.get("/v1/fs/ls")
def ls(path: str = "/", u=Depends(current_user)):
    uid, p = u["sub"], norm(path)
    if p != "/":
        kv = etcd.get(ns_key(uid, p))
        if kv is None:
            err(404, "NOT_FOUND", f"{p} no existe")
        if kv.json()["type"] == "file":
            return {"path": p, "entries": [{"name": posixpath.basename(p), **kv.json()}]}
    prefix = f"/ns/{uid}{p}/" if p != "/" else f"/ns/{uid}/"
    entries = []
    for kv in etcd.get_prefix(prefix):
        rel = kv.key[len(prefix):]
        if rel and "/" not in rel:
            entries.append({"name": rel, **kv.json()})
    entries.sort(key=lambda e: (e["type"] != "dir", e["name"]))
    return {"path": p, "entries": entries}


@pub.post("/v1/fs/mkdir", status_code=201)
def mkdir(b: PathBody, u=Depends(current_user)):
    uid, p = u["sub"], norm(b.path)
    if p == "/":
        err(409, "EXISTS", "la raíz ya existe")
    guard = f"/namespace/{uid}"
    for _ in range(10):
        g = etcd.get(guard)
        require_dir(uid, parent_of(p))
        if etcd.get(ns_key(uid, p)):
            err(409, "EXISTS", f"{p} ya existe")
        ok, _, _ = etcd.txn([guard_cmp(guard, g), E.cmp_version(ns_key(uid, p), 0)],
            [E.put_op(ns_key(uid, p), J({"type": "dir", "mtime": time.time()})),
             E.put_op(guard, uuid.uuid4().hex)])
        if ok:
            return {"path": p}
    err(503, "BUSY", "reintenta crear el directorio")


@pub.delete("/v1/fs/dir")
def rmdir(path: str, u=Depends(current_user)):
    uid, p = u["sub"], norm(path)
    if p == "/":
        err(403, "FORBIDDEN", "no se puede borrar la raíz")
    guard = f"/namespace/{uid}"
    for _ in range(10):
        g = etcd.get(guard)
        kv = etcd.get(ns_key(uid, p))
        if kv is None:
            err(404, "NOT_FOUND", f"{p} no existe")
        if kv.json()["type"] != "dir":
            err(409, "NOT_A_DIR", f"{p} es un archivo")
        if etcd.get_prefix(f"/ns/{uid}{p}/"):
            err(409, "NOT_EMPTY", "la carpeta no está vacía")
        ok, _, _ = etcd.txn([guard_cmp(guard, g), E.cmp_mod(kv.key, kv.mod_rev)],
                           [E.del_op(kv.key), E.put_op(guard, uuid.uuid4().hex)])
        if ok:
            return {"deleted": p}
    err(503, "BUSY", "reintenta borrar el directorio")


@pub.delete("/v1/fs/file")
def rm(path: str, u=Depends(current_user)):
    uid, p = u["sub"], norm(path)
    for _ in range(5):
        namespace = f"/namespace/{uid}"
        ng = etcd.get(namespace)
        kv = etcd.get(ns_key(uid, p))
        if kv is None:
            err(404, "NOT_FOUND", f"{p} no existe")
        e = kv.json()
        if e["type"] != "file":
            err(409, "IS_DIR", f"{p} es una carpeta; usa rmdir")
        fid = e["fid"]
        if etcd.get_prefix(f"/locks/{fid}/"):
            err(409, "LOCKED", "el archivo está en uso (tiene locks activos)")
        g = etcd.get(f"/lockguard/{fid}")
        mkv, m = load_manifest(fid)
        m["state"] = "DELETED"
        m["deleted_at"] = time.time()
        cmp = [guard_cmp(namespace, ng), E.cmp_mod(kv.key, kv.mod_rev), E.cmp_mod(mkv.key, mkv.mod_rev),
               E.cmp_mod(f"/lockguard/{fid}", g.mod_rev) if g else E.cmp_version(f"/lockguard/{fid}", 0)]
        ok, _, _ = etcd.txn(cmp, [E.del_op(kv.key), E.put_op(mkv.key, J(m)),
                                  E.put_op(f"/lockguard/{fid}", J({"t": time.time()})),
                                  E.put_op(namespace, uuid.uuid4().hex), epoch_op()])
        if ok:
            # borrado lógico: los bloques se liberan después (recolector de basura)
            return {"deleted": p}
    err(503, "BUSY", "reintenta")


@pub.get("/v1/fs/stat")
def stat(path: str, u=Depends(current_user)):
    uid, p = u["sub"], norm(path)
    kv = etcd.get(ns_key(uid, p)) if p != "/" else None
    if p != "/" and kv is None:
        err(404, "NOT_FOUND", f"{p} no existe")
    if p == "/" or kv.json()["type"] == "dir":
        return {"path": p, "type": "dir"}
    _, m = own_manifest(kv.json()["fid"], uid)
    return {"path": p, "type": "file", "fid": m["fid"], "version": m["version"], "size": m["size"],
            "block_size": m["block_size"],
            "blocks": [{"index": b["index"], "block_id": b["block_id"], "gen": b["gen"], "sha256": b["sha256"],
                        "size": b["size"], "in_sync": b["in_sync"]} for b in m["blocks"]]}


# ---- RF3: apertura, locks y bloques
def session_record(sid, uid, fid=None):
    kv = etcd.get(f"/sessions/{sid}")
    if kv is None:
        err(410, "SESSION_EXPIRED", "la sesión venció o fue cerrada; abre el archivo de nuevo")
    s = kv.json()
    if s["uid"] != uid or (fid is not None and s["fid"] != fid):
        err(403, "FORBIDDEN", "esa sesión no pertenece al usuario o archivo")
    return kv, s


def open_session(fid, uid, lock=None, created=False, ttl=None):
    ttl = SESSION_TTL if ttl is None else ttl
    if not 1 <= ttl <= SESSION_TTL:
        err(400, "BAD_TTL", "la sesión debe durar entre 1 y SESSION_TTL segundos")
    sid = uuid.uuid4().hex
    lease = etcd.lease_grant(ttl)
    for _ in range(10):
        kv, m = own_manifest(fid, uid)
        s = {"uid": uid, "fid": fid, "manifest": m, "lock": lock, "ttl": ttl,
             "mode": "w" if lock else "r"}
        cmps = [E.cmp_mod(kv.key, kv.mod_rev)]
        if lock:
            cmps.append(E.cmp_create(f"/locks/{fid}/{lock['lock_id']}", lock["fencing_token"]))
        ok, _, _ = etcd.txn(cmps, [E.put_op(f"/sessions/{sid}", J(s), lease), epoch_op()])
        if ok:
            return {**view(m), "session_id": sid, "session_ttl": ttl,
                    "mode": s["mode"], "lock": lock, "created": created}
    etcd.lease_revoke(lease)
    err(503, "BUSY", "el archivo cambió durante la apertura")


@pub.get("/v1/sessions/{sid}")
def get_session(sid: str, u=Depends(current_user)):
    _, s = session_record(sid, u["sub"])
    return {**view(s["manifest"]), "session_id": sid, "session_ttl": s["ttl"],
            "mode": s["mode"], "lock": s["lock"]}


@pub.post("/v1/sessions/{sid}:renew")
def renew_session(sid: str, u=Depends(current_user)):
    kv, s = session_record(sid, u["sub"])
    if s["lock"]:
        lock = s["lock"]
        lockkv, _ = validate_lock(lock["lock_id"], u["sub"], s["fid"], lock["fencing_token"])
        if etcd.lease_keepalive(lockkv.lease) <= 0:
            err(412, "STALE_FENCING_TOKEN", "venció la reserva de escritura")
    if etcd.lease_keepalive(kv.lease) <= 0:
        err(410, "SESSION_EXPIRED", "la sesión venció")
    return {"session_id": sid, "ttl": s["ttl"]}


@pub.delete("/v1/sessions/{sid}")
def close_session(sid: str, u=Depends(current_user)):
    kv = etcd.get(f"/sessions/{sid}")
    if kv is None:
        return {"closed": False}
    s = kv.json()
    if s["uid"] != u["sub"]:
        err(403, "FORBIDDEN", "esa sesión no es tuya")
    if s["lock"]:
        lock_release(s["lock"]["lock_id"], u)
    etcd.lease_revoke(kv.lease)
    return {"closed": True}


@pub.post("/v1/files/open")
def open_file(b: OpenBody, u=Depends(current_user)):
    uid, p = u["sub"], norm(b.path)
    if p == "/":
        err(409, "IS_DIR", "la raíz es una carpeta")
    if b.mode not in ("r", "w"):
        err(400, "BAD_MODE", "modo debe ser r o w")
    ns = etcd.get(ns_key(uid, p))
    if ns is not None and ns.json()["type"] == "dir":
        err(409, "IS_DIR", f"{p} es una carpeta")
    if b.mode == "r":
        if ns is None:
            err(404, "NOT_FOUND", f"{p} no existe")
        fid = ns.json()["fid"]
        if b.session:
            return open_session(fid, uid, ttl=b.ttl)
        _, m = own_manifest(fid, uid)
        return view(m)
    if ns is not None:
        fid = ns.json()["fid"]
        _, m = own_manifest(fid, uid)
        lock = acquire_lock(fid, uid, b.ranges, "w")
        if b.session:
            return open_session(fid, uid, lock, ttl=b.ttl)
        _, m = own_manifest(fid, uid)
        return {**view(m), "lock": lock, "created": False}
    if not b.create:
        err(404, "NOT_FOUND", f"{p} no existe")
    require_dir(uid, parent_of(p))
    # archivo nuevo: queda PENDIENTE (invisible) hasta el primer commit
    fid = uuid.uuid4().hex[:12]
    m = {"fid": fid, "uid": uid, "path": p, "version": 0, "size": 0, "block_size": BLOCK_SIZE,
         "state": "PENDING", "created": time.time(), "blocks": [],
         "wrapped_dek": wrap_dek(fid, os.urandom(32))}
    etcd.put(f"/files/{fid}", J(m))
    lock = acquire_lock(fid, uid, b.ranges, "w")
    if b.session:
        return open_session(fid, uid, lock, created=True, ttl=b.ttl)
    return {**view(m), "lock": lock, "created": True}


@pub.post("/v1/locks", status_code=201)
def lock_create(b: LockBody, u=Depends(current_user)):
    uid, p = u["sub"], norm(b.path)
    if b.mode not in ("r", "w"):
        err(400, "BAD_MODE", "modo debe ser r o w")
    ns = etcd.get(ns_key(uid, p))
    if ns is None or ns.json()["type"] != "file":
        err(404, "NOT_FOUND", f"{p} no existe o no es un archivo")
    fid = ns.json()["fid"]
    own_manifest(fid, uid)
    return acquire_lock(fid, uid, b.ranges, b.mode, b.ttl)


@pub.post("/v1/locks/{lock_id}:renew")
def lock_renew(lock_id: str, u=Depends(current_user)):
    fid = lock_id.split(".")[0]
    kv, lock = validate_lock(lock_id, u["sub"], fid)
    ttl = etcd.lease_keepalive(kv.lease)
    if ttl <= 0:
        err(412, "STALE_FENCING_TOKEN", "el lock ya venció")
    return {"lock_id": lock_id, "ttl": ttl}


@pub.delete("/v1/locks/{lock_id}")
def lock_release(lock_id: str, u=Depends(current_user)):
    fid = lock_id.split(".")[0]
    kv = etcd.get(f"/locks/{fid}/{lock_id}")
    if kv is None:
        return {"released": False}
    if kv.json()["uid"] != u["sub"]:
        err(403, "FORBIDDEN", "ese lock no es tuyo")
    etcd.delete(kv.key)
    if kv.lease:
        etcd.lease_revoke(kv.lease)
    return {"released": True}


@pub.post("/v1/files/{fid}/blocks:allocate")
def allocate(fid: str, b: AllocBody, u=Depends(current_user)):
    uid = u["sub"]
    _, m = own_manifest(fid, uid)
    _, lock = validate_lock(b.lock_id, uid, fid)
    if lock["mode"] != "w":
        err(403, "FORBIDDEN", "se necesita un lock de escritura")
    nodes = {k: v for k, v in all_nodes().items() if v["state"] == "ALIVE"}
    if len(nodes) < W:
        err(503, "INSUFFICIENT_REPLICAS", "no hay suficientes nodos de datos vivos")
    ring = Ring(list(nodes))
    load = {k: v.get("blocks", 0) for k, v in nodes.items()}
    lease = etcd.lease_grant(3600)
    out, ops = [], []
    for idx in b.indexes:
        idx = int(idx)
        if idx < 0 or not _covered(lock["ranges"], idx):
            err(403, "FORBIDDEN", f"el bloque {idx} está fuera del rango del lock")
        cur = m["blocks"][idx]["gen"] if idx < len(m["blocks"]) else 0
        gen = cur + 1
        bid = f"{fid}-{idx}-{gen}-{secrets.token_hex(3)}"
        chosen = ring.pick(bid, min(RF, len(nodes)), load)
        reps = [{"id": c, "url": nodes[c]["url"], "internal_url": nodes[c]["internal_url"]} for c in chosen]
        token = T.sign({"sub": uid, "bid": bid, "gen": gen, "op": "w",
                        "nodes": [{"id": r["id"], "internal_url": r["internal_url"]} for r in reps]},
                       PRIV, BLOCK_TOKEN_TTL, "block")
        ops.append(E.put_op(f"/pending/{bid}", J({
            "fid": fid, "uid": uid, "index": idx, "gen": gen,
            "lock_id": b.lock_id, "ts": time.time(),
            "nodes": [{"id": r["id"], "internal_url": r["internal_url"]} for r in reps],
        }), lease))
        out.append({"index": idx, "block_id": bid, "gen": gen, "token": token,
                    "replicas": [{"id": r["id"], "url": r["url"]} for r in reps]})
    if ops:
        etcd.txn([], ops + [epoch_op()])
    return {"blocks": out}


@pub.post("/v1/files/{fid}/tokens")
def read_tokens(fid: str, b: TokenBody, u=Depends(current_user)):
    uid = u["sub"]
    if b.session_id:
        _, s = session_record(b.session_id, uid, fid)
        m = s["manifest"]
    else:
        _, m = own_manifest(fid, uid)
    allowed = {(blk["block_id"], blk["gen"]) for blk in m["blocks"]}
    toks = {}
    for x in b.blocks:
        bid, gen = str(x["block_id"]), int(x["gen"])
        if (bid, gen) not in allowed:
            err(403, "FORBIDDEN", "el bloque no forma parte de la versión abierta")
        toks[bid] = T.sign({"sub": uid, "bid": bid, "gen": gen, "op": "r"}, PRIV, BLOCK_TOKEN_TTL, "block")
    return {"tokens": toks}


@pub.get("/v1/files/{fid}/blocks/{index}/locations")
def locations(fid: str, index: int, session_id: Optional[str] = None, u=Depends(current_user)):
    if session_id:
        _, s = session_record(session_id, u["sub"], fid)
        m = s["manifest"]
    else:
        _, m = own_manifest(fid, u["sub"])
    if index < 0 or index >= len(m["blocks"]):
        err(404, "NOT_FOUND", "bloque inexistente")
    nodes = all_nodes()
    blk = m["blocks"][index]
    return {"version": m["version"], "block_id": blk["block_id"], "gen": blk["gen"], "sha256": blk["sha256"],
            "nodes": [node_view(nodes[x]) for x in blk["in_sync"] if x in nodes and nodes[x]["state"] != "DEAD"]}


@pub.post("/v1/files/{fid}/commit")
def commit(fid: str, b: CommitBody, u=Depends(current_user)):
    uid = u["sub"]
    verified = {}
    result_key = None
    result_lease = 0
    fingerprint = hashlib.sha256(J(b.model_dump()).encode()).hexdigest()
    if b.request_id:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", b.request_id):
            err(400, "BAD_REQUEST_ID", "identificador de operación inválido")
        result_key = f"/commits/{fid}/{b.request_id}"

    def previous_result():
        prior = etcd.get(result_key) if result_key else None
        if prior:
            value = prior.json()
            if value["uid"] != uid or value["fingerprint"] != fingerprint:
                err(409, "REQUEST_ID_CONFLICT", "la operación ya existe con otro contenido")
            return value["result"]
        return None

    prior = previous_result()
    if prior is not None:
        return prior

    def mk(c):
        if not str(c["block_id"]).startswith(fid + "-"):
            err(403, "FORBIDDEN", "bloque ajeno")
        idx, gen, size = int(c["index"]), int(c["gen"]), int(c["size"])
        if idx < 0 or not 0 < size <= m["block_size"] or not re.fullmatch(r"[0-9a-f]{64}", c["sha256"]):
            err(400, "BAD_CHANGES", "índice, tamaño o hash de bloque inválido")
        cache_key = (c["block_id"], gen, size, c["sha256"])
        if cache_key not in verified:
            pending = etcd.get(f"/pending/{c['block_id']}")
            plan = pending.json() if pending else {}
            if (plan.get("fid"), plan.get("uid"), plan.get("lock_id"),
                    plan.get("index"), plan.get("gen")) != (fid, uid, b.lock_id, idx, gen):
                err(403, "INVALID_ALLOCATION", "el bloque no corresponde a una asignación vigente")

            # No confiamos en acked: consultamos los destinos que asignó el control.
            def check(node):
                try:
                    with tls.http_client(timeout=5.0, mtls=True) as client:
                        response = client.get(
                            node["internal_url"] + f"/internal/blocks/{c['block_id']}/verify",
                            params={"gen": gen}, headers={"X-Cluster-Token": CLUSTER_TOKEN})
                        response.raise_for_status()
                        result = response.json()
                    if (result.get("node_id") == node["id"]
                            and result.get("block_id") == c["block_id"]
                            and result.get("gen") == gen
                            and result.get("sha256") == c["sha256"]
                            and result.get("stored_size") == size + 28):  # nonce + etiqueta AES-GCM
                        return node["id"]
                except Exception as exc:  # un destino fallido no cuenta como copia
                    log.warning("no se verificó %s en %s: %s", c["block_id"], node["id"], exc)
                return None

            nodes = {n["id"]: n for n in plan.get("nodes", [])}
            with ThreadPoolExecutor(max_workers=max(1, len(nodes))) as pool:
                acked = [nid for nid in pool.map(check, nodes.values()) if nid is not None]
            if len(acked) < W:
                err(503, "INSUFFICIENT_REPLICAS", f"el bloque {idx} requiere {W} copias verificadas")
            verified[cache_key] = acked
        acked = verified[cache_key]
        return {"index": int(c["index"]), "block_id": c["block_id"], "gen": int(c["gen"]),
                "size": int(c["size"]), "sha256": c["sha256"], "in_sync": acked}

    for _ in range(10):
        prior = previous_result()
        if prior is not None:
            return prior
        namespace = f"/namespace/{uid}"
        ng = etcd.get(namespace)
        kv, m = own_manifest(fid, uid)
        require_dir(uid, parent_of(m["path"]))
        lockkv, lock = validate_lock(b.lock_id, uid, fid, b.fencing_token)
        if lock["mode"] != "w":
            err(403, "FORBIDDEN", "se necesita un lock de escritura")
        skv, s = None, None
        if b.session_id:
            skv, s = session_record(b.session_id, uid, fid)
            if not s["lock"] or s["lock"]["lock_id"] != b.lock_id:
                err(403, "FORBIDDEN", "la sesión no corresponde al lock de escritura")
        new = copy.deepcopy(m)
        changes = sorted(b.changes, key=lambda c: int(c["index"]))
        if len({int(c["index"]) for c in changes}) != len(changes):
            err(400, "BAD_CHANGES", "un índice no puede aparecer dos veces")
        if b.replace_all:
            if not any(a == 0 and e is None for a, e in lock["ranges"]):
                err(403, "FORBIDDEN", "reemplazar todo exige lock sobre todo el archivo")
            if m["version"] != b.base_version:
                err(412, "VERSION_CONFLICT", "el archivo cambió desde que lo abriste", current_version=m["version"])
            if [int(c["index"]) for c in changes] != list(range(len(changes))):
                err(400, "BAD_CHANGES", "los bloques deben ser contiguos desde 0")
            new["blocks"] = [mk(c) for c in changes]
        else:
            blocks = new["blocks"]
            intent = copy.deepcopy(s["manifest"]["blocks"] if s else m["blocks"])
            for c in changes:
                i = int(c["index"])
                if not _covered(lock["ranges"], i):
                    err(403, "FORBIDDEN", f"el bloque {i} está fuera del rango de tu lock")
                if i < len(blocks):
                    if int(c["gen"]) != blocks[i]["gen"] + 1:
                        err(412, "VERSION_CONFLICT", f"el bloque {i} cambió desde que lo leíste")
                    blocks[i] = mk(c)
                elif i == len(blocks):
                    if int(c["gen"]) != 1:
                        err(412, "VERSION_CONFLICT", f"generación inválida para el bloque nuevo {i}")
                    blocks.append(mk(c))
                else:
                    err(400, "BAD_CHANGES", "los bloques nuevos deben ser contiguos")
                if i < len(intent):
                    intent[i] = mk(c)
                elif i == len(intent):
                    intent.append(mk(c))
                else:
                    err(400, "BAD_CHANGES", "el cambio deja huecos en la versión abierta")
            if sum(blk["size"] for blk in intent) != b.size:
                err(400, "BAD_SIZE", "el tamaño no corresponde al cambio sobre la versión abierta")
        n = len(new["blocks"])
        sizes = [blk["size"] for blk in new["blocks"]]
        effective_size = b.size if b.replace_all else sum(sizes)
        if (sum(sizes) != effective_size or any(s != m["block_size"] for s in sizes[:-1])
                or (n > 0 and not 0 < sizes[-1] <= m["block_size"])):
            err(400, "BAD_SIZE", "el tamaño no corresponde a la cantidad de bloques")
        if not b.replace_all and effective_size < m["size"]:
            err(400, "TRUNCATE_UNSUPPORTED", "solo un reemplazo completo puede reducir el archivo")
        new["size"] = effective_size
        new["version"] = m["version"] + 1
        new["state"] = "ACTIVE"
        new["mtime"] = time.time()
        nskey = ns_key(uid, m["path"])
        entry = {"type": "file", "fid": fid, "size": effective_size, "version": new["version"], "mtime": new["mtime"]}
        cmps = [guard_cmp(namespace, ng), E.cmp_mod(kv.key, kv.mod_rev), E.cmp_create(lockkv.key, b.fencing_token)]
        cmps.append(E.cmp_version(nskey, 0) if m["state"] == "PENDING" else E.cmp_version(nskey, 0, "GREATER"))
        ops = [E.put_op(kv.key, J(new)), E.put_op(nskey, J(entry)),
               E.put_op(namespace, J(uuid.uuid4().hex)), epoch_op()]
        if s is not None:
            s["manifest"] = new
            cmps.append(E.cmp_mod(skv.key, skv.mod_rev))
            ops.append(E.put_op(skv.key, J(s), skv.lease))
        result = {"version": new["version"], "size": new["size"]}
        if result_key:
            if not result_lease:
                result_lease = etcd.lease_grant(86400)
            cmps.append(E.cmp_version(result_key, 0))
            ops.append(E.put_op(result_key, J({"uid": uid, "fingerprint": fingerprint,
                                              "result": result}), result_lease))
        # commit atómico: manifiesto + entrada de directorio en una sola transacción de etcd
        ok, _, _ = etcd.txn(cmps, ops)
        if ok:
            ids = [c["block_id"] for c in changes]
            for i in range(0, len(ids), 100):   # los bloques confirmados dejan de estar "pendientes"
                etcd.txn([], [E.del_op(f"/pending/{x}") for x in ids[i:i + 100]])
            return result
        prior = previous_result()
        if prior is not None:
            return prior
        k2 = etcd.get(lockkv.key)
        if k2 is None or k2.create_rev != b.fencing_token:
            err(412, "STALE_FENCING_TOKEN", "el lock venció durante el commit")
        if m["state"] == "PENDING" and etcd.get(nskey) is not None:
            err(409, "EXISTS", f"{m['path']} fue creado por otro cliente mientras subías")
    err(503, "BUSY", "demasiados conflictos de commit, reintenta")


@pub.get("/v1/cluster/status")
def cluster_status(u=Depends(current_user)):
    nodes = all_nodes()
    target = RF
    total = under = 0
    for kv in etcd.get_prefix("/files/"):
        m = kv.json()
        if m["state"] != "ACTIVE":
            continue
        for blk in m["blocks"]:
            total += 1
            live = [x for x in blk["in_sync"] if nodes.get(x, {}).get("state") in ("ALIVE", "SUSPECT")]
            under += len(live) < target
    return {"nodes": [{"id": n["id"], "state": n["state"], "url": n["url"], "blocks": n.get("blocks", 0),
                       "last_hb_age": round(time.time() - n["last_hb"], 1)} for n in nodes.values()],
            "blocks_total": total, "blocks_under_replicated": under, "rf": RF, "w": W,
            "config": {"block_size": BLOCK_SIZE, "gc_grace": GC_GRACE,
                       "block_token_ttl": BLOCK_TOKEN_TTL, "session_ttl": SESSION_TTL,
                       "dead_after": DEAD_AFTER}}


# ------------------------------------------------------------------ API interna (mTLS)
def _check_cluster(token):
    if CLUSTER_TOKEN and not secrets.compare_digest(token or "", CLUSTER_TOKEN):
        err(403, "FORBIDDEN", "token de clúster inválido")


@internal.post("/internal/heartbeat")
def heartbeat(b: HB, x_cluster_token: Optional[str] = Header(None)):
    _check_cluster(x_cluster_token)
    etcd.put(f"/nodes/{b.node_id}", J({"id": b.node_id, "url": b.public_url, "internal_url": b.internal_url,
                                        "state": "ALIVE", "last_hb": time.time(),
                                        "free_bytes": b.free_bytes, "blocks": b.blocks}))
    kvs = etcd.get_prefix(f"/tasks/{b.node_id}/")
    tasks = [kv.json() for kv in kvs]
    for start in range(0, len(kvs), 100):
        etcd.txn([], [E.del_op(kv.key) for kv in kvs[start:start + 100]])
    return {"tasks": tasks, "catalog_revision": etcd.revision()}


def _enqueue_delete(node_id, bid, gen):
    etcd.put(f"/tasks/{node_id}/{uuid.uuid4().hex[:8]}", J({"op": "delete", "block_id": bid, "gen": gen}))


@internal.post("/internal/blockreport")
def blockreport(b: BlockReport, x_cluster_token: Optional[str] = Header(None)):
    _check_cluster(x_cluster_token)
    node = b.node_id
    held = {(x["block_id"], int(x["gen"])): float(x.get("age", 0)) for x in b.blocks}
    epoch = etcd.get("/catalog/epoch")
    epoch_revision = epoch.mod_rev if epoch else 0
    referenced = {}
    for kv in etcd.get_prefix("/files/"):
        m = kv.json()
        if m["state"] == "ACTIVE":
            for blk in m["blocks"]:
                referenced[(blk["block_id"], blk["gen"])] = m["fid"]
    pinned = set()
    for kv in etcd.get_prefix("/sessions/"):
        pinned.update((blk["block_id"], blk["gen"]) for blk in kv.json()["manifest"]["blocks"])
    marks = {kv.key: kv for kv in etcd.get_prefix(f"/gc/{node}/")}
    pending = {kv.key.removeprefix("/pending/") for kv in etcd.get_prefix("/pending/")}

    def fix(m):
        changed = False
        for blk in m["blocks"]:
            key = (blk["block_id"], blk["gen"])
            has = key in held
            if node in blk["in_sync"] and not has:
                blk["in_sync"].remove(node)       # el nodo perdió la copia
                changed = True
            elif has and node not in blk["in_sync"]:
                if len(blk["in_sync"]) < RF:
                    blk["in_sync"].append(node)   # copia válida que volvió: pasa a "al día"
                    changed = True
        return changed

    for fid in set(referenced.values()):
        update_manifest(fid, fix, max_revision=b.snapshot_revision)
    mark_ops = []
    ready = []
    for bid, gen in held:
        mark_key = f"/gc/{node}/{bid}.{gen}"
        if (bid, gen) in referenced or (bid, gen) in pinned or bid in pending:
            if mark_key in marks:
                mark_ops.append(E.del_op(mark_key))
            continue
        mark = marks.get(mark_key)
        now = time.time()
        # Una apertura/publicación concurrente reinicia la espera. El GC prefiere
        # conservar espacio temporalmente antes que borrar una versión en uso.
        if mark is None or mark.json()["epoch"] != epoch_revision:
            mark_ops.append(E.put_op(mark_key, J({"since": now, "epoch": epoch_revision})))
            continue
        if now - mark.json()["since"] < max(GC_GRACE, BLOCK_TOKEN_TTL + 5):
            continue
        ready.append((bid, gen, mark_key, mark.mod_rev))
    for start in range(0, len(mark_ops), 100):
        etcd.txn([], mark_ops[start:start + 100])
    for start in range(0, len(ready), 25):
        cmps = [guard_cmp("/catalog/epoch", epoch)]
        ops = []
        for bid, gen, mark_key, revision in ready[start:start + 25]:
            cmps += [E.cmp_mod(mark_key, revision), E.cmp_version(f"/pending/{bid}", 0)]
            task_key = f"/tasks/{node}/{uuid.uuid4().hex}"
            ops += [E.put_op(task_key, J({"op": "delete", "block_id": bid, "gen": gen})),
                    E.del_op(mark_key)]
        etcd.txn(cmps, ops)
    return {"ok": True}


@internal.post("/internal/task-done")
def task_done(b: TaskDone, x_cluster_token: Optional[str] = Header(None)):
    _check_cluster(x_cluster_token)
    etcd.delete(f"/inflight/{b.block_id}.{b.gen}.{b.node_id}")
    if b.ok and b.op == "copy":
        def add(m):
            for blk in m["blocks"]:
                if blk["block_id"] == b.block_id and blk["gen"] == b.gen and b.node_id not in blk["in_sync"]:
                    if len(blk["in_sync"]) < RF:
                        blk["in_sync"].append(b.node_id)
                        return True
            return False
        update_manifest(b.block_id.split("-")[0], add)
    return {"ok": True}


# ------------------------------------------------------------------ monitor (solo el líder)
class Leader:
    KEY = "/leader/monitor"

    def __init__(self):
        self.lease = None

    def check(self):
        kv = etcd.get(self.KEY)
        if kv is not None and kv.value == CONTROL_ID and self.lease:
            if etcd.lease_keepalive(self.lease) > 0:
                return True
        if kv is None:
            lease = etcd.lease_grant(max(10, int(MONITOR_INTERVAL * 4)))
            ok, _, _ = etcd.txn([E.cmp_version(self.KEY, 0)], [E.put_op(self.KEY, CONTROL_ID, lease)])
            if ok:
                self.lease = lease
                log.info("esta instancia es ahora el líder del monitor")
                return True
            etcd.lease_revoke(lease)
        return False


def tick():
    now = time.time()
    nodes = {}
    for kv in etcd.get_prefix("/nodes/"):
        n = kv.json()
        age = now - n["last_hb"]
        st = "ALIVE" if age <= SUSPECT_AFTER else ("SUSPECT" if age <= DEAD_AFTER else "DEAD")
        if st != n["state"]:
            log.warning("nodo %s: %s -> %s", n["id"], n["state"], st)
            n["state"] = st
            etcd.txn([E.cmp_mod(kv.key, kv.mod_rev)], [E.put_op(kv.key, J(n))])
        nodes[n["id"]] = n
    alive = [i for i, n in nodes.items() if n["state"] == "ALIVE"]
    target = min(RF, len(alive))
    inflight = {kv.key for kv in etcd.get_prefix("/inflight/")}
    needs = []
    for kv in etcd.get_prefix("/files/"):
        m = kv.json()
        if m["state"] == "PENDING" and now - m["created"] > 3600:
            etcd.delete(kv.key)
            continue
        if m["state"] == "DELETED" and now - m.get("deleted_at", now) > 2 * GC_GRACE:
            etcd.delete(kv.key)
            continue
        if m["state"] != "ACTIVE":
            continue
        changed = False
        for blk in m["blocks"]:
            live = [x for x in blk["in_sync"] if nodes.get(x, {}).get("state") in ("ALIVE", "SUSPECT")]
            if len(live) != len(blk["in_sync"]):
                blk["in_sync"] = live
                changed = True
        if changed:
            etcd.txn([E.cmp_mod(kv.key, kv.mod_rev)], [E.put_op(kv.key, J(m))])
        for blk in m["blocks"]:
            if len(blk["in_sync"]) < target:
                needs.append((len(blk["in_sync"]), blk))
    needs.sort(key=lambda x: x[0])          # primero los bloques con menos copias
    queued = 0
    for _, blk in needs:
        if queued >= MAX_COPIES_PER_TICK:   # limita el ancho de banda de reparación
            break
        if not blk["in_sync"]:
            log.error("bloque %s sin copias vivas: datos perdidos", blk["block_id"])
            continue
        cands = [x for x in alive if x not in blk["in_sync"]
                 and f"/inflight/{blk['block_id']}.{blk['gen']}.{x}" not in inflight]
        if not cands:
            continue
        cands.sort(key=lambda x: nodes[x].get("blocks", 0))
        tgt = cands[0]
        srcs = sorted(blk["in_sync"], key=lambda x: nodes[x]["state"] != "ALIVE")
        task = {"id": uuid.uuid4().hex[:8], "op": "copy", "block_id": blk["block_id"], "gen": blk["gen"],
                "source": nodes[srcs[0]]["internal_url"], "sha256": blk["sha256"]}
        lease = etcd.lease_grant(INFLIGHT_TTL)
        ikey = f"/inflight/{blk['block_id']}.{blk['gen']}.{tgt}"
        etcd.txn([], [E.put_op(f"/tasks/{tgt}/{task['id']}", J(task)), E.put_op(ikey, "1", lease)])
        inflight.add(ikey)
        queued += 1
        log.info("re-replicación: %s gen %s -> %s (desde %s)", blk["block_id"], blk["gen"], tgt, srcs[0])


def monitor_loop():
    leader = Leader()
    while True:
        try:
            if leader.check():
                tick()
        except Exception as e:  # noqa: BLE001
            log.warning("monitor: %s", e)
        time.sleep(MONITOR_INTERVAL)
