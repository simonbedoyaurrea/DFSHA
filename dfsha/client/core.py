"""Cliente de DFSha: autenticación, RF1, RF2 (put/get) y RF3 (bloques, locks)."""
import base64
import hashlib
import json
import os
import posixpath
import ssl
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DfshaError(Exception):
    def __init__(self, status, code, message="", extra=None):
        super().__init__(f"[{status} {code}] {message}")
        self.status, self.code, self.message, self.extra = status, code, message, extra or {}


def _aad(fid, index, gen):
    return f"{fid}|{index}|{gen}".encode()


def encrypt_block(dek, fid, index, gen, plain):
    nonce = os.urandom(12)
    return nonce + AESGCM(dek).encrypt(nonce, plain, _aad(fid, index, gen))


def decrypt_block(dek, fid, index, gen, stored):
    return AESGCM(dek).decrypt(stored[:12], stored[12:], _aad(fid, index, gen))


class LockKeeper:
    """Renueva el lock en segundo plano mientras dura una transferencia."""

    def __init__(self, client, lock):
        self.c, self.lock = client, lock
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.wait(max(1.0, self.lock["ttl"] / 3)):
            try:
                self.c.req("POST", f"/v1/locks/{self.lock['lock_id']}:renew")
            except Exception:  # noqa: BLE001
                return

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        try:
            self.c.req("DELETE", f"/v1/locks/{self.lock['lock_id']}")
        except Exception:  # noqa: BLE001
            pass


class SessionKeeper:
    """Mantiene la referencia de lectura y, si existe, el lock de escritura."""
    def __init__(self, client, handle, close_on_exit=True):
        self.client, self.handle = client, handle
        self.close_on_exit = close_on_exit
        self.stop = threading.Event()
        ttl = min(handle["session_ttl"], (handle.get("lock") or {}).get("ttl", handle["session_ttl"]))
        self.interval = max(0.5, ttl / 3)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.wait(self.interval):
            try:
                self.client.renew(self.handle)
            except Exception:
                return  # el servidor rechazará un commit o lectura con permiso vencido

    def __enter__(self):
        self.thread.start()
        return self.handle

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(timeout=1)
        if self.close_on_exit:
            self.client.close(self.handle)


class Client:
    def __init__(self, home=None):
        self.home = Path(home or os.environ.get("DFSHA_HOME", "~/.dfsha")).expanduser()
        self.home.mkdir(parents=True, exist_ok=True)
        cfgf = self.home / "config.json"
        shared = Path("~/.dfsha/config.json").expanduser()
        cfg = json.loads(shared.read_text()) if shared.exists() else {}
        if cfgf.exists():
            cfg.update(json.loads(cfgf.read_text()))
        seeds = os.environ.get("DFSHA_CONTROL") or ",".join(cfg.get("control", []))
        self.seeds = [s.strip().rstrip("/") for s in seeds.split(",") if s.strip()]
        ca = os.environ.get("DFSHA_CA") or cfg.get("ca")
        self.ca = ca
        verify = ssl.create_default_context(cafile=ca) if ca else True
        self.http = httpx.Client(verify=verify, timeout=httpx.Timeout(30.0, connect=3.0))
        self.nodes_http = httpx.Client(verify=verify, timeout=httpx.Timeout(60.0, connect=3.0))
        self.sf = self.home / "state.json"
        self.state = json.loads(self.sf.read_text()) if self.sf.exists() else {}
        self._i = 0
        self.block_size_hint = None

    # ---------------------------------------------------------------- estado local (sesión y carpeta actual)
    def save(self):
        self.sf.write_text(json.dumps(self.state))
        os.chmod(self.sf, 0o600)

    @property
    def cwd(self):
        return self.state.get("cwd", "/")

    def resolve(self, p):
        """cd/rutas relativas se resuelven localmente; el servidor solo recibe rutas absolutas."""
        p = p if p.startswith("/") else posixpath.join(self.cwd, p)
        n = posixpath.normpath(p)
        return "/" + n.lstrip("/") if n.startswith("//") else n

    def cd(self, p):
        path = self.resolve(p)
        if self.stat(path)["type"] != "dir":
            raise DfshaError(409, "NOT_A_DIR", "cd necesita un directorio")
        self.state["cwd"] = path
        self.save()
        return self.state["cwd"]

    # ---------------------------------------------------------------- HTTP al control con failover y reintentos
    def req(self, method, path, auth=True, retries=4, **kw):
        if not self.seeds:
            raise DfshaError(0, "NO_CONTROL", "configura DFSHA_CONTROL con la(s) URL(s) del servicio de control")
        refreshed = False
        attempt = 0
        while True:
            last, again, backoff = None, False, False
            for k in range(len(self.seeds)):
                base = self.seeds[(self._i + k) % len(self.seeds)]
                headers = {}
                if auth and self.state.get("access"):
                    headers["Authorization"] = "Bearer " + self.state["access"]
                try:
                    r = self.http.request(method, base + path, headers=headers, **kw)
                except httpx.HTTPError as e:
                    last = e          # esa instancia no responde: se prueba la siguiente
                    continue
                self._i = (self._i + k) % len(self.seeds)
                if r.status_code == 401 and auth and not refreshed and self.state.get("refresh"):
                    refreshed = True
                    rr = self.http.post(base + "/v1/auth/refresh", json={"refresh_token": self.state["refresh"]})
                    if rr.status_code == 200:
                        self.state["access"] = rr.json()["access_token"]
                        self.save()
                        again = True
                        break
                if r.status_code == 503 and attempt < retries:
                    last, again, backoff = r, True, True
                    self._i = (self._i + 1) % len(self.seeds)
                    break
                if r.status_code >= 400:
                    d = {}
                    if r.headers.get("content-type", "").startswith("application/json"):
                        d = r.json().get("detail", {})
                    d = d if isinstance(d, dict) else {"message": str(d)}
                    raise DfshaError(r.status_code, d.get("error", "ERROR"), d.get("message", r.text), d)
                return r.json()
            if again and not backoff:
                continue
            attempt += 1
            if attempt > retries:
                raise DfshaError(0, "UNREACHABLE", f"no se pudo contactar al control: {last}")
            time.sleep(0.4 * 2 ** (attempt - 1))   # backoff exponencial

    # ---------------------------------------------------------------- cuenta
    def register(self, user, pw):
        return self.req("POST", "/v1/auth/register", auth=False, json={"username": user, "password": pw})

    def login(self, user, pw):
        r = self.req("POST", "/v1/auth/login", auth=False, json={"username": user, "password": pw})
        self.state.update(access=r["access_token"], refresh=r["refresh_token"], user=user, cwd="/")
        self.save()
        return r

    def logout(self):
        self.state = {}
        self.save()

    # ---------------------------------------------------------------- RF1
    def ls(self, path="."):
        return self.req("GET", "/v1/fs/ls", params={"path": self.resolve(path)})

    def mkdir(self, path):
        return self.req("POST", "/v1/fs/mkdir", json={"path": self.resolve(path)})

    def rmdir(self, path):
        return self.req("DELETE", "/v1/fs/dir", params={"path": self.resolve(path)})

    def rm(self, path):
        return self.req("DELETE", "/v1/fs/file", params={"path": self.resolve(path)})

    def stat(self, path):
        return self.req("GET", "/v1/fs/stat", params={"path": self.resolve(path)})

    def status(self):
        return self.req("GET", "/v1/cluster/status")

    # ---------------------------------------------------------------- bajo nivel: subir/bajar bloques
    def _upload_block(self, o, alloc, plain):
        fid, idx, gen = o["fid"], alloc["index"], alloc["gen"]
        dek = base64.b64decode(o["dek"])
        stored = encrypt_block(dek, fid, idx, gen, plain)
        sha = hashlib.sha256(stored).hexdigest()
        last = None
        for rep in alloc["replicas"]:   # cualquier réplica del conjunto puede coordinar la escritura
            try:
                r = self.nodes_http.put(f"{rep['url']}/v1/blocks/{alloc['block_id']}", params={"gen": gen},
                                        content=stored, headers={"X-Block-Token": alloc["token"], "X-Sha256": sha})
                if r.status_code == 201:
                    return {"index": idx, "block_id": alloc["block_id"], "gen": gen, "sha256": sha,
                            "size": len(plain), "acked": r.json()["stored"]}
                last = r.text
            except httpx.HTTPError as e:
                last = str(e)
        raise DfshaError(503, "UPLOAD_FAILED", f"no se pudo guardar el bloque {idx}: {last}")

    def _upload_blocks(self, o, lock_id, items, workers=8, batch=16):
        """items: lista de (index, bytes_plano). Pide ubicaciones por lotes y sube en paralelo."""
        results = []
        for s in range(0, len(items), batch):
            chunk = items[s:s + batch]
            al = self.req("POST", f"/v1/files/{o['fid']}/blocks:allocate",
                          json={"lock_id": lock_id, "indexes": [i for i, _ in chunk]})["blocks"]
            by_idx = {a["index"]: a for a in al}
            with ThreadPoolExecutor(workers) as ex:
                futs = [ex.submit(self._upload_block, o, by_idx[i], plain) for i, plain in chunk]
                results += [f.result() for f in futs]
        return results

    def _fetch_block(self, o, blk, token, dek):
        last = None
        for node in blk["nodes"]:
            try:
                r = self.nodes_http.get(f"{node['url']}/v1/blocks/{blk['block_id']}", params={"gen": blk["gen"]},
                                        headers={"X-Block-Token": token})
                if r.status_code != 200:
                    last = f"{node['id']}: {r.status_code}"
                    continue
                if hashlib.sha256(r.content).hexdigest() != blk["sha256"]:
                    last = f"{node['id']}: huella distinta (bloque dañado)"
                    continue
                return decrypt_block(dek, o["fid"], blk["index"], blk["gen"], r.content)
            except httpx.HTTPError as e:
                last = f"{node['id']}: {e}"
        raise DfshaError(503, "BLOCK_UNAVAILABLE", f"bloque {blk['index']} no disponible ({last})")

    def _fetch_blocks(self, o, blocks, workers=8, batch=32):
        """Descarga bloques y devuelve {index: bytes_plano}. Obtiene tokens por lotes (duran poco)."""
        dek = base64.b64decode(o["dek"])
        out = {}
        for s in range(0, len(blocks), batch):
            chunk = blocks[s:s + batch]
            toks = self.req("POST", f"/v1/files/{o['fid']}/tokens",
                            json={"session_id": o.get("session_id"),
                                  "blocks": [{"block_id": b["block_id"], "gen": b["gen"]} for b in chunk]})["tokens"]
            with ThreadPoolExecutor(workers) as ex:
                futs = {b["index"]: ex.submit(self._fetch_block, o, b, toks[b["block_id"]], dek) for b in chunk}
                for i, f in futs.items():
                    try:
                        out[i] = f.result()
                    except DfshaError:
                        # las ubicaciones pudieron cambiar: se vuelve a preguntar al control
                        b = next(x for x in chunk if x["index"] == i)
                        loc = self.req("GET", f"/v1/files/{o['fid']}/blocks/{i}/locations",
                                       params={"session_id": o["session_id"]} if o.get("session_id") else {})
                        if loc["block_id"] != b["block_id"]:
                            raise
                        b = {**b, "nodes": loc["nodes"]}
                        out[i] = self._fetch_block(o, b, toks[b["block_id"]], dek)
        return out

    # ---------------------------------------------------------------- RF2: put / get
    def open(self, remote, mode="r", create=False, ranges=None):
        return self.req("POST", "/v1/files/open", json={
            "path": self.resolve(remote), "mode": mode, "create": create,
            "ranges": ranges, "session": True})

    def close(self, handle):
        if handle.get("closed"):
            return {"closed": False}
        result = self.req("DELETE", f"/v1/sessions/{handle['session_id']}")
        handle["closed"] = True
        return result

    def renew(self, handle):
        return self.req("POST", f"/v1/sessions/{handle['session_id']}:renew")

    def _commit(self, o, changes, size, replace_all=False, lock=None):
        lk = lock or o["lock"]
        result = self.req("POST", f"/v1/files/{o['fid']}/commit", timeout=180,
            json={"lock_id": lk["lock_id"], "fencing_token": lk["fencing_token"],
                  "base_version": o["version"], "changes": changes, "size": size,
                  "replace_all": replace_all, "request_id": uuid.uuid4().hex,
                  "session_id": o.get("session_id") if lock is None else None})
        if lock is None:
            o.update(self.req("GET", f"/v1/sessions/{o['session_id']}"))
        return result

    def read(self, handle, index):
        if handle.get("closed"):
            raise DfshaError(410, "SESSION_EXPIRED", "el archivo está cerrado")
        blocks = [b for b in handle["blocks"] if b["index"] == index]
        if not blocks:
            raise DfshaError(404, "NOT_FOUND", "bloque inexistente")
        with SessionKeeper(self, handle, close_on_exit=False):
            return self._fetch_blocks(handle, blocks)[index]

    def write(self, handle, index, data):
        with SessionKeeper(self, handle, close_on_exit=False):
            return self._write(handle, index, data)

    def _write(self, handle, index, data):
        if handle.get("closed") or handle.get("mode") != "w":
            raise DfshaError(403, "FORBIDDEN", "se requiere una sesión de escritura abierta")
        n, bs = len(handle["blocks"]), handle["block_size"]
        if index < 0 or index > n or not data or len(data) > bs:
            raise DfshaError(400, "BAD_BLOCK", "tamaño o índice de bloque inválido")
        if index < n - 1 and len(data) != bs:
            raise DfshaError(400, "BAD_BLOCK", "un bloque intermedio debe estar completo")
        if index == n - 1 and len(data) < handle["blocks"][-1]["size"]:
            raise DfshaError(400, "TRUNCATE_UNSUPPORTED", "la escritura parcial no reduce el archivo")
        if index == n and n > 0 and handle["blocks"][-1]["size"] != bs:
            raise DfshaError(400, "BAD_BLOCK", "completa el último bloque o utiliza append")
        changes = self._upload_blocks(handle, handle["lock"]["lock_id"], [(index, data)])
        size = (handle["size"] + len(data) if index == n else
                (n - 1) * bs + len(data) if index == n - 1 else handle["size"])
        return self._commit(handle, changes, size)

    def put(self, local, remote, workers=8):
        local = Path(local)
        size = local.stat().st_size
        path = self.resolve(remote)
        o = self.open(path, "w", create=True)
        bs = o["block_size"]
        with SessionKeeper(self, o):
            n = (size + bs - 1) // bs
            changes = []
            with open(local, "rb") as f:
                for s in range(0, n, 16):    # lotes de 16 bloques para no retener todo en memoria
                    items = []
                    for i in range(s, min(n, s + 16)):
                        f.seek(i * bs)
                        items.append((i, f.read(bs)))
                    changes += self._upload_blocks(o, o["lock"]["lock_id"], items, workers)
            r = self._commit(o, changes, size, replace_all=True)
        return {"path": path, "size": size, "blocks": n, "version": r["version"]}

    def get(self, remote, local, workers=8):
        o = self.open(remote, "r")
        local = Path(local)
        h = hashlib.sha256()
        with SessionKeeper(self, o), open(local, "wb") as f:
            blocks = o["blocks"]
            for s in range(0, len(blocks), 32):
                got = self._fetch_blocks(o, blocks[s:s + 32], workers)
                for b in blocks[s:s + 32]:
                    f.write(got[b["index"]])
                    h.update(got[b["index"]])
        return {"size": o["size"], "version": o["version"], "sha256": h.hexdigest()}

    # ---------------------------------------------------------------- RF3: lock, lectura y escritura por bloque
    def lock(self, path, blocks=None, mode="w", ttl=None):
        ranges = None if blocks is None else [list(blocks)]
        return self.req("POST", "/v1/locks", json={"path": self.resolve(path), "ranges": ranges, "mode": mode, "ttl": ttl})

    def unlock(self, lock_id):
        return self.req("DELETE", f"/v1/locks/{lock_id}")

    def read_block(self, remote, index):
        with SessionKeeper(self, self.open(remote)) as handle:
            return self.read(handle, index)

    def write_block(self, remote, index, data, lock=None):
        """Modifica un bloque completo (copy-on-write). Si pasas un lock propio se usa ese."""
        path = self.resolve(remote)
        if lock is None:
            with SessionKeeper(self, self.open(path, "w", ranges=[[index, index]])) as o:
                return self.write(o, index, data)
        with SessionKeeper(self, self.open(path)) as o:
            n, bs = len(o["blocks"]), o["block_size"]
            if index < 0 or index >= n or not data or len(data) > bs or (index < n - 1 and len(data) != bs):
                raise DfshaError(400, "BAD_BLOCK", "tamaño o índice de bloque inválido")
            if index == n - 1 and len(data) < o["blocks"][-1]["size"]:
                raise DfshaError(400, "TRUNCATE_UNSUPPORTED", "la escritura parcial no reduce el archivo")
            changes = self._upload_blocks(o, lock["lock_id"], [(index, data)])
            size = (n - 1) * bs + len(data) if index == n - 1 else o["size"]
            return self._commit(o, changes, size, lock=lock)

    def append(self, remote, local, workers=8):
        path = self.resolve(remote)
        with SessionKeeper(self, self.open(path)) as initial:
            n, bs = len(initial["blocks"]), initial["block_size"]
            start = n - 1 if n and initial["blocks"][-1]["size"] < bs else n
        with SessionKeeper(self, self.open(path, "w", ranges=[[start, None]])) as o:
            n = len(o["blocks"])
            start = n - 1 if n and o["blocks"][-1]["size"] < bs else n
            head = self.read(o, start) if start < n else b""
            changes, items = [], []
            index = start
            added = 0
            with open(local, "rb") as source:
                while True:
                    chunk = source.read(bs - len(head))
                    added += len(chunk)
                    payload = head + chunk
                    head = b""
                    if not payload:
                        break
                    items.append((index, payload))
                    index += 1
                    if len(items) == 16:
                        changes += self._upload_blocks(o, o["lock"]["lock_id"], items, workers)
                        items = []
                if items:
                    changes += self._upload_blocks(o, o["lock"]["lock_id"], items, workers)
            return self._commit(o, changes, o["size"] + added)
