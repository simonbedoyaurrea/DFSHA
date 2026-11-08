"""Almacenamiento local de bloques: archivo temporal -> fsync -> renombrar (nunca queda un bloque a medias)."""
import hashlib
import os
import re
import shutil
import threading
import time

SAFE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")


class BlockConflictError(ValueError):
    """Un identificador publicado no puede cambiar de contenido."""


class Store:
    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.mu = threading.Lock()
        self.cleanup()

    def _p(self, bid, gen):
        if not SAFE.match(bid) or int(gen) < 0:
            raise ValueError("identificador de bloque inválido")
        return os.path.join(self.root, f"{bid}.{int(gen)}")

    def cleanup(self):
        """Al arrancar: borra temporales de escrituras interrumpidas y huellas sin bloque."""
        for f in os.listdir(self.root):
            full = os.path.join(self.root, f)
            if f.endswith(".tmp") or (f.endswith(".sha") and not os.path.exists(full[:-4])):
                os.remove(full)

    def _write_atomic(self, path, data):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def write(self, bid, gen, data, sha):
        p = self._p(bid, gen)
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError("la huella no corresponde al bloque")
        with self.mu:
            existing = self.read(bid, gen)
            if existing is not None:
                if existing[0] != data:
                    raise BlockConflictError("el bloque ya existe con otro contenido")
                return                      # reintentar la misma escritura es seguro
            self._write_atomic(p + ".sha", sha.encode())
            self._write_atomic(p, data)
            fd = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def read(self, bid, gen):
        p = self._p(bid, gen)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            data = f.read()
        try:
            sha = open(p + ".sha").read().strip()
        except FileNotFoundError:
            sha = hashlib.sha256(data).hexdigest()
        return data, sha

    def delete(self, bid, gen):
        p = self._p(bid, gen)
        for x in (p, p + ".sha"):
            try:
                os.remove(x)
            except FileNotFoundError:
                pass

    def list(self):
        now = time.time()
        out = []
        for f in os.listdir(self.root):
            if f.endswith(".tmp") or f.endswith(".sha"):
                continue
            bid, _, gen = f.rpartition(".")
            try:
                age = now - os.path.getmtime(os.path.join(self.root, f))
            except FileNotFoundError:
                continue  # una tarea de GC terminó después de listar el directorio
            out.append({"block_id": bid, "gen": int(gen), "age": age})
        return out

    def scrub(self):
        """Recalcula huellas; borra bloques corruptos (el control los repara desde otra copia)."""
        bad = []
        for b in self.list():
            r = self.read(b["block_id"], b["gen"])
            if r and hashlib.sha256(r[0]).hexdigest() != r[1]:
                self.delete(b["block_id"], b["gen"])
                bad.append((b["block_id"], b["gen"]))
        return bad

    def free_bytes(self):
        return shutil.disk_usage(self.root).free
