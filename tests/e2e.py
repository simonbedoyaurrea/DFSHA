#!/usr/bin/env python3
"""Pruebas de extremo a extremo (las 7 pruebas mínimas del enunciado) contra un clúster en ejecución.

  scripts/local.sh up && eval "$(scripts/local.sh env)" && python tests/e2e.py
Para caídas de nodos usa STOP_CMD / START_CMD (por defecto scripts/local.sh dn-stop|dn-start N).
"""
import glob
import hashlib
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dfsha.client.core import Client, DfshaError  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
STOP = os.environ.get("STOP_CMD", f"{shlex.quote(str(ROOT / 'scripts/local.sh'))} dn-stop {{n}}")
START = os.environ.get("START_CMD", f"{shlex.quote(str(ROOT / 'scripts/local.sh'))} dn-start {{n}}")
DATA_GLOB = os.environ.get("DATA_GLOB", f"{ROOT}/.run/data/dn*")
TMP = Path(tempfile.mkdtemp(prefix="dfsha-e2e-"))
RES = []
PW = "clave-segura-123"
SUF = hex(int(time.time()))[-5:]
GC_WAIT = int(os.environ.get("GC_WAIT", "150"))


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def rnd(name, size):
    p = TMP / name
    p.write_bytes(os.urandom(size))
    return p


def new_client(user):
    c = Client(TMP / f"home-{user}")
    try:
        c.register(user, PW)
    except DfshaError as e:
        if e.code != "EXISTS":
            raise
    c.login(user, PW)
    return c


def expect(code, fn, *a, **k):
    try:
        fn(*a, **k)
    except DfshaError as e:
        assert e.code == code or e.status == code, f"se esperaba {code} y llegó {e}"
        return e
    raise AssertionError(f"se esperaba el error {code}, pero la operación tuvo éxito")


def wait_for(cond, timeout, step=1.0):
    t = time.time()
    while time.time() - t < timeout:
        v = cond()
        if v:
            return True
        time.sleep(step)
    return False


def run(name):
    def deco(fn):
        t = time.time()
        try:
            info = fn()
            RES.append((name, True, info or "", time.time() - t))
        except Exception as e:  # noqa: BLE001
            RES.append((name, False, f"{type(e).__name__}: {e}", time.time() - t))
        r = RES[-1]
        print(f"[{'OK ' if r[1] else 'FALLA'}] {name}  ({r[3]:.1f}s)  {r[2]}", flush=True)
        return fn
    return deco


A = new_client(f"alice{SUF}")
B = new_client(f"bob{SUF}")
BS = A.status().get("config", {}).get("block_size", 4 * 1024 * 1024)


@run("1. Carga y recuperación: archivo particionado en varios nodos, recuperado idéntico (hash)")
def _():
    f = rnd("grande.bin", 8 * BS + 345)
    A.mkdir("/tests")
    r = A.put(f, "/tests/grande.bin")
    st = A.stat("/tests/grande.bin")
    nodes = {n for b in st["blocks"] for n in b["in_sync"]}
    assert len(nodes) >= 3, f"solo {len(nodes)} nodos"
    assert all(len(b["in_sync"]) == 3 for b in st["blocks"]), "faltan réplicas"
    out = TMP / "grande.out"
    g = A.get("/tests/grande.bin", out)
    assert sha(f) == sha(out) == g["sha256"]
    return f"{r['blocks']} bloques en {len(nodes)} nodos, 3 copias c/u, sha256 idéntico"


@run("RF1. ls / cd / mkdir / rmdir / rm")
def _():
    A.mkdir("/rf1"); A.mkdir("/rf1/sub")
    A.cd("/rf1")
    assert A.cwd == "/rf1"
    p = rnd("x.bin", 1000)
    A.put(p, "sub/x.bin")
    names = [e["name"] for e in A.ls("sub")["entries"]]
    assert names == ["x.bin"], names
    expect("NOT_EMPTY", A.rmdir, "/rf1/sub")
    expect("EXISTS", A.mkdir, "/rf1/sub")
    A.rm("/rf1/sub/x.bin")
    expect("NOT_FOUND", A.get, "/rf1/sub/x.bin", TMP / "nada")
    A.rmdir("/rf1/sub")
    A.cd("/")
    return "jerarquía, errores NOT_EMPTY/EXISTS/NOT_FOUND correctos"


@run("2. RF3: read()/write() por bloque, append() y lock() con la semántica declarada")
def _():
    bs = A.stat("/tests/grande.bin")["block_size"]
    orig = (TMP / "grande.bin").read_bytes()
    new1 = os.urandom(bs)
    r = A.write_block("/tests/grande.bin", 3, new1)
    assert r["version"] == 2
    assert A.read_block("/tests/grande.bin", 3) == new1
    assert A.read_block("/tests/grande.bin", 2) == orig[2 * bs:3 * bs]      # los demás no cambian
    exp = bytearray(orig); exp[3 * bs:4 * bs] = new1
    extra = rnd("extra.bin", 2_500_000)
    A.append("/tests/grande.bin", extra)
    exp += extra.read_bytes()
    out = TMP / "mod.out"
    A.get("/tests/grande.bin", out)
    assert out.read_bytes() == bytes(exp), "contenido distinto tras write_block + append"
    return f"write_block y append OK, tamaño final {len(exp)} bytes, versión {A.stat('/tests/grande.bin')['version']}"


@run("3a. Concurrencia: dos clientes, mismo bloque -> uno gana, el otro recibe LOCKED")
def _():
    A2 = Client(TMP / f"home-alice{SUF}")   # segundo proceso del mismo usuario
    A2.login(f"alice{SUF}", PW)
    lk = A.lock("/tests/grande.bin", [5, 5])
    e = expect("LOCKED", A2.write_block, "/tests/grande.bin", 5, os.urandom(BS))
    A.unlock(lk["lock_id"])
    A2.write_block("/tests/grande.bin", 5, os.urandom(BS))   # ya liberado: ahora sí
    return f"segundo cliente rechazado con LOCKED (retry_after={e.extra.get('retry_after')}) y luego exitoso"


@run("3b. Concurrencia: dos clientes escriben bloques DISTINTOS del mismo archivo a la vez -> ambos avanzan")
def _():
    A2 = Client(TMP / f"home-alice{SUF}"); A2.login(f"alice{SUF}", PW)
    d1, d2 = os.urandom(BS), os.urandom(BS)
    errs = []

    def w(c, i, d):
        try:
            c.write_block("/tests/grande.bin", i, d)
        except Exception as e:  # noqa: BLE001
            errs.append(e)
    ts = [threading.Thread(target=w, args=(A, 6, d1)), threading.Thread(target=w, args=(A2, 7, d2))]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errs, errs
    assert A.read_block("/tests/grande.bin", 6) == d1 and A.read_block("/tests/grande.bin", 7) == d2
    return "los dos commits fueron aceptados; el manifiesto quedó con ambos cambios"


@run("3c. Concurrencia: lock vencido -> el commit del cliente lento se rechaza (STALE_FENCING_TOKEN)")
def _():
    A2 = Client(TMP / f"home-alice{SUF}"); A2.login(f"alice{SUF}", PW)
    slow = A.lock("/tests/grande.bin", [4, 4], ttl=3)     # A no renueva: simula un cliente congelado
    time.sleep(5)
    A2.write_block("/tests/grande.bin", 4, os.urandom(BS))   # el lock venció: otro lo obtiene y escribe
    e = expect("STALE_FENCING_TOKEN", A.write_block, "/tests/grande.bin", 4, os.urandom(BS), slow)
    return f"token {slow['fencing_token']} rechazado: {e.message}"


@run("4. Replicación y fallos: cae un nodo -> la lectura sigue y se restauran las 3 copias")
def _():
    f = rnd("rep.bin", 6 * 1024 * 1024)
    A.put(f, "/tests/rep.bin")
    subprocess.run(STOP.format(n=2), shell=True, check=True, capture_output=True)
    out = TMP / "rep.out"
    A.get("/tests/rep.bin", out)
    assert sha(f) == sha(out), "lectura con un nodo caído falló"

    target = min(3, len(A.status()["nodes"]) - 1)

    def ok():
        s = A.status()
        dead = [n for n in s["nodes"] if n["state"] == "DEAD"]
        st = A.stat("/tests/rep.bin")
        return dead and all(len(b["in_sync"]) >= target for b in st["blocks"])
    assert wait_for(ok, 60), "no se restauró la replicación"
    st = A.stat("/tests/rep.bin")
    assert all(len(b["in_sync"]) == target and "dn2" not in b["in_sync"] for b in st["blocks"])
    return f"lectura OK; dn2 DEAD; {target} copias por bloque en nodos restantes (objetivo final RF=3)"


@run("5. Consistencia: escritura con una réplica desconectada y reingreso del nodo")
def _():
    f = rnd("durante.bin", 4 * 1024 * 1024)
    A.put(f, "/tests/durante.bin")         # dn2 sigue caído
    st = A.stat("/tests/durante.bin")
    assert all("dn2" not in b["in_sync"] and len(b["in_sync"]) >= 2 for b in st["blocks"])
    out = TMP / "durante.out"; A.get("/tests/durante.bin", out)
    assert sha(f) == sha(out)
    subprocess.run(START.format(n=2), shell=True, check=True, capture_output=True)
    assert wait_for(lambda: any(n["id"] == "dn2" and n["state"] == "ALIVE" for n in A.status()["nodes"]), 30)
    assert wait_for(lambda: A.status()["blocks_under_replicated"] == 0, 60)
    A.get("/tests/durante.bin", out)
    assert sha(f) == sha(out)
    s = A.status()
    assert s["blocks_under_replicated"] == 0
    return "durante la caída ningún lector vio datos viejos; dn2 reingresó y el clúster quedó sano"


@run("6. Seguridad: autorización (acceso permitido y denegado), tokens y rutas")
def _():
    msgs = []
    expect("NOT_FOUND", B.get, "/tests/grande.bin", TMP / "robado")                # cada usuario ve solo su espacio
    msgs.append("otro usuario no ve el archivo")
    fid = A.stat("/tests/grande.bin")["fid"]
    st = A.stat("/tests/grande.bin")
    expect(403, B.req, "POST", f"/v1/files/{fid}/tokens", json={"blocks": [{"block_id": f"{fid}-0-1-abc", "gen": 1}]})
    msgs.append("otro usuario no obtiene tokens de bloque de un archivo ajeno (403)")
    expect(403, A.req, "GET", "/v1/fs/ls", params={"path": "/../etc"})
    msgs.append("rutas con .. rechazadas (403)")
    anon = Client(TMP / "anon")
    expect(401, anon.ls, "/")
    msgs.append("sin token -> 401")
    import httpx
    node = A.req("POST", "/v1/files/open", json={"path": "/tests/rep.bin", "mode": "r", "session": False})["blocks"][0]
    url = node["nodes"][0]["url"]
    kw = {"verify": A.ca} if A.ca else {}
    r = httpx.get(f"{url}/v1/blocks/{node['block_id']}", params={"gen": node["gen"]}, **kw)
    assert r.status_code == 401, r.status_code
    msgs.append("el nodo de datos sin token -> 401")
    r = httpx.get(f"{url}/v1/blocks/{node['block_id']}", params={"gen": node["gen"]},
                  headers={"X-Block-Token": "aaa.bbb.ccc"}, **kw)
    assert r.status_code == 401
    msgs.append("token falso -> 401")
    u = f"mallory{SUF}"
    c = Client(TMP / "mal"); c.register(u, PW)
    for _ in range(5):
        expect(401, c.login, u, "incorrecta-xx")
    expect(429, c.login, u, "incorrecta-xx")
    msgs.append("bloqueo tras 5 intentos fallidos (429)")
    return "; ".join(msgs)


@run("6b. Seguridad: almacenamiento cifrado en reposo (el disco del nodo no contiene el texto original)")
def _():
    files = [p for d in glob.glob(DATA_GLOB) for p in glob.glob(d + "/*") if not p.endswith(".sha")]
    if not files:
        return "omitida (no hay acceso a los discos de los nodos desde aquí)"
    plain = (TMP / "rep.bin").read_bytes()
    probe = plain[1000:1064]
    hits = [p for p in files if probe in open(p, "rb").read()]
    assert not hits, f"texto en claro encontrado en {hits[:1]}"
    return f"{len(files)} bloques en disco revisados: ninguno contiene el contenido original"


@run("7. Recolección de basura: bloques de archivos borrados y de versiones antiguas se liberan en los nodos")
def _():
    if not glob.glob(DATA_GLOB):
        return "omitida (no hay acceso a los discos de los nodos desde aquí)"
    disk = lambda fid: {os.path.basename(p) for d in glob.glob(DATA_GLOB) for p in glob.glob(d + f"/{fid}-*")
                        if not p.endswith(".sha")}
    # versiones antiguas: grande.bin tuvo varios write_block, así que hay bloques viejos en disco
    st = A.stat("/tests/grande.bin"); fid = st["fid"]
    live = {f"{b['block_id']}.{b['gen']}" for b in st["blocks"]}
    assert wait_for(lambda: disk(fid) <= live, GC_WAIT, 2), f"sobran {len(disk(fid) - live)} bloques de versiones antiguas"
    # archivo borrado
    fid2 = A.stat("/tests/rep.bin")["fid"]
    A.rm("/tests/rep.bin")
    expect("NOT_FOUND", A.get, "/tests/rep.bin", TMP / "z")
    assert wait_for(lambda: not disk(fid2), GC_WAIT, 2), f"quedan {len(disk(fid2))} bloques del archivo borrado"
    return "bloques viejos y de archivos borrados eliminados tras el periodo de gracia; los vigentes se conservan"


print("\n=== RESUMEN ===")
bad = [r for r in RES if not r[1]]
print(f"{len(RES) - len(bad)}/{len(RES)} pruebas OK")
sys.exit(1 if bad else 0)
