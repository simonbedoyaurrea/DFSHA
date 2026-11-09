#!/usr/bin/env python3
"""Mediciones de rendimiento: latencia y throughput de put/get, efecto del paralelismo y de la concurrencia.

  python tests/bench.py [--label sin-tls] [--sizes 1,10,50] [--repeats 5] [--clients 1,2,4]
Escribe results/<label>.csv y muestra un resumen (mediana y p95).
"""
import argparse
import csv
import os
import statistics as st
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dfsha.client.core import Client, DfshaError  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--label", default="run")
ap.add_argument("--sizes", default="1,10,50", help="tamaños en MiB")
ap.add_argument("--repeats", type=int, default=5)
ap.add_argument("--clients", default="1,2,4")
ap.add_argument("--workers", default="1,8", help="transferencias paralelas por cliente")
a = ap.parse_args()

TMP = Path(tempfile.mkdtemp(prefix="dfsha-bench-"))
user = f"bench{int(time.time()) % 100000}"
PW = "bench-clave-123"


def mk(i):
    c = Client(TMP / f"h{i}")
    try:
        c.register(user, PW)
    except DfshaError:
        pass
    c.login(user, PW)
    return c


def p95(v):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))]


rows = []
c0 = mk(0)
c0.mkdir("/bench")
print(f"== {a.label}: operaciones por tamaño y paralelismo (mediana / p95 sobre {a.repeats} repeticiones) ==")
print(f"{'MiB':>5} {'workers':>8} {'op':>4} {'lat. med (s)':>13} {'lat. p95 (s)':>13} {'MB/s (med)':>11}")
for mib in [int(x) for x in a.sizes.split(",")]:
    src = TMP / f"f{mib}.bin"
    src.write_bytes(os.urandom(mib * 1024 * 1024))
    for w in [int(x) for x in a.workers.split(",")]:
        for op in ("put", "get"):
            ts = []
            for r in range(a.repeats):
                t = time.perf_counter()
                if op == "put":
                    c0.put(src, f"/bench/f{mib}_{w}_{r}.bin", workers=w)
                else:
                    c0.get(f"/bench/f{mib}_{w}_{r}.bin", TMP / "out.bin", workers=w)
                ts.append(time.perf_counter() - t)
                rows.append([a.label, "size", mib, w, 1, op, r, round(ts[-1], 4), round(mib / ts[-1], 2)])
            print(f"{mib:>5} {w:>8} {op:>4} {st.median(ts):>13.3f} {p95(ts):>13.3f} {mib / st.median(ts):>11.1f}")

print(f"\n== {a.label}: concurrencia (N clientes escribiendo/leyendo archivos de 10 MiB a la vez) ==")
print(f"{'clientes':>9} {'op':>4} {'tiempo total (s)':>17} {'MB/s agregado':>14} {'lat. p95 (s)':>13}")
src = TMP / "c10.bin"
src.write_bytes(os.urandom(10 * 1024 * 1024))
for n in [int(x) for x in a.clients.split(",")]:
    clients = [mk(i) for i in range(n)]
    for op in ("put", "get"):
        lat, errs = [], []

        def job(i):
            try:
                t = time.perf_counter()
                if op == "put":
                    clients[i].put(src, f"/bench/c_{n}_{i}.bin", workers=4)
                else:
                    clients[i].get(f"/bench/c_{n}_{i}.bin", TMP / f"o{i}.bin", workers=4)
                lat.append(time.perf_counter() - t)
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        t0 = time.perf_counter()
        ths = [threading.Thread(target=job, args=(i,)) for i in range(n)]
        [t.start() for t in ths]; [t.join() for t in ths]
        tot = time.perf_counter() - t0
        if errs:
            raise RuntimeError(f"fallaron {len(errs)}/{n} operaciones: {errs}")
        for i, l in enumerate(lat):
            rows.append([a.label, "concurrency", 10, 4, n, op, i, round(l, 4), round(10 / l, 2)])
        print(f"{n:>9} {op:>4} {tot:>17.2f} {10 * n / tot:>14.1f} {p95(lat) if lat else float('nan'):>13.3f}"
              + (f"   errores: {len(errs)}" if errs else ""))

out = Path(__file__).resolve().parents[1] / "results"
out.mkdir(exist_ok=True)
with open(out / f"{a.label}.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["condicion", "experimento", "MiB", "workers", "clientes", "op", "repeticion", "segundos", "MB_por_s"])
    w.writerows(rows)
print(f"\nResultados crudos en results/{a.label}.csv")
