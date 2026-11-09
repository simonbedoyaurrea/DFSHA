#!/usr/bin/env python3
"""Alta disponibilidad del plano de control: cae un nodo etcd (el líder) y una instancia del control.
Requiere el clúster local con ETCD3=1:  ETCD3=1 scripts/local.sh up
"""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dfsha.client.core import Client  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LOCAL = f"{ROOT}/scripts/local.sh"
TMP = Path(tempfile.mkdtemp(prefix="dfsha-ha-"))
c = Client(TMP / "h")
u = f"ha{int(time.time()) % 100000}"
c.register(u, "clave-segura-123"); c.login(u, "clave-segura-123")
f = TMP / "a.bin"; f.write_bytes(os.urandom(5_000_000))
c.mkdir("/ha"); c.put(f, "/ha/antes.bin")
print("[ok] datos escritos con el clúster completo")


def ops(tag):
    t = time.time()
    c.put(f, f"/ha/{tag}.bin")
    out = TMP / f"{tag}.out"
    r = c.get(f"/ha/{tag}.bin", out)
    assert out.read_bytes() == f.read_bytes()
    c.get("/ha/antes.bin", TMP / "antes.out")
    assert (TMP / "antes.out").read_bytes() == f.read_bytes()
    print(f"[ok] {tag}: put + get + lectura de datos previos correctos ({time.time() - t:.1f}s)")


# 1) cae el nodo etcd que es líder de Raft (detectado con etcdctl)
cmd = [f"{ROOT}/.run/bin/etcdctl", "--endpoints=https://127.0.0.1:2379,https://127.0.0.2:2379,https://127.0.0.3:2379",
       f"--cacert={ROOT}/certs/ca.crt", f"--cert={ROOT}/certs/control.crt", f"--key={ROOT}/certs/control.key",
       "endpoint", "status", "--cluster", "-w", "simple"]
out = subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
print("estado etcd:", out)
leader = None
for ln in out:
    parts = [p.strip() for p in ln.split(",")]
    if len(parts) > 4 and parts[4] == "true":
        leader = int(parts[0].split("//")[1].split(":")[0].split(".")[-1])
print(f"líder de etcd actual: etcd{leader}")
subprocess.run([LOCAL, "etcd-stop", str(leader)], check=True, capture_output=True)
t = time.time()
ops("tras_caida_etcd")
print(f"[ok] el sistema siguió funcionando con etcd{leader} caído (Raft eligió nuevo líder)")

# 2) cae además una instancia del servicio de control (el cliente cambia de semilla solo)
subprocess.run(["bash", "-c", f"kill $(cat {ROOT}/.run/pids/control1.pid)"], check=True)
time.sleep(1)
ops("tras_caida_control")
print("[ok] el cliente conmutó a otra instancia del control sin intervención")

# 3) se recupera el nodo etcd
subprocess.run([LOCAL, "etcd-start", str(leader)], check=True, capture_output=True)
time.sleep(4)
ops("tras_recuperar_etcd")
print("RESULTADO: plano de control tolera la caída de 1 nodo etcd y de 1 instancia de control")
