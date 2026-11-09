"""CLI de DFSha:  python -m dfsha.client.cli <comando> ..."""
import argparse
import getpass
import os
import sys

from .core import Client, DfshaError


def fmt_size(n):
    for u in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TiB"


def password(args):
    return args.password or os.environ.get("DFSHA_PASSWORD") or getpass.getpass("Contraseña: ")


def parse_blocks(s):
    if s is None:
        return None
    a, _, b = s.partition("-")
    return [int(a), int(b) if b else int(a)]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dfsha", description="Cliente de DFSha (sistema de archivos distribuido)")
    sp = ap.add_subparsers(dest="cmd", required=True)

    def add(name, *args, **kw):
        p = sp.add_parser(name, **kw)
        for a in args:
            p.add_argument(a)
        return p

    for n in ("register", "login"):
        p = add(n, "user")
        p.add_argument("--password")
    sp.add_parser("logout")
    sp.add_parser("whoami")
    sp.add_parser("pwd")
    sp.add_parser("status", help="estado de los nodos y de la replicación")
    p = sp.add_parser("ls"); p.add_argument("path", nargs="?", default=".")
    add("cd", "path")
    add("mkdir", "path")
    add("rmdir", "path")
    add("rm", "path")
    add("stat", "path")
    p = add("put", "local"); p.add_argument("remote", nargs="?")
    p = add("get", "remote"); p.add_argument("local", nargs="?")
    p = add("lock", "path"); p.add_argument("--blocks", help="rango de bloques, ej. 2-5 (por defecto todo el archivo)")
    p.add_argument("--ttl", type=int); p.add_argument("--mode", default="w", choices=["r", "w"])
    add("unlock", "lock_id")
    p = add("read-block", "path", "index"); p.add_argument("-o", "--out")
    p = add("write-block", "path", "index", "local"); p.add_argument("--lock-id"); p.add_argument("--fencing", type=int)
    add("append", "path", "local")
    p = add("open", "path"); p.add_argument("--mode", choices=["r", "w"], default="r")
    p.add_argument("--create", action="store_true"); p.add_argument("--blocks")
    add("close", "session_id")
    add("renew", "session_id")
    p = add("read", "session_id", "index"); p.add_argument("-o", "--out")
    add("write", "session_id", "index", "local")
    a = ap.parse_args(argv)
    c = Client()
    try:
        if a.cmd == "register":
            print("usuario creado:", c.register(a.user, password(a))["username"])
        elif a.cmd == "login":
            c.login(a.user, password(a)); print("sesión iniciada como", a.user)
        elif a.cmd == "logout":
            c.logout(); print("sesión cerrada")
        elif a.cmd == "whoami":
            print(c.state.get("user", "(sin sesión)"))
        elif a.cmd == "pwd":
            print(c.cwd)
        elif a.cmd == "cd":
            print(c.cd(a.path))
        elif a.cmd == "ls":
            for e in c.ls(a.path)["entries"]:
                if e["type"] == "dir":
                    print(f"d  {'-':>10}  {e['name']}/")
                else:
                    print(f"-  {fmt_size(e['size']):>10}  {e['name']}  (v{e['version']})")
        elif a.cmd == "mkdir":
            print("creada", c.mkdir(a.path)["path"])
        elif a.cmd == "rmdir":
            print("borrada", c.rmdir(a.path)["deleted"])
        elif a.cmd == "rm":
            print("borrado", c.rm(a.path)["deleted"])
        elif a.cmd == "stat":
            s = c.stat(a.path)
            print(f"{s['path']}  tipo={s['type']}", end="")
            if s["type"] == "file":
                print(f"  tamaño={fmt_size(s['size'])}  versión={s['version']}  bloques={len(s['blocks'])}")
                for b in s["blocks"]:
                    print(f"  bloque {b['index']:>3}  gen {b['gen']}  {b['sha256'][:12]}…  copias al día: {', '.join(b['in_sync'])}")
            else:
                print()
        elif a.cmd == "status":
            s = c.status()
            print(f"copias por bloque (N)={s['rf']}  quórum de escritura (W)={s['w']}")
            for n in s["nodes"]:
                print(f"  {n['id']:<6} {n['state']:<8} bloques={n['blocks']:<5} último latido hace {n['last_hb_age']} s  {n['url']}")
            print(f"bloques: {s['blocks_total']}  con menos copias de las debidas: {s['blocks_under_replicated']}")
        elif a.cmd == "put":
            r = c.put(a.local, a.remote or os.path.basename(a.local))
            print(f"subido {r['path']}  {fmt_size(r['size'])}  {r['blocks']} bloques  versión {r['version']}")
        elif a.cmd == "get":
            r = c.get(a.remote, a.local or os.path.basename(a.remote))
            print(f"descargado  {fmt_size(r['size'])}  versión {r['version']}  sha256={r['sha256']}")
        elif a.cmd == "lock":
            r = c.lock(a.path, parse_blocks(a.blocks), a.mode, a.ttl)
            print(f"lock {r['lock_id']}  fencing_token={r['fencing_token']}  vence en {r['ttl']} s (sin renovar)")
        elif a.cmd == "unlock":
            print(c.unlock(a.lock_id))
        elif a.cmd == "read-block":
            data = c.read_block(a.path, int(a.index))
            if a.out:
                open(a.out, "wb").write(data); print(f"{len(data)} bytes escritos en {a.out}")
            else:
                sys.stdout.buffer.write(data)
        elif a.cmd == "write-block":
            lk = {"lock_id": a.lock_id, "fencing_token": a.fencing} if a.lock_id else None
            print(c.write_block(a.path, int(a.index), open(a.local, "rb").read(), lk))
        elif a.cmd == "append":
            print(c.append(a.path, a.local))
        elif a.cmd == "open":
            blocks = parse_blocks(a.blocks)
            handle = c.open(a.path, a.mode, create=a.create, ranges=[blocks] if blocks else None)
            c.state.setdefault("handles", {})[handle["session_id"]] = handle
            c.save()
            print(f"sesión {handle['session_id']}  modo={handle['mode']}  versión={handle['version']}  tamaño={handle['size']}")
        elif a.cmd in ("close", "renew", "read", "write"):
            handle = c.state.get("handles", {}).get(a.session_id)
            if handle is None:
                raise DfshaError(404, "NOT_FOUND", "esta CLI no tiene esa sesión abierta")
            if a.cmd == "close":
                print(c.close(handle))
                del c.state["handles"][a.session_id]
            elif a.cmd == "renew":
                print(c.renew(handle))
            elif a.cmd == "read":
                data = c.read(handle, int(a.index))
                if a.out:
                    with open(a.out, "wb") as out:
                        out.write(data)
                    print(f"{len(data)} bytes escritos en {a.out}")
                else:
                    sys.stdout.buffer.write(data)
            else:
                with open(a.local, "rb") as source:
                    print(c.write(handle, int(a.index), source.read()))
            c.save()
    except DfshaError as e:
        print("ERROR:", e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
