#!/usr/bin/env python3
"""Operaciones de prueba sobre los hosts del inventario de esta copia."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def remote(n, command):
    hosts = json.loads((ROOT/'deploy/aws/inventory.json').read_text())
    host = next(h for h in hosts if h['n']==int(n))
    result = subprocess.run(['ssh','-i',str(Path.home()/'.ssh/dfsha-entrega.pem'),
        '-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=accept-new',
        f"ubuntu@{host['private']}",command],capture_output=True,text=True,timeout=180)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return result.stdout


def action(operation,n):
    if operation in ('stop','start'):
        return remote(n,f'sudo docker {operation} dfsha-dn')
    if operation in ('control-stop','control-start','etcd-stop','etcd-start'):
        role,verb=operation.split('-')
        return remote(n,f'sudo docker {verb} dfsha-{role}')
    if operation=='status':
        return remote(n,"sudo docker ps --format '{{.Names}} {{.Status}}'")
    if operation=='etcd-status':
        hosts=json.loads((ROOT/'deploy/aws/inventory.json').read_text())
        eps=','.join(f"https://{h['private']}:2379" for h in hosts)
        return remote(n,f'sudo docker exec dfsha-etcd etcdctl --endpoints={eps} '
            f'--cacert=/certs/ca.crt --cert=/certs/host{n}.crt --key=/certs/host{n}.key endpoint status --cluster -w json')
    raise ValueError(operation)


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action');ap.add_argument('n',type=int)
    a=ap.parse_args();print(action(a.action,a.n))
