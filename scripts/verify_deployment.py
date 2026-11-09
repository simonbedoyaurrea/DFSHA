#!/usr/bin/env python3
"""Comprueba estado y código de los seis procesos de aplicación desplegados."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import sys
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy/aws'))
from deploy_cluster import connect, run


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--ssh-key',default=str(ROOT/'deploy/aws/secrets/ssh/dfsha-entrega.pem'))
    ap.add_argument('--inventory',default=str(ROOT/'deploy/aws/inventory.json'))
    args=ap.parse_args()
    expected={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted((ROOT/'dfsha').rglob('*.py'))}
    inventory=json.loads(Path(args.inventory).read_text())
    script=("import pathlib,hashlib,json; base=pathlib.Path('/app'); "
            "print(json.dumps({str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest() "
            "for p in (base/'dfsha').rglob('*.py')},sort_keys=True))")
    report={'captured_at':datetime.now(timezone.utc).isoformat(),
            'application_files':expected,'hosts':[]}
    for h in inventory:
        client=connect(h,Path(args.ssh_key))
        try:
            state={'n':h['n'],'id':h.get('id'),'private':h['private'],'containers':[]}
            for name in ('dfsha-control','dfsha-dn'):
                actual=json.loads(run(client,f'sudo docker exec {name} python -c '+shlex.quote(script)))
                assert actual==expected,f"código diferente en host{h['n']} {name}"
                state['containers'].append({'name':name,'code_matches':True})
            raw=run(client,"sudo docker inspect dfsha-control dfsha-dn dfsha-etcd --format '{{json .State}}'")
            states=[json.loads(line) for line in raw.splitlines()]
            assert len(states)==3 and all(s['Running'] for s in states)
            state['all_running']=True
            state['images']=run(client,"sudo docker inspect dfsha-control dfsha-dn dfsha-etcd --format '{{.Name}} {{.Image}}'").splitlines()
            state['disk']=run(client,'df -B1 --output=size,used,avail,pcent /').strip()
            report['hosts'].append(state)
            if h['n']==1:
                command='cd /home/ubuntu/dfsha-copia && PYTHONPATH=. .venv/bin/python -c '+shlex.quote(
                    'from dfsha.client.core import Client; import json; print(json.dumps(Client().status()))')
                report['cluster_status']=json.loads(run(client,command))
                report['runtime_dependencies']=run(client,'sudo docker exec dfsha-control python -m pip freeze').splitlines()
                report['etcd_status']=json.loads(run(client,
                    'cd /home/ubuntu/dfsha-copia && .venv/bin/python deploy/aws/node.py etcd-status 1'))
        finally:client.close()
    assert all(n['state']=='ALIVE' for n in report['cluster_status']['nodes'])
    assert report['cluster_status']['blocks_under_replicated']==0
    (ROOT/'results/aws-runtime-manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'hosts':len(report['hosts']),'containers_running':9,
                      'application_code_matches':True,'blocks_under_replicated':0},indent=2))


if __name__=='__main__':main()
