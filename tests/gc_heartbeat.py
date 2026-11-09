#!/usr/bin/env python3
"""Regresión de disponibilidad: limpiar muchos bloques no debe frenar heartbeats."""
import json
from pathlib import Path
import shlex
import sys
import tempfile
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from dfsha.client.core import Client
from deploy.aws.node import remote


def main():
    directory=Path(tempfile.mkdtemp(prefix='gc-stress-',dir=ROOT/'.run'))
    client=Client(directory/'client');observer=Client(directory/'observer')
    user='gc'+uuid.uuid4().hex[:10];pw='pruebas-dfsha-2026'
    client.register(user,pw);client.login(user,pw);observer.login(user,pw)
    client.mkdir('/gc')
    config=client.status()['config']
    source=directory/'small.bin';source.write_bytes(b'gc-heartbeat'*100)
    time.sleep(5)
    samples=[];errors=[];stop=threading.Event()

    def observe():
        while not stop.is_set():
            try:
                nodes=observer.status()['nodes']
                samples.append({'t':round(time.monotonic(),3),'nodes':[
                    {'id':n['id'],'state':n['state'],'age':n['last_hb_age']} for n in nodes]})
            except Exception as exc:errors.append(str(exc))
            stop.wait(1)

    thread=threading.Thread(target=observe,daemon=True);thread.start()
    names=[]
    started=time.monotonic()
    remaining=200
    try:
        for n in range(200):
            path=f'/gc/f{n}.bin';client.put(source,path)
            block=client.stat(path)['blocks'][0]
            names.append(f"{block['block_id']}.{block['gen']}")
        for n in range(200):client.rm(f'/gc/f{n}.bin')
        script=("import pathlib,json; names=set("+repr(names)+
                "); present={p.name for p in pathlib.Path('/var/lib/docker/volumes/dfsha_dn-data/_data').iterdir()}; "
                "print(len(names & present))")
        deadline=time.monotonic()+config['gc_grace']+90
        while time.monotonic()<deadline:
            remaining=int(remote(1,'sudo python3 -c '+shlex.quote(script)).strip())
            if remaining==0:break
            time.sleep(3)
        assert remaining==0,remaining
        assert not errors,errors
        false_dead=[sample for sample in samples if any(n['state']=='DEAD' for n in sample['nodes'])]
        assert not false_dead,false_dead[:2]
        max_age=max(n['age'] for sample in samples for n in sample['nodes'])
        assert max_age<config['dead_after'],max_age
        report={'ok':True,'created_files':200,'deleted_blocks_on_host1':200,'remaining_on_host1':remaining,
                'samples':len(samples),'max_heartbeat_age_seconds':max_age,'false_dead_states':0,
                'seconds':round(time.monotonic()-started,3),'observations':samples}
        (ROOT/'results/aws-gc-heartbeat.json').write_text(json.dumps(report,indent=2))
        print(json.dumps({k:v for k,v in report.items() if k!='observations'}),flush=True)
    finally:
        stop.set();thread.join(timeout=30)


if __name__=='__main__':main()
