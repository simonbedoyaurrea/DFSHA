#!/usr/bin/env python3
"""Fases de prueba mientras el coordinador AWS detiene y arranca host3."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from dfsha.client.core import Client, DfshaError

STATE=ROOT/'.run/host-failure'
STATE.mkdir(exist_ok=True)
REPORT=ROOT/'results/aws-host-failure.json'


def wait(fn,timeout=120):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            if fn():return
        except DfshaError:pass
        time.sleep(2)
    raise AssertionError('el host no alcanzó el estado esperado')


def main(phase):
    c=Client(STATE/'home')
    report=json.loads(REPORT.read_text()) if REPORT.exists() else {'phases':[]}
    source=STATE/'base.bin';new=STATE/'during.bin';out=STATE/'out.bin'
    if phase=='before':
        user='host'+uuid.uuid4().hex[:10]
        c.register(user,'pruebas-dfsha-2026');c.login(user,'pruebas-dfsha-2026')
        source.write_bytes(os.urandom(8*1024*1024+123));c.put(source,'/base.bin')
        assert all(len(b['in_sync'])==3 for b in c.stat('/base.bin')['blocks'])
        result={'phase':phase,'ok':True,'copies':3,'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
    elif phase=='during':
        wait(lambda:any(n['id']=='dn3' and n['state']=='DEAD' for n in c.status()['nodes']))
        c.get('/base.bin',out);assert out.read_bytes()==source.read_bytes()
        new.write_bytes(os.urandom(5*1024*1024+9));c.put(new,'/durante.bin')
        st=c.stat('/durante.bin');assert all(set(b['in_sync'])=={'dn1','dn2'} for b in st['blocks'])
        c.get('/durante.bin',out);assert out.read_bytes()==new.read_bytes()
        result={'phase':phase,'ok':True,'copies_for_new_write':2,
                'read_before_failure':'correcta','new_write':'confirmada con mayoría de etcd y W=2',
                'sha256':hashlib.sha256(new.read_bytes()).hexdigest()}
    elif phase=='after':
        wait(lambda:any(n['id']=='dn3' and n['state']=='ALIVE' for n in c.status()['nodes']))
        wait(lambda:c.status()['blocks_under_replicated']==0)
        c.get('/durante.bin',out);assert out.read_bytes()==new.read_bytes()
        result={'phase':phase,'ok':True,'restored_copies':3,'cluster':c.status()}
    else:raise ValueError(phase)
    report['phases'].append(result);REPORT.write_text(json.dumps(report,indent=2))
    print(json.dumps(result,ensure_ascii=False),flush=True)


if __name__=='__main__':main(sys.argv[1])
