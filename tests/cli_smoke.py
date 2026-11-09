#!/usr/bin/env python3
"""Recorrido por la CLI real, incluidas las primitivas RF3 explícitas."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[1]
home=Path(tempfile.mkdtemp(prefix='cli-',dir=ROOT/'.run'))
env={**os.environ,'PYTHONPATH':str(ROOT),'DFSHA_HOME':str(home/'home'),
     'DFSHA_PASSWORD':'pruebas-dfsha-2026'}
commands=[]


def cli(*args,ok=True):
    p=subprocess.run([sys.executable,'-m','dfsha.client.cli',*map(str,args)],
                     cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    commands.append({'command':str(args[0]),'exit':p.returncode})
    assert (p.returncode==0)==ok,(args,p.stdout,p.stderr)
    return p.stdout+p.stderr


def main():
    user='cli'+uuid.uuid4().hex[:10]
    cli('register',user);cli('login',user);cli('mkdir','/cli');cli('cd','/cli')
    source=home/'source.bin';source.write_bytes(b'A'*(4*1024*1024))
    cli('put',source,'archivo.bin')
    session=re.search(r'sesión ([0-9a-f]+)',cli('open','archivo.bin','--mode','w','--blocks','0-0')).group(1)
    source.write_bytes(b'Z'*(4*1024*1024));cli('write',session,0,source)
    out=home/'read.bin';cli('read',session,0,'-o',out);assert out.read_bytes()==source.read_bytes()
    cli('close',session);cli('read',session,0,'-o',out,ok=False)
    lock=re.search(r'lock ([^ ]+)',cli('lock','archivo.bin','--blocks','0-0')).group(1)
    assert 'LOCKED' in cli('write-block','archivo.bin',0,source,ok=False)
    cli('unlock',lock)
    extra=home/'extra.bin';extra.write_bytes(b'contenido-anexado')
    cli('append','archivo.bin',extra);cli('get','archivo.bin',out)
    assert out.read_bytes()==source.read_bytes()+extra.read_bytes()
    snapshot=re.search(r'sesión ([0-9a-f]+)',cli('open','archivo.bin')).group(1)
    replacement=home/'replacement.bin';replacement.write_bytes(b'archivo-reemplazado')
    cli('put',replacement,'archivo.bin');cli('read',snapshot,0,'-o',out)
    assert out.read_bytes()==source.read_bytes();cli('close',snapshot)
    cli('rmdir','/cli',ok=False);cli('rm','archivo.bin');cli('cd','/');cli('rmdir','/cli')
    report={'ok':True,'commands':commands,'explicit_rf3':'open/read/write/close',
            'snapshot':'contenido anterior conservado después de put',
            'append_sha256':hashlib.sha256(source.read_bytes()+extra.read_bytes()).hexdigest()}
    (ROOT/'results/aws-cli.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
