#!/usr/bin/env python3
"""Verificación reproducible del enunciado en el clúster AWS de esta copia.

    PYTHONPATH=. .venv/bin/python tests/acceptance.py --large-mib 1024 --label aws

Ejecutar desde host1. Las caídas se restauran en bloques finally.
Genera resultados JSON, hashes y un log por prueba en results/.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import ssl
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import urlparse

import httpx

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from dfsha.client.core import Client, DfshaError, SessionKeeper
from deploy.aws.node import action, remote


def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as source:
        for chunk in iter(lambda:source.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def expect(code, fn, *args, **kw):
    try:fn(*args,**kw)
    except DfshaError as e:
        assert e.code==code or e.status==code,(code,str(e))
        return str(e)
    raise AssertionError(f'no se produjo {code}')


def wait(predicate,timeout=90):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            result=predicate()
            if result:return result
        except (DfshaError,RuntimeError,httpx.HTTPError):pass
        time.sleep(2)
    raise AssertionError('tiempo de espera agotado')


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--large-mib',type=int,default=1024)
    ap.add_argument('--label',default='aws');ap.add_argument('--skip-long-gc',action='store_true')
    args=ap.parse_args()
    result_dir=ROOT/'results';result_dir.mkdir(exist_ok=True)
    temp=Path(tempfile.mkdtemp(prefix='acceptance-',dir=ROOT/'.run'))
    report={'label':args.label,'started':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':[]}
    pw='pruebas-dfsha-2026';user='valid'+uuid.uuid4().hex[:10]
    a=Client(temp/'a');a.register(user,pw);a.login(user,pw)
    b=Client(temp/'b');b.login(user,pw)
    other=Client(temp/'other')
    outsider='outsider'+uuid.uuid4().hex[:8]
    other.register(outsider,pw);other.login(outsider,pw)
    wait(lambda:len(a.status()['nodes'])==3 and all(n['state']=='ALIVE' for n in a.status()['nodes']))
    config=a.status()['config'];bs=config['block_size']
    a.mkdir('/validacion')
    report['configuration']={'block_size':bs,'nodes':a.status()['nodes'],'rf':3,'w':2,
                             'platform':sys.platform,'python':sys.version.split()[0]}

    def run(name,category,fn):
        started=time.monotonic()
        try:
            detail=fn();entry={'name':name,'category':category,'ok':True,'detail':detail}
        except Exception as exc:
            entry={'name':name,'category':category,'ok':False,'error':f'{type(exc).__name__}: {exc}'}
        entry['seconds']=round(time.monotonic()-started,3)
        report['tests'].append(entry)
        (result_dir/f'{args.label}-acceptance.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(entry,ensure_ascii=False),flush=True)

    def small(name,content):
        path=temp/name;path.write_bytes(content);return path

    source=temp/'large.bin'
    def large():
        with source.open('wb') as out:
            for _ in range(args.large_mib):out.write(os.urandom(1024*1024))
            out.write(b'ultimo-bloque-incompleto')
        original=digest(source)
        uploaded=a.put(source,'/validacion/grande.bin',workers=4)
        st=a.stat('/validacion/grande.bin')
        assert len(st['blocks'])>1
        assert len({n for blk in st['blocks'] for n in blk['in_sync']})==3
        assert all(len(blk['in_sync'])==3 for blk in st['blocks'])
        out=temp/'large.out';r=a.get('/validacion/grande.bin',out,workers=4)
        assert original==digest(out)==r['sha256']
        out.unlink()
        return {'bytes':source.stat().st_size,'blocks':uploaded['blocks'],'sha256':original,
                'nodes':sorted({n for blk in st['blocks'] for n in blk['in_sync']})}
    run('Archivo grande, distribución y hash idéntico','Carga y recuperación',large)

    base=small('base.bin',b'A'*bs+b'B'*bs+b'C'*123)
    a.put(base,'/validacion/edit.bin')
    def rf1():
        a.mkdir('/validacion/carpeta');a.cd('/validacion/carpeta')
        a.put(small('tiny.bin',b'contenido'),'tiny.bin')
        assert a.ls()['entries'][0]['name']=='tiny.bin'
        expect('NOT_EMPTY',a.rmdir,'/validacion/carpeta')
        expect('NOT_FOUND',a.cd,'/no-existe')
        a.rm('tiny.bin');a.cd('/');a.rmdir('/validacion/carpeta')
        return 'ls, cd, mkdir, rmdir y rm; directorio no vacío y ruta inexistente comprobados'
    run('Jerarquía y espacio propio','Carga y recuperación',rf1)

    def rf3():
        h=a.open('/validacion/edit.bin','w',ranges=[[0,0]])
        try:
            assert a.read(h,0)==b'A'*bs
            a.write(h,0,b'D'*bs)
            assert a.read(h,0)==b'D'*bs
        finally:a.close(h)
        expect('SESSION_EXPIRED',a.read,h,0)
        a.append('/validacion/edit.bin',small('append.bin',b'E'*200))
        assert a.read_block('/validacion/edit.bin',2)==b'C'*123+b'E'*200
        expect('TRUNCATE_UNSUPPORTED',a.write_block,'/validacion/edit.bin',2,b'corto')
        empty=small('empty.bin',b'');a.put(empty,'/validacion/vacio.bin')
        out=temp/'empty.out';a.get('/validacion/vacio.bin',out);assert out.stat().st_size==0
        return 'open/read/write/close explícitos; append, rechazo de truncado y archivo vacío correctos'
    run('Operaciones RF3 con la semántica declarada','Acceso RF3',rf3)

    def concurrency():
        barrier=threading.Barrier(2);release=threading.Event();outcomes=[]
        def writer(c,mark):
            barrier.wait()
            try:h=c.open('/validacion/edit.bin','w',ranges=[[0,0]])
            except DfshaError as e:
                outcomes.append(e.code);release.set();return
            try:
                # El ganador conserva la reserva hasta observar el otro intento.
                release.wait(10);c.write(h,0,mark*bs);outcomes.append('OK')
            finally:c.close(h)
        with ThreadPoolExecutor(2) as pool:
            jobs=[pool.submit(writer,a,b'F'),pool.submit(writer,b,b'G')]
            [j.result() for j in jobs]
        assert sorted(outcomes)==['LOCKED','OK'],outcomes
        result=a.read_block('/validacion/edit.bin',0);assert result in (b'F'*bs,b'G'*bs)
        with ThreadPoolExecutor(2) as pool:
            jobs=[pool.submit(a.write_block,'/validacion/edit.bin',0,b'H'*bs),
                  pool.submit(b.write_block,'/validacion/edit.bin',1,b'I'*bs)]
            [j.result() for j in jobs]
        assert a.read_block('/validacion/edit.bin',0)==b'H'*bs
        assert a.read_block('/validacion/edit.bin',1)==b'I'*bs
        slow=a.lock('/validacion/edit.bin',[0,0],ttl=2);time.sleep(4)
        expect('STALE_FENCING_TOKEN',a.write_block,'/validacion/edit.bin',0,b'J'*bs,slow)
        return {'same_block':outcomes,'different_blocks':'ambos cambios conservados','expired_lock':'rechazado'}
    run('Dos escritores simultáneos y lock vencido','Concurrencia',concurrency)

    def snapshot():
        a.put(small('snapshot.bin',b'viejo'*1000),'/validacion/snapshot.bin')
        old=a.open('/validacion/snapshot.bin')
        old_name=f"{old['blocks'][0]['block_id']}.{old['blocks'][0]['gen']}"
        try:
            a.put(small('new.bin',b'nuevo'*1000),'/validacion/snapshot.bin')
            assert a.read(old,0)==b'viejo'*1000
            assert a.read_block('/validacion/snapshot.bin',0)==b'nuevo'*1000
            a.rm('/validacion/snapshot.bin')
            expect('NOT_FOUND',a.open,'/validacion/snapshot.bin')
            assert a.read(old,0)==b'viejo'*1000
            # Mantener pin más allá del umbral de GC verifica que no basta una espera fija.
            if not args.skip_long_gc:
                with SessionKeeper(a,old,close_on_exit=False):
                    time.sleep(config['gc_grace']+12)
                    assert a.read(old,0)==b'viejo'*1000
        finally:a.close(old)
        if not args.skip_long_gc:
            command="sudo python3 -c "+shlex.quote(
                f"from pathlib import Path; print((Path('/var/lib/docker/volumes/dfsha_dn-data/_data')/{old_name!r}).exists())")
            wait(lambda:remote(1,command).strip()=='False',config['gc_grace']+50)
        exp=a.req('POST','/v1/files/open',json={'path':'/validacion/edit.bin','mode':'r','ttl':2})
        time.sleep(4)
        expect('SESSION_EXPIRED',a.read,exp,0)
        return {'old_reader':'versión original conservada tras reemplazo y borrado',
                'new_reader':'nuevo contenido; 404 tras rm','pin_gc_test':not args.skip_long_gc,
                'expired_session':'410','cleanup_after_close':not args.skip_long_gc}
    run('Lectura consistente durante reemplazo y borrado','Consistencia',snapshot)

    def replica():
        a.put(small('replica.bin',b'original'*1000),'/validacion/replica.bin')
        before=a.stat('/validacion/replica.bin')['blocks'][0]['block_id']
        action('stop',3)
        try:
            assert a.read_block('/validacion/replica.bin',0)==b'original'*1000
            wait(lambda:any(n['id']=='dn3' and n['state']=='DEAD' for n in a.status()['nodes']),45)
            a.write_block('/validacion/replica.bin',0,b'actualizado'*1000)
            assert b.read_block('/validacion/replica.bin',0)==b'actualizado'*1000
            st=a.stat('/validacion/replica.bin');assert len(st['blocks'][0]['in_sync'])==2
            assert 'dn3' not in st['blocks'][0]['in_sync']
            assert before!=st['blocks'][0]['block_id']
        finally:action('start',3)
        wait(lambda:len(a.stat('/validacion/replica.bin')['blocks'][0]['in_sync'])==3,90)
        assert a.read_block('/validacion/replica.bin',0)==b'actualizado'*1000
        return 'lectura durante caída, escritura W=2, versión nueva y restauración de RF=3 comprobadas'
    run('Réplica desconectada durante una modificación','Replicación y fallos',replica)

    def interrupted():
        h=a.open('/validacion/interrumpido.bin','w',create=True)
        try:
            allocation=a.req('POST',f"/v1/files/{h['fid']}/blocks:allocate",
                             json={'lock_id':h['lock']['lock_id'],'indexes':[0]})['blocks'][0]
            response=a.nodes_http.put(f"{allocation['replicas'][0]['url']}/v1/blocks/{allocation['block_id']}",
                params={'gen':allocation['gen']},content=b'solo una parte',
                headers={'X-Block-Token':allocation['token'],'X-Sha256':'0'*64})
            assert response.status_code==422
            expect('NOT_FOUND',b.open,'/validacion/interrumpido.bin')
            target=next(rep for rep in allocation['replicas'] if rep['id']=='dn3')
            url=urlparse(target['url'])
            ctx=ssl.create_default_context(cafile=a.ca)
            raw=socket.create_connection((url.hostname,url.port),timeout=10)
            connection=ctx.wrap_socket(raw,server_hostname=url.hostname)
            try:
                header=(f"PUT /v1/blocks/{allocation['block_id']}?gen={allocation['gen']} HTTP/1.1\r\n"
                        f"Host: {url.hostname}\r\nContent-Length: {bs+28}\r\n"
                        f"X-Block-Token: {allocation['token']}\r\nX-Sha256: {'0'*64}\r\n\r\n")
                connection.sendall(header.encode()+b'fragmento'*100)
                time.sleep(1)
                action('stop',3)
            finally:
                connection.close()
                action('start',3)
            wait(lambda:a.nodes_http.get(target['url']+'/health').status_code==200,40)
            expect('NOT_FOUND',b.open,'/validacion/interrumpido.bin')
            filename=f"{allocation['block_id']}.{allocation['gen']}"
            check="sudo docker exec dfsha-dn python -c "+shlex.quote(
                f"from pathlib import Path; print((Path('/data')/{filename!r}).exists())")
            assert remote(3,check).strip()=='False'
        finally:a.close(h)
        return 'hash incorrecto rechazado; dn3 detenido a mitad del envío; sin bloque final ni archivo publicado'
    run('Carga interrumpida no publica un archivo parcial','Replicación y fallos',interrupted)

    def security():
        expect('NOT_FOUND',other.open,'/validacion/edit.bin')
        h=a.open('/validacion/edit.bin')
        try:
            blk=h['blocks'][0]
            expect(403,other.req,'POST',f"/v1/files/{h['fid']}/tokens",
                   json={'session_id':h['session_id'],'blocks':[blk]})
            anon=Client(temp/'anon');expect(401,anon.ls)
            expect(403,a.req,'GET','/v1/fs/ls',params={'path':'/../etc'})
            response=a.nodes_http.get(f"{blk['nodes'][0]['url']}/v1/blocks/{blk['block_id']}",params={'gen':blk['gen']})
            assert response.status_code==401
            host=json.loads((ROOT/'deploy/aws/inventory.json').read_text())[0]
            ctx=ssl.create_default_context(cafile=a.ca)
            try:
                with httpx.Client(verify=ctx,timeout=5) as no_cert:
                    no_cert.get(f"https://{host['private']}:9444/health")
            except httpx.HTTPError:
                pass
            else:raise AssertionError('el canal interno aceptó un cliente sin certificado')
            try:
                httpx.get(f"https://{host['private']}:9443/health",timeout=5)
            except httpx.HTTPError:
                pass
            else:raise AssertionError('se aceptó el certificado sin la CA privada')
            # Comprobación directa de los archivos en disco, sin depender de un mensaje del API.
            probe=(b'H'*64).hex();disk=[]
            for node in (1,2,3):
                name=f"{blk['block_id']}.{blk['gen']}"
                command=("sudo python3 -c "+shlex.quote(
                    "import pathlib,hashlib,json; p=pathlib.Path('/var/lib/docker/volumes/dfsha_dn-data/_data')/"+repr(name)+
                    "; d=p.read_bytes(); print(json.dumps({'size':len(d),'sha256':hashlib.sha256(d).hexdigest(),"
                    "'contains_plaintext':bytes.fromhex("+repr(probe)+") in d}))"))
                info=json.loads(remote(node,command));assert info['sha256']==blk['sha256']
                assert info['size']==bs+28 and not info['contains_plaintext'];disk.append(info)
            return {'authorization':'permitido/denegado','tls':'CA privada requerida',
                    'mtls':'certificado de cliente requerido','encrypted_disk_blocks':disk}
        finally:a.close(h)
    run('Autorización, TLS/mTLS y almacenamiento cifrado','Seguridad',security)

    def control_ha():
        status=json.loads(action('etcd-status',1))
        leader=next(x for x in status if x['Status']['header']['member_id']==x['Status']['leader'])
        ip=leader['Endpoint'].split('//')[1].split(':')[0]
        hosts=json.loads((ROOT/'deploy/aws/inventory.json').read_text())
        leader_n=next(x['n'] for x in hosts if x['private']==ip)
        action('etcd-stop',leader_n)
        try:
            action('control-stop',1)
            try:
                a._i=0
                a.put(small('ha.bin',b'mayoria-confirmada'),'/validacion/ha.bin')
                assert a.read_block('/validacion/ha.bin',0)==b'mayoria-confirmada'
            finally:action('control-start',1)
        finally:action('etcd-start',leader_n)
        wait(lambda:len(json.loads(action('etcd-status',1)))==3,60)
        return {'stopped_etcd_leader_host':leader_n,'stopped_control':1,'read_write':'correctos con mayoría y failover'}
    run('Caída del líder de etcd y de una instancia de control','Replicación y fallos',control_ha)

    report['finished']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    report['passed']=sum(x['ok'] for x in report['tests'])
    report['total']=len(report['tests'])
    report['performance']='Ejecutar tests/bench.py; resultados CSV separados, con dos condiciones de workers/clientes.'
    (result_dir/f'{args.label}-acceptance.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(f"RESUMEN: {report['passed']}/{report['total']} pruebas aprobadas",flush=True)
    return 0 if report['passed']==report['total'] else 1


if __name__=='__main__':
    (ROOT/'.run').mkdir(exist_ok=True)
    raise SystemExit(main())
