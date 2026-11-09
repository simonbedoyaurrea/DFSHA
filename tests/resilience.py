#!/usr/bin/env python3
"""Casos de recuperación y coordinación complementarios al enunciado."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from dfsha.client.core import Client, DfshaError
from deploy.aws.node import action


def wait(fn,timeout=90):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            if fn():return
        except DfshaError:pass
        time.sleep(2)
    raise AssertionError('no se recuperó el estado esperado')


def main():
    root=Path(tempfile.mkdtemp(prefix='resilience-',dir=ROOT/'.run'))
    a=Client(root/'a');b=Client(root/'b');user='res'+uuid.uuid4().hex[:10];pw='pruebas-dfsha-2026'
    a.register(user,pw);a.login(user,pw);b.login(user,pw)
    results=[]
    def run(name,fn):
        start=time.monotonic()
        try:entry={'name':name,'ok':True,'detail':fn()}
        except Exception as exc:entry={'name':name,'ok':False,'error':f'{type(exc).__name__}: {exc}'}
        entry['seconds']=round(time.monotonic()-start,3);results.append(entry)
        (ROOT/'results/aws-resilience.json').write_text(json.dumps(results,indent=2))
        print(json.dumps(entry,ensure_ascii=False),flush=True)

    def idempotent():
        h=a.open('/reintento.bin','w',create=True)
        try:
            changes=a._upload_blocks(h,h['lock']['lock_id'],[(0,b'operacion-confirmada')])
            body={'lock_id':h['lock']['lock_id'],'fencing_token':h['lock']['fencing_token'],
                  'base_version':h['version'],'changes':changes,'size':20,'replace_all':True,
                  'session_id':h['session_id'],'request_id':uuid.uuid4().hex}
            first=a.req('POST',f"/v1/files/{h['fid']}/commit",json=body)
            repeated=a.req('POST',f"/v1/files/{h['fid']}/commit",json=body)
            assert first==repeated and first['version']==1
        finally:a.close(h)
        after_close=a.req('POST',f"/v1/files/{h['fid']}/commit",json=body)
        assert after_close==first and a.stat('/reintento.bin')['version']==1
        assert a.read_block('/reintento.bin',0)==b'operacion-confirmada'
        h=a.open('/creacion-write.bin','w',create=True)
        try:
            a.write(h,0,b'creado-por-write');assert a.read(h,0)==b'creado-por-write'
        finally:a.close(h)
        return 'mismo request_id conserva versión 1 incluso tras close; creación mediante open/write/close correcta'
    run('Reintento de commit y creación RF3',idempotent)

    def directory_race():
        counts={'mkdir':0,'rmdir':0}
        for i in range(20):
            path=f'/race-{i}';a.mkdir(path);barrier=threading.Barrier(2)
            def work(c,op):
                barrier.wait()
                try:
                    c.mkdir(path+'/hijo') if op=='mkdir' else c.rmdir(path)
                    return True
                except DfshaError as exc:
                    assert exc.code in ('NOT_EMPTY','NOT_FOUND','BUSY'),str(exc)
                    return False
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                one=pool.submit(work,a,'mkdir');two=pool.submit(work,b,'rmdir')
                m,r=one.result(),two.result()
            assert m != r,(m,r)
            counts['mkdir']+=m;counts['rmdir']+=r
            if m:
                assert a.ls(path)['entries'][0]['name']=='hijo'
                a.rmdir(path+'/hijo');a.rmdir(path)
            else:
                try:a.stat(path+'/hijo')
                except DfshaError as exc:assert exc.code=='NOT_FOUND'
                else:raise AssertionError('se creó un hijo sin directorio padre')
        return {'races':20,'winners':counts,'orphans':0}
    run('Crear un hijo frente a borrar su directorio',directory_race)

    def append_and_patch():
        bs=a.status()['config']['block_size']
        original=root/'merge.bin';original.write_bytes(b'A'*bs+b'B'*bs)
        extra=root/'tail.bin';extra.write_bytes(b'cola-agregada')
        a.put(original,'/merge.bin')
        writer=a.open('/merge.bin','w',ranges=[[0,0]])
        try:
            b.append('/merge.bin',extra)
            a.write(writer,0,b'X'*bs)
        finally:a.close(writer)
        out=root/'merged.out';a.get('/merge.bin',out)
        assert out.read_bytes()==b'X'*bs+b'B'*bs+b'cola-agregada'
        return 'escritura sobre bloque 0 y append conservados, incluido el tamaño final'
    run('Anexado concurrente con modificación de otro bloque',append_and_patch)

    def insufficient_copies():
        local=root/'original.bin';local.write_bytes(b'version-original'*1000)
        a.put(local,'/quorum.bin');original=a.read_block('/quorum.bin',0)
        action('stop',2);action('stop',3)
        try:
            wait(lambda:sum(n['state']=='DEAD' for n in a.status()['nodes'])==2,45)
            assert a.read_block('/quorum.bin',0)==original
            local.write_bytes(b'no-debe-publicarse')
            try:a.put(local,'/quorum.bin')
            except DfshaError as exc:assert exc.status==503,str(exc)
            else:raise AssertionError('se confirmó con una sola copia')
            assert a.read_block('/quorum.bin',0)==original
        finally:
            action('start',2);action('start',3)
        wait(lambda:a.status()['blocks_under_replicated']==0,90)
        return 'lectura con una copia; escritura 503; versión anterior conservada; RF=3 restaurado'
    run('Falta de W=2 no publica cambios',insufficient_copies)

    def no_majority():
        handle=a.open('/reintento.bin')
        action('etcd-stop',2);action('etcd-stop',3)
        try:
            try:a.req('POST','/v1/fs/mkdir',json={'path':'/sin-mayoria'},retries=0,timeout=45)
            except DfshaError as exc:assert exc.status==503,str(exc)
            else:raise AssertionError('hubo escritura de metadatos sin mayoría')
            try:a.req('DELETE',f"/v1/sessions/{handle['session_id']}",retries=0,timeout=45)
            except DfshaError as exc:assert exc.status==503,str(exc)
            else:raise AssertionError('se confirmó el cierre sin poder consultar el catálogo')
        finally:
            action('etcd-start',2);action('etcd-start',3)
        wait(lambda:len(a.ls('/')['entries'])>0,90)
        assert a.close(handle)['closed']
        try:a.stat('/sin-mayoria')
        except DfshaError as exc:assert exc.code=='NOT_FOUND'
        else:raise AssertionError('se publicó el directorio sin mayoría')
        return '503 sin mayoría; el cambio rechazado no aparece después de recuperar etcd'
    run('Pérdida de mayoría del catálogo',no_majority)
    print(f"RESUMEN: {sum(r['ok'] for r in results)}/{len(results)} aprobadas")
    return 0 if all(r['ok'] for r in results) else 1


if __name__=='__main__':raise SystemExit(main())
