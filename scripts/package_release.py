#!/usr/bin/env python3
"""Resume evidencias reales y empaqueta código sin claves ni datos de prueba."""
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import statistics
import zipfile

ROOT=Path(__file__).resolve().parents[1]
RESULTS=ROOT/'results'


def main():
    acceptance=json.loads((RESULTS/'aws-acceptance.json').read_text())
    resilience=json.loads((RESULTS/'aws-resilience.json').read_text())
    cli=json.loads((RESULTS/'aws-cli.json').read_text())
    gc=json.loads((RESULTS/'aws-gc-heartbeat.json').read_text())
    infra=json.loads((RESULTS/'aws-infrastructure.json').read_text())
    runtime=json.loads((RESULTS/'aws-runtime-manifest.json').read_text())
    host=json.loads((RESULTS/'aws-host-failure.json').read_text())
    restart_path=RESULTS/'aws-session-restart.json'
    restart=json.loads(restart_path.read_text()) if restart_path.exists() else None
    events=json.loads((RESULTS/'aws-host-events.json').read_text())
    regression=(RESULTS/'aws-regression.log').read_text()
    assert acceptance['passed']==acceptance['total']==9
    assert all(t['ok'] for t in resilience) and len(resilience)==5
    assert cli['ok'] and gc['ok'] and gc['false_dead_states']==0
    assert all(p['ok'] for p in host['phases'])
    assert {e['aws_state'] for e in events}=={'stopped','running'}
    assert '14 passed' in regression
    assert all(v['encrypted'] for v in infra['volumes'])
    assert runtime['cluster_status']['blocks_under_replicated']==0
    for file,digest in runtime['application_files'].items():
        assert hashlib.sha256((ROOT/file).read_bytes()).hexdigest()==digest,file
    rows=list(csv.DictReader((RESULTS/'aws-rendimiento.csv').open()))
    assert {r['workers'] for r in rows if r['experimento']=='size'}=={'1','4'}
    assert {r['clientes'] for r in rows if r['experimento']=='concurrency'}=={'1','2','4'}
    metrics=[]
    for workers in ('1','4'):
        for op in ('put','get'):
            samples=[float(r['segundos']) for r in rows if r['experimento']=='size'
                     and r['MiB']=='64' and r['workers']==workers and r['op']==op]
            assert len(samples)==5
            med=statistics.median(samples)
            metrics.append({'workers':int(workers),'operation':op,'median_seconds':med,
                            'p95_seconds':max(samples),'MiB_per_second':64/med})
    large=acceptance['tests'][0]['detail']
    if restart:
        assert restart['ok'] and restart['sha256']==large['sha256']
    summary={'captured_at':datetime.now(timezone.utc).isoformat(),
             'mandatory_categories':{k:'passed' for k in (
                 'Carga y recuperación','Acceso RF3','Concurrencia','Replicación y fallos',
                 'Consistencia','Seguridad','Rendimiento')},
             'functional_cases':9,'regression_tests':14,'resilience_cases':5,
             'cli_scenario_passed':True,'gc_availability_passed':True,
             'vm_failure_passed':True,'hosts':3,'containers_running':9,
             'full_lab_restart_passed':bool(restart and restart['ok']),
             'application_matches_runtime':True,'under_replicated_blocks':0,
             'large_file':large,'metrics_64_MiB':metrics,
             'code_digest':hashlib.sha256(json.dumps(runtime['application_files'],sort_keys=True).encode()).hexdigest()}
    (RESULTS/'aws-final-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    lines=['# Resultado técnico en AWS', '',
           'La copia está desplegada en tres VM de AWS Academy, con nueve contenedores activos. '
           'La comprobación final encontró los tres nodos vivos, cero bloques con copias insuficientes '
           'y el mismo código de aplicación que está guardado en esta carpeta.', '',
           '## Pruebas del enunciado', '', '| Prueba | Resultado |', '|---|---|',
           '| Carga y recuperación | 1 GiB más 24 bytes, 257 bloques en tres nodos y hash idéntico. |',
           '| RF3 | Apertura, lectura, escritura, cierre, locks y anexado comprobados. |',
           '| Concurrencia | Mismo bloque: un ganador; bloques distintos: ambos cambios conservados. |',
           '| Replicación y fallos | Caída de nodo, interrupción de carga, recuperación y fallo de control/etcd. |',
           '| Consistencia | Réplica atrasada y versión antigua conservada durante reemplazo o borrado. |',
           '| Seguridad | Acceso permitido/denegado, TLS/mTLS, contenido cifrado y EBS cifrado. |',
           '| Rendimiento | Comparación de uno/cuatro workers y tandas con uno/dos/cuatro clientes. |', '',
           f"SHA-256 del archivo grande: `{large['sha256']}`.", '',
           'También pasaron 14 pruebas de regresión, cinco casos de recuperación, el recorrido completo '
           'de la CLI y la limpieza de 200 archivos sin falsas caídas. Se apagó una VM completa y '
           'se comprobó lectura/escritura con las otras dos; al regresar se restauraron las tres copias.', '',
           '## Ejemplo de rendimiento: archivo de 64 MiB', '',
           '| Workers | Operación | Mediana (s) | p95 observado (s) | MiB/s |', '|---|---|---|---|---|']
    for m in metrics:
        lines.append(f"| {m['workers']} | {m['operation']} | {m['median_seconds']:.3f} | {m['p95_seconds']:.3f} | {m['MiB_per_second']:.1f} |")
    lines += ['', 'Cinco repeticiones por combinación de tamaño y workers, con TLS/mTLS y RF=3/W=2. '
              'Las tandas de concurrencia se ejecutaron una vez por cantidad de clientes. '
              'El cliente comparte host1 con otros componentes. Las tasas son MiB/s; el CSV conserva '
              'la etiqueta histórica `MB_por_s`. El p95 de cinco muestras es el máximo observado de esas cinco.', '',
              '## Evidencias y acceso', '',
              '- `aws-acceptance.json` y su log: pruebas funcionales y hashes.',
              '- `aws-resilience.json`: reintentos, directorios concurrentes, anexado paralelo y falta de copias/mayoría.',
              '- `aws-gc-heartbeat.json`: limpieza sin falsas caídas, con observaciones de los heartbeats.',
              '- `aws-cli.json`: comandos reales, incluidos los errores esperados.',
              '- `aws-rendimiento.csv`: mediciones crudas.',
              '- `aws-host-failure.json` y `aws-host-events.json`: caída y regreso de una VM.',
              ('- `aws-session-restart.json`: recuperación idéntica del archivo de 1 GiB tras reiniciar las tres VM al renovar el laboratorio.'
               if restart else '- Recuperación tras reinicio completo: pendiente en esta ejecución.'),
              '- `aws-infrastructure.json`, `aws-runtime-manifest.json` y `aws-ec2-running.png`: infraestructura y estado.',
              '- `README.md` del proyecto: acceso, comandos, contrato de RF3 y reproducción.', '',
              'Los originales permanecen en `dfsha-proyecto.zip` y `implementacion/dfsha-project`, fuera de esta copia. '
              'El informe final, GitHub, video y preparación de la defensa corresponden a la siguiente etapa.']
    (RESULTS/'RESUMEN-AWS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')

    archive=ROOT.parent/'dfsha-entrega-codigo.zip'
    excluded={'.run','.venv','.pytest_cache','__pycache__','.git','secrets','keys','certs'}
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as out:
        for path in sorted(ROOT.rglob('*')):
            if not path.is_file():continue
            rel=path.relative_to(ROOT)
            if any(part in excluded for part in rel.parts):continue
            if path.suffix in ('.pem','.key','.pyc') or path.name=='.DS_Store':continue
            if path.name in ('cluster.env','host.env'):continue
            if path.stat().st_size>10*1024*1024:raise RuntimeError(f'archivo inesperadamente grande: {rel}')
            out.write(path,Path('dfsha-project')/rel)
    with zipfile.ZipFile(archive) as package:
        for name in package.namelist():
            assert not any(part in excluded for part in Path(name).parts)
            payload=package.read(name)
            for kind in (b'PRIVATE KEY', b'OPENSSH PRIVATE KEY', b'RSA PRIVATE KEY'):
                secret = b'-----' + b'BEGIN ' + kind + b'-----'
                assert secret not in payload,name
    print(json.dumps({'summary':str(RESULTS/'RESUMEN-AWS.md'),'archive':str(archive),
                      'archive_bytes':archive.stat().st_size,
                      'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                      'mandatory_categories':7,'secrets_in_archive':False},indent=2))


if __name__=='__main__':main()
