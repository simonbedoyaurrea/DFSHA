#!/usr/bin/env python3
"""Despliega la copia en tres VM existentes usando IP privadas entre servicios.

python deploy/aws/deploy_cluster.py --inventory inventario.json --ssh-key llave.pem
El inventario contiene [{"n":1,"private":"...","public":"..."}, ...].
Las credenciales AWS no se copian a las VM ni al repositorio.
"""
import argparse
import concurrent.futures
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import time

import paramiko

ROOT = Path(__file__).resolve().parents[2]
REMOTE = '/home/ubuntu/dfsha-copia'


def connect(host, key):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host['public'], username='ubuntu', key_filename=str(key),
                   timeout=15, auth_timeout=15, banner_timeout=20)
    return client


def run(client, command, timeout=900):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdin.close()
    channel = stdout.channel
    output, error = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    # Docker y pip pueden escribir mucho en stderr. Drenar ambos canales evita
    # bloquear la lectura de stdout cuando se llena la ventana SSH del otro canal.
    while True:
        if channel.recv_ready():
            output.extend(channel.recv(65536))
        if channel.recv_stderr_ready():
            error.extend(channel.recv_stderr(65536))
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if time.monotonic() > deadline:
            channel.close()
            raise TimeoutError(f'Tiempo agotado al ejecutar: {command}')
        time.sleep(0.01)
    status = channel.recv_exit_status()
    output, error = output.decode(errors='replace'), error.decode(errors='replace')
    if status:
        raise RuntimeError(f'Comando falló ({status}): {command}\n{output[-3000:]}\n{error[-3000:]}')
    return output


def deploy(inventory, key):
    if (len(inventory) != 3 or len({h['private'] for h in inventory}) != 3
            or {h['n'] for h in inventory} != {1, 2, 3}):
        raise ValueError('se requieren tres hosts diferentes')
    if not key.is_file():
        raise ValueError(f'No existe la clave SSH: {key}')
    secrets = ROOT / 'deploy/aws/secrets'
    secrets.mkdir(exist_ok=True)
    subprocess.run([os.sys.executable, str(ROOT/'deploy/gen-keys.py'), str(secrets/'keys')],check=True)
    subprocess.run(['bash', str(ROOT/'deploy/gen-certs.sh'), str(secrets/'certs'),
                    *[f"host{h['n']}:{h['private']}" for h in inventory]],check=True)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        def include(info):
            parts = Path(info.name).parts
            if any(p in ('.run','.venv','__pycache__','.pytest_cache','.git','secrets','certs','keys') for p in parts):
                return None
            return info
        tar.add(ROOT, arcname='.', filter=include)
    payload = archive.getvalue()
    cluster = ','.join(f"host{h['n']}=https://{h['private']}:2380" for h in inventory)
    endpoints = ','.join(f"https://{h['private']}:2379" for h in inventory)
    controls = ','.join(f"https://{h['private']}:8444" for h in inventory)

    def host_setup(h):
        client = connect(h,key)
        try:
            run(client,'sudo cloud-init status --wait',timeout=900)
            # Una copia recién descargada no debe cambiar las claves de un
            # clúster anterior que ya tiene sus volúmenes y archivos cifrados.
            sftp = client.open_sftp()
            try:
                previous = sftp.file(f'{REMOTE}/deploy/aws/secrets/keys/control_ed25519.pub').read()
            except FileNotFoundError:
                previous = None
            finally:
                sftp.close()
            if previous and previous != (secrets/'keys/control_ed25519.pub').read_bytes():
                raise RuntimeError('El host ya usa otras claves. Recupera los secretos originales antes de actualizarlo.')
            run(client,f'mkdir -p {REMOTE}/deploy/aws/secrets/certs {REMOTE}/deploy/aws/secrets/keys')
            sftp=client.open_sftp()
            with sftp.file('/home/ubuntu/dfsha-code.tar.gz','wb') as out:
                out.write(payload)
            run(client,f'tar xzf /home/ubuntu/dfsha-code.tar.gz -C {REMOTE}')
            for folder,names in [('certs',['ca.crt',f"host{h['n']}.crt",f"host{h['n']}.key"]),
                                 ('keys',['control_ed25519.pem','control_ed25519.pub','kek.b64','cluster_token'])]:
                for name in names:
                    target=f'{REMOTE}/deploy/aws/secrets/{folder}/{name}'
                    sftp.put(str(secrets/folder/name),target)
                    sftp.chmod(target,0o600)
            config=f"N={h['n']}\nMY_IP={h['private']}\nETCD_CLUSTER={cluster}\nETCD_ENDPOINTS={endpoints}\nCONTROL_INTERNAL_URLS={controls}\n"
            with sftp.file(f'{REMOTE}/deploy/aws/host.env','w') as out:out.write(config)
            sftp.close()
            command=f'cd {REMOTE}/deploy/aws && sudo docker compose -p dfsha --env-file host.env -f compose.host.yml up -d --build'
            print(f"Iniciando host{h['n']} ({h['private']})",flush=True)
            run(client,command,timeout=1200)
            return {'host':h['n'],'status':'deployed'}
        finally:
            client.close()

    with concurrent.futures.ThreadPoolExecutor(3) as pool:
        for result in pool.map(host_setup,inventory):print(json.dumps(result),flush=True)
    # El cliente de pruebas vive en host1 y accede a los servicios por las IP privadas.
    h=inventory[0];client=connect(h,key)
    try:
        run(client,f'cd {REMOTE} && python3 -m venv .venv && .venv/bin/pip install -q -r requirements-dev.txt')
        run(client,'mkdir -p /home/ubuntu/.dfsha /home/ubuntu/.ssh && chmod 700 /home/ubuntu/.dfsha /home/ubuntu/.ssh')
        sftp=client.open_sftp()
        config={'control':[f"https://{x['private']}:8443" for x in inventory],
                'ca':f'{REMOTE}/deploy/aws/secrets/certs/ca.crt'}
        with sftp.file('/home/ubuntu/.dfsha/config.json','w') as out:out.write(json.dumps(config))
        client_env = ('# Cargar con source desde Bash. Generado por deploy_cluster.py.\n'
            f'export PYTHONPATH={shlex.quote(REMOTE)}\n'
            f'export DFSHA_CONTROL={shlex.quote(",".join(config["control"]))}\n'
            f'export DFSHA_CA={shlex.quote(config["ca"])}\n')
        with sftp.file(f'{REMOTE}/deploy/aws/client-env.sh','w') as out:out.write(client_env)
        with sftp.file(f'{REMOTE}/deploy/aws/inventory.json','w') as out:out.write(json.dumps(inventory,indent=2))
        sftp.put(str(key),'/home/ubuntu/.ssh/dfsha-entrega.pem')
        sftp.chmod('/home/ubuntu/.ssh/dfsha-entrega.pem',0o600)
        sftp.close()
        print(run(client,f'cd {REMOTE} && PYTHONPATH=. .venv/bin/python -m dfsha.client.cli --help'))
    finally:client.close()


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--inventory',required=True);ap.add_argument('--ssh-key',required=True)
    args=ap.parse_args()
    deploy(sorted(json.loads(Path(args.inventory).read_text()),key=lambda x:x['n']),Path(args.ssh_key))
