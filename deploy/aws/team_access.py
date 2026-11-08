#!/usr/bin/env python3
"""Acceso SSH personal para tres integrantes, sin permisos de administración.

Genera claves locales privadas excluidas de Git. Instala únicamente el cliente
y el certificado público de la CA en host1. No modifica contenedores ni archivos DFSha.
"""
import argparse
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import zipfile

import paramiko

from deploy_cluster import ROOT, connect, run


def package_access():
    """Un paquete por integrante; nunca incluye las claves de los otros dos."""
    host = json.loads((ROOT/'deploy/aws/inventory.json').read_text())[0]
    folder = ROOT/'deploy/aws/secrets/equipo'
    for name in ('sebastian', 'simon', 'santiago'):
        user = 'dfsha-'+name
        key = folder/(user+'.pem')
        instruction = (f'Acceso personal de {name}\n\n'
            f'chmod 600 {key.name}\nssh -i {key.name} {user}@{host["public"]}\n\n'
            f'Dentro de AWS, registra tu usuario DFSha una sola vez:\ndfsha register {name}\n'
            f'dfsha login {name}\ndfsha status\n\n'
            'La contraseña DFSha la eliges al registrarte; es distinta de la clave SSH.\n'
            'Para ver los mismos archivos que otro integrante, ambos deben usar la misma cuenta DFSha.\n'
            'La IP pública de tu red debe estar autorizada para SSH/TCP 22.\n'
            'Consulta tu IPv4 en https://checkip.amazonaws.com y envíala al administrador.\n'
            'La dirección pública del servidor puede cambiar tras reiniciar AWS Academy.\n')
        bundle = folder/('acceso-'+name+'.zip')
        with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(key, key.name)
            archive.writestr('LEEME.txt', instruction)
        bundle.chmod(0o600)
        print('Paquete personal: '+str(bundle.relative_to(ROOT)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssh-key', type=Path, required=True)
    args = parser.parse_args()
    host = json.loads((ROOT/'deploy/aws/inventory.json').read_text())[0]
    folder = ROOT/'deploy/aws/secrets/equipo'; folder.mkdir(exist_ok=True, mode=0o700)
    names = ('sebastian', 'simon', 'santiago')
    # Solo se distribuye código del cliente; nunca claves de firma, KEK ni token interno.
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        tar.add(ROOT/'dfsha/__init__.py', arcname='dfsha/__init__.py')
        for p in (ROOT/'dfsha/client').glob('*.py'):
            tar.add(p, arcname='dfsha/client/'+p.name)
        tar.add(ROOT/'requirements.txt', arcname='requirements.txt')
    client = connect(host, args.ssh_key)
    entries = []
    try:
        sftp = client.open_sftp()
        with sftp.file('/tmp/dfsha-client-code.tar.gz', 'wb') as out:
            out.write(archive.getvalue())
        run(client, 'sudo mkdir -p /opt/dfsha-client /etc/dfsha && '
            'sudo tar xzf /tmp/dfsha-client-code.tar.gz -C /opt/dfsha-client && '
            'sudo python3 -m venv /opt/dfsha-client/.venv && '
            'sudo /opt/dfsha-client/.venv/bin/pip install -q -r /opt/dfsha-client/requirements.txt && '
            'sudo install -m 644 /home/ubuntu/dfsha-copia/deploy/aws/secrets/certs/ca.crt /etc/dfsha/ca.crt')
        config = {'control': [f"https://{h['private']}:8443" for h in json.loads((ROOT/'deploy/aws/inventory.json').read_text())],
                  'ca': '/etc/dfsha/ca.crt'}
        command = '#!/bin/sh\nexport PYTHONPATH=/opt/dfsha-client\nexec /opt/dfsha-client/.venv/bin/python -m dfsha.client.cli "$@"\n'
        with sftp.file('/tmp/dfsha-client-command', 'w') as out:
            out.write(command)
        run(client, 'sudo install -m 755 /tmp/dfsha-client-command /usr/local/bin/dfsha')
        for name in names:
            user = 'dfsha-'+name
            key = folder/(user+'.pem')
            if not key.exists():
                subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', user, '-f', str(key)],
                               check=True, capture_output=True)
            key.chmod(0o600)
            public = Path(str(key)+'.pub').read_text().strip()
            run(client, f'id -u {user} >/dev/null 2>&1 || sudo useradd -m -s /bin/bash {user}')
            home = '/home/'+user
            run(client, f'sudo install -d -m 700 -o {user} -g {user} {home}/.ssh {home}/.dfsha')
            for filename, value, mode in (
                ('authorized_keys', public+'\n', '600'),
                ('config.json', json.dumps(config)+'\n', '600')):
                temporary = '/tmp/'+user+'-'+filename
                with sftp.file(temporary, 'w') as out:
                    out.write(value)
                target = home+('/.ssh/' if filename=='authorized_keys' else '/.dfsha/')+filename
                run(client, f'sudo install -m {mode} -o {user} -g {user} {temporary} {target} && rm -f {temporary}')
            # Prueba real de autenticación SSH con la clave individual y el cliente instalado.
            test = paramiko.SSHClient()
            test.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                test.connect(host['public'], username=user, key_filename=str(key), timeout=15)
                assert run(test, 'whoami').strip() == user
                run(test, 'dfsha --help >/dev/null && dfsha whoami')
            finally:
                test.close()
            assert 'sudo' not in run(client, f'id -nG {user}').split()
            entries.append({'name': name, 'ssh_user': user, 'host': host['public'],
                            'private_key': str(key.relative_to(ROOT)), 'sudo': False, 'isolated_session': True})
        sftp.close()
    finally:
        client.close()
    report = {'host': host['public'], 'access': entries,
              'network': 'SSH requiere que el grupo de seguridad autorice la IP pública de cada integrante.'}
    (ROOT/'results/verificacion-acceso-equipo.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    package_access()


if __name__ == '__main__':
    main()
