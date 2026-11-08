#!/usr/bin/env python3
"""Comprueba el mismo archivo DFSha mediante las tres claves SSH personales."""
import json
from pathlib import Path
import uuid

import paramiko

ROOT = Path(__file__).resolve().parents[2]


def main():
    host = json.loads((ROOT/'deploy/aws/inventory.json').read_text())[0]
    user = 'equipo' + uuid.uuid4().hex[:12]
    password = uuid.uuid4().hex
    results = []
    for index, name in enumerate(('sebastian', 'simon', 'santiago')):
        ssh_user = 'dfsha-' + name
        key = ROOT/'deploy/aws/secrets/equipo'/(ssh_user+'.pem')
        script = ("import sys,tempfile,json\nfrom pathlib import Path\n"
                  "sys.path.insert(0,'/opt/dfsha-client')\nfrom dfsha.client.core import Client\n"
                  f"c=Client(); user={user!r}; pw={password!r}\n")
        if index == 0:
            script += "c.register(user,pw)\n"
        script += "c.login(user,pw)\n"
        if index == 0:
            script += ("with tempfile.TemporaryDirectory() as d:\n"
                       " p=Path(d)/'prueba.txt'; p.write_bytes(b'acceso-compartido-de-tres-clientes')\n"
                       " c.put(p,'/prueba-equipo.txt')\n")
        script += ("assert c.read_block('/prueba-equipo.txt',0)==b'acceso-compartido-de-tres-clientes'\n"
                   "print(json.dumps({'file_visible':True,'content_verified':True}))\n")
        if index == 2:
            script += "c.rm('/prueba-equipo.txt')\n"
        script += "c.logout()\n"
        client = paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host['public'], username=ssh_user, key_filename=str(key), timeout=15)
            stdin, stdout, stderr = client.exec_command('/opt/dfsha-client/.venv/bin/python -', timeout=90)
            stdin.write(script); stdin.flush(); stdin.channel.shutdown_write()
            output = stdout.read().decode(); error = stderr.read().decode()
            assert stdout.channel.recv_exit_status() == 0, error
            result = json.loads(output)
            results.append({'ssh_user': ssh_user, **result})
        finally:
            client.close()
    report = {'host': host['public'], 'same_dfs_account':True, 'personal_ssh_keys':True,
              'all_passed':len(results)==3, 'clients':results, 'test_file_deleted':True,
              'sessions_logged_out':True,
              'external_networks':'Pendiente autorizar las IP públicas de los compañeros.'}
    (ROOT/'results/verificacion-equipo-end-to-end.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
