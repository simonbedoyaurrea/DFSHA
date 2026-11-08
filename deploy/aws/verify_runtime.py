#!/usr/bin/env python3
"""Contrasta el código local con el cliente y los nueve contenedores existentes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shlex
import time

from deploy_cluster import ROOT, connect, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssh-key', type=Path, required=True)
    parser.add_argument('--label', default='verificacion-runtime')
    args = parser.parse_args()
    inventory = json.loads((ROOT/'deploy/aws/inventory.json').read_text())
    def digest(folder):
        h = hashlib.sha256()
        for path in sorted(folder.rglob('*.py')):
            h.update(str(path.relative_to(folder)).encode()+b'\0'+path.read_bytes())
        return h.hexdigest()
    expected = digest(ROOT/'dfsha')
    remote_digest = ("from pathlib import Path; import hashlib; r=Path('dfsha'); h=hashlib.sha256(); "
        "[(h.update(str(p.relative_to(r)).encode()+b'\\0'+p.read_bytes())) for p in sorted(r.rglob('*.py'))]; print(h.hexdigest())")
    def inspect(host):
        c = connect(host, args.ssh_key)
        try:
            containers = json.loads('['+','.join(run(c, "sudo docker ps --format '{{json .}}'").splitlines())+']')
            records = []
            for name in ('dfsha-control', 'dfsha-dn'):
                value = run(c, f'sudo docker exec {name} python -c '+shlex.quote(remote_digest)).strip()
                assert value == expected, (host['n'], name, value, expected)
                records.append({'container': name, 'application_sha256': value, 'matches_local': True})
            client_digest = run(c, 'cd /home/ubuntu/dfsha-copia && python3 -c '+shlex.quote(remote_digest)).strip()
            assert client_digest == expected
            return {'host': host, 'containers': [{'name':x['Names'], 'status':x['Status'], 'image':x['Image']} for x in containers],
                    'application': records, 'client_matches_local': True}
        finally:
            c.close()
    with ThreadPoolExecutor(3) as pool:
        hosts = list(pool.map(inspect, inventory))
    report = {'captured_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'application_sha256': expected, 'hosts': hosts}
    (ROOT/'results'/f'{args.label}.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
