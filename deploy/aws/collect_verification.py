#!/usr/bin/env python3
"""Descarga solo evidencias de la comprobación actual, sin claves ni sesiones."""
import argparse
import json
from pathlib import Path

from deploy_cluster import ROOT, REMOTE, connect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssh-key', type=Path, required=True)
    args = parser.parse_args()
    host = json.loads((ROOT/'deploy/aws/inventory.json').read_text())[0]
    client = connect(host, args.ssh_key)
    try:
        sftp = client.open_sftp()
        for name in sftp.listdir(REMOTE+'/results'):
            if name.startswith('verificacion-') and name.endswith(('.json', '.csv', '.log')):
                sftp.get(REMOTE+'/results/'+name, str(ROOT/'results'/name))
                print('Evidencia: '+name)
        sftp.close()
    finally:
        client.close()


if __name__ == '__main__':
    main()
