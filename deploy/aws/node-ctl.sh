#!/usr/bin/env bash
# Detiene o arranca el nodo de datos N (para simular caídas):  node-ctl.sh stop 2 | start 2 | logs 2
# Úsalo con las pruebas:  STOP_CMD="deploy/aws/node-ctl.sh stop {n}" START_CMD="deploy/aws/node-ctl.sh start {n}" python tests/e2e.py
set -euo pipefail
cd "$(dirname "$0")"; source cluster.env
act="$1"; n="$2"; k=0; ip=""
for x in $DATA_IPS; do k=$((k+1)); [ "$k" = "$n" ] && ip="$x"; done
[ -n "$ip" ] || { echo "no existe dn$n"; exit 1; }
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip" "sudo docker $act dfsha-dn"
