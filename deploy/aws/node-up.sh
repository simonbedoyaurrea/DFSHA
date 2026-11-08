#!/usr/bin/env bash
# Se ejecuta DENTRO de cada VM:   bash deploy/aws/node-up.sh control|data|client <n>
set -euo pipefail
cd "$(dirname "$0")"
source cluster.env
ROLE="$1"; N="$2"
nth() { local k=0; for x in $2; do k=$((k+1)); [ "$k" = "$1" ] && { echo "$x"; return; }; done; }

if ! command -v docker >/dev/null && [ "$ROLE" != client ]; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER" || true
fi

case "$ROLE" in
  control)
    MY_IP="$(nth "$N" "$CONTROL_IPS")"
    CL=""; EP=""; k=0
    for ip in $CONTROL_IPS; do k=$((k+1)); CL+="control$k=https://$ip:2380,"; EP+="https://$ip:2379,"; done
    cat > node.env << EOT
NODE=control$N
MY_IP=$MY_IP
ETCD_CLUSTER=${CL%,}
ETCD_ENDPOINTS=${EP%,}
EOT
    sudo docker compose --env-file node.env -f compose.control.yml up -d --build
    ;;
  data)
    MY_IP="$(nth "$N" "$DATA_IPS")"
    CI=""; for ip in $CONTROL_IPS; do CI+="https://$ip:8444,"; done
    cat > node.env << EOT
NODE=dn$N
MY_IP=$MY_IP
CONTROL_INTERNAL_URLS=${CI%,}
EOT
    sudo mkdir -p /var/lib/dfsha
    sudo docker compose --env-file node.env -f compose.data.yml up -d --build
    ;;
  client)
    sudo apt-get update -y && sudo apt-get install -y python3-venv python3-pip
    cd ../..
    python3 -m venv .venv && . .venv/bin/activate && pip install -q -r requirements.txt
    SEEDS=""; for ip in $CONTROL_IPS; do SEEDS+="\"https://$ip:8443\","; done
    mkdir -p "$HOME/.dfsha"
    cat > "$HOME/.dfsha/config.json" << EOT
{"control": [${SEEDS%,}], "ca": "$PWD/deploy/aws/secrets/certs/ca.crt"}
EOT
    echo "Cliente listo. Usa:  cd $PWD && . .venv/bin/activate && PYTHONPATH=. python -m dfsha.client.cli status"
    ;;
esac
echo "OK: $ROLE $N"
