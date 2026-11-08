#!/usr/bin/env bash
# Copia el proyecto y los secretos mínimos necesarios a cada VM y las arranca.
#   control: certificado propio + CA + TODAS las claves (necesita la clave privada y la KEK)
#   data:    certificado propio + CA + SOLO la clave pública y el token de clúster
#   client:  CA (para validar el servidor)
set -euo pipefail
cd "$(dirname "$0")"
source cluster.env
[ -d secrets ] || { echo "Primero ejecuta ./make-secrets.sh"; exit 1; }
ROOT="$(cd ../.. && pwd)"
SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10)
SCP=(scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -q)

deploy_node() { # rol n ip
  local role="$1" n="$2" ip="$3" name
  case "$role" in control) name="control$n";; data) name="dn$n";; client) name="client$n";; esac
  echo "=== $role $n ($ip) ==="
  rsync -az --delete -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=no" \
    --exclude .venv --exclude .run --exclude certs --exclude keys --exclude results --exclude .git \
    --exclude 'deploy/aws/secrets' "$ROOT/" "$SSH_USER@$ip:$REPO_DIR/"
  "${SSH[@]}" "$SSH_USER@$ip" "mkdir -p $REPO_DIR/deploy/aws/secrets/certs $REPO_DIR/deploy/aws/secrets/keys"
  "${SCP[@]}" secrets/certs/ca.crt "$SSH_USER@$ip:$REPO_DIR/deploy/aws/secrets/certs/"
  case "$role" in
    control) "${SCP[@]}" secrets/certs/$name.crt secrets/certs/$name.key "$SSH_USER@$ip:$REPO_DIR/deploy/aws/secrets/certs/"
             "${SCP[@]}" secrets/keys/* "$SSH_USER@$ip:$REPO_DIR/deploy/aws/secrets/keys/";;
    data)    "${SCP[@]}" secrets/certs/$name.crt secrets/certs/$name.key "$SSH_USER@$ip:$REPO_DIR/deploy/aws/secrets/certs/"
             "${SCP[@]}" secrets/keys/control_ed25519.pub secrets/keys/cluster_token "$SSH_USER@$ip:$REPO_DIR/deploy/aws/secrets/keys/";;
  esac
  "${SCP[@]}" cluster.env "$SSH_USER@$ip:$REPO_DIR/deploy/aws/cluster.env"
  "${SSH[@]}" "$SSH_USER@$ip" "bash $REPO_DIR/deploy/aws/node-up.sh $role $n"
}

i=0; for ip in $CONTROL_IPS; do i=$((i+1)); deploy_node control $i "$ip"; done
i=0; for ip in $DATA_IPS;    do i=$((i+1)); deploy_node data    $i "$ip"; done
i=0; for ip in $CLIENT_IPS;  do i=$((i+1)); deploy_node client  $i "$ip"; done
echo "Listo. Entra a la VM cliente por SSH y prueba:  dfsha status (ver README, sección AWS)"
