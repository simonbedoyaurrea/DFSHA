#!/usr/bin/env bash
# Genera (una sola vez) la CA, un certificado por VM (con su IP privada) y las claves del clúster.
set -euo pipefail
cd "$(dirname "$0")"
[ -f cluster.env ] || { echo "Primero: cp cluster.env.example cluster.env y edítalo"; exit 1; }
source cluster.env
ROOT="$(cd ../.. && pwd)"
PY="$(command -v python3)"
rm -rf secrets; mkdir -p secrets/keys
SPECS=(); i=0
for ip in $CONTROL_IPS; do i=$((i+1)); SPECS+=("control$i:$ip"); done
i=0; for ip in $DATA_IPS; do i=$((i+1)); SPECS+=("dn$i:$ip"); done
i=0; for ip in $CLIENT_IPS; do i=$((i+1)); SPECS+=("client$i:$ip"); done
"$ROOT/deploy/gen-certs.sh" secrets/certs "${SPECS[@]}"
if "$PY" -c "import cryptography" 2>/dev/null; then
  "$PY" "$ROOT/deploy/gen-keys.py" secrets/keys
else
  echo "Instala 'cryptography' (pip install cryptography) para generar las claves"; exit 1
fi
echo "Secretos listos en deploy/aws/secrets (NO los subas a GitHub)"
