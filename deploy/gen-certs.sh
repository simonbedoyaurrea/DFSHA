#!/usr/bin/env bash
# Uso: deploy/gen-certs.sh <carpeta_salida> <nombre1:IP1|DNS1,...> ...
# Crea una CA interna y un certificado por nombre. Cada certificado sirve como servidor y como cliente (mTLS).
# Ejemplo: deploy/gen-certs.sh certs control1:10.0.1.11 dn1:10.0.2.21 client:localhost
set -euo pipefail
OUT="$1"; shift
mkdir -p "$OUT"; cd "$OUT"
if [ ! -f ca.crt ]; then
  openssl genrsa -out ca.key 4096 2>/dev/null
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -subj "/CN=DFSha internal CA" -out ca.crt
fi
for spec in "$@"; do
  name="${spec%%:*}"; hosts="${spec#*:}"
  san="DNS:localhost,IP:127.0.0.1,DNS:${name}"
  IFS=',' read -ra HS <<< "$hosts"
  for h in "${HS[@]}"; do
    if [[ "$h" =~ ^[0-9.]+$ ]]; then san="$san,IP:$h"; else san="$san,DNS:$h"; fi
  done
  openssl genrsa -out "$name.key" 2048 2>/dev/null
  openssl req -new -key "$name.key" -subj "/CN=$name" -out "$name.csr"
  printf "subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n" "$san" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$name.crt" -days 365 -sha256 -extfile "$name.ext" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
  chmod 600 "$name.key"
  echo "certificado emitido: $name ($san)"
done
