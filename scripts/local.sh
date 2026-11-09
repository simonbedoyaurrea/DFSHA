#!/usr/bin/env bash
# Clúster local SIN Docker: 1 etcd + 2 servicios de control + 4 nodos de datos.
#   scripts/local.sh up            # arranca todo (TLS=1 para TLS/mTLS)
#   scripts/local.sh down          # detiene todo
#   scripts/local.sh dn-stop 2     # detiene el nodo dn2   (simular caída)
#   scripts/local.sh dn-start 2    # lo vuelve a arrancar
#   scripts/local.sh env           # imprime variables para usar el CLI
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"; RUN="$ROOT/.run"
PY="${PY:-$ROOT/.venv/bin/python}"
ETCD="${ETCD:-$RUN/bin/etcd}"; [ -x "$ETCD" ] || ETCD="$(command -v etcd || true)"
TLS="${TLS:-$(cat "$RUN/mode" 2>/dev/null || echo 0)}"   # recuerda el modo con que se hizo "up"
ETCD3="${ETCD3:-$(cat "$RUN/etcd3" 2>/dev/null || echo 0)}"   # ETCD3=1: clúster etcd de 3 nodos (127.0.0.1/2/3)
SCHEME=http; [ "$TLS" = "1" ] && SCHEME=https
mkdir -p "$RUN/logs" "$RUN/pids" "$RUN/data"

# parámetros rápidos para pruebas (en producción se usan los valores por defecto del diseño)
export BLOCK_SIZE="${BLOCK_SIZE:-1048576}" LOCK_TTL="${LOCK_TTL:-8}" SUSPECT_AFTER="${SUSPECT_AFTER:-5}" \
       DEAD_AFTER="${DEAD_AFTER:-12}" GC_GRACE="${GC_GRACE:-20}" MONITOR_INTERVAL="${MONITOR_INTERVAL:-2}" \
       HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-2}" BLOCKREPORT_INTERVAL="${BLOCKREPORT_INTERVAL:-8}" \
       SCRUB_INTERVAL="${SCRUB_INTERVAL:-300}" INFLIGHT_TTL="${INFLIGHT_TTL:-20}"
export TLS PYTHONPATH="$ROOT"
if [ "$TLS" = "1" ]; then
  export CA_FILE="$ROOT/certs/ca.crt"
fi
export PRIVATE_KEY="$ROOT/keys/control_ed25519.pem" PUBLIC_KEY="$ROOT/keys/control_ed25519.pub" \
       KEK_FILE="$ROOT/keys/kek.b64" CLUSTER_TOKEN_FILE="$ROOT/keys/cluster_token"

start_bg() { # nombre comando...
  local name="$1"; shift
  if command -v setsid >/dev/null; then
    setsid nohup "$@" > "$RUN/logs/$name.log" 2>&1 < /dev/null &
  else
    nohup "$@" > "$RUN/logs/$name.log" 2>&1 < /dev/null &
  fi
  echo $! > "$RUN/pids/$name.pid"
}
stop_bg() { local f="$RUN/pids/$1.pid"; [ -f "$f" ] && { kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; }; }
alive() { [ -f "$RUN/pids/$1.pid" ] && kill -0 "$(cat "$RUN/pids/$1.pid")" 2>/dev/null; }

etcd_endpoints() {
  if [ "$ETCD3" = "1" ]; then echo "$SCHEME://127.0.0.1:2379,$SCHEME://127.0.0.2:2379,$SCHEME://127.0.0.3:2379"
  else echo "$SCHEME://127.0.0.1:2379"; fi
}

start_etcd() { # n  (en modo ETCD3 cada nodo usa su propia IP de loopback, como en AWS cada VM tiene la suya)
  local n="$1" ip="127.0.0.$1"
  if [ "$ETCD3" = "1" ]; then
    local cl="etcd1=$SCHEME://127.0.0.1:2380,etcd2=$SCHEME://127.0.0.2:2380,etcd3=$SCHEME://127.0.0.3:2380"
    local a=(--name="etcd$n" --data-dir="$RUN/etcd$n" --listen-client-urls="$SCHEME://$ip:2379" --advertise-client-urls="$SCHEME://$ip:2379" \
      --listen-peer-urls="$SCHEME://$ip:2380" --initial-advertise-peer-urls="$SCHEME://$ip:2380" --initial-cluster="$cl" \
      --initial-cluster-token=dfsha --initial-cluster-state=new)
    [ "$TLS" = "1" ] && a+=(--cert-file="certs/etcd$n.crt" --key-file="certs/etcd$n.key" --trusted-ca-file=certs/ca.crt --client-cert-auth \
      --peer-cert-file="certs/etcd$n.crt" --peer-key-file="certs/etcd$n.key" --peer-trusted-ca-file=certs/ca.crt --peer-client-cert-auth)
  else
    local a=(--data-dir "$RUN/etcd" --listen-client-urls "$SCHEME://127.0.0.1:2379" --advertise-client-urls "$SCHEME://127.0.0.1:2379")
    [ "$TLS" = "1" ] && a+=(--cert-file certs/etcd.crt --key-file certs/etcd.key --trusted-ca-file certs/ca.crt --client-cert-auth)
  fi
  start_bg "etcd$n" "$ETCD" "${a[@]}"
}

start_dn() {
  local n="$1"
  local env=(NODE_ID="dn$n" PORT=$((9000+n)) INTERNAL_PORT=$((9100+n)) \
    PUBLIC_URL="$SCHEME://127.0.0.1:$((9000+n))" INTERNAL_URL="$SCHEME://127.0.0.1:$((9100+n))" \
    CONTROL_INTERNAL_URLS="$SCHEME://127.0.0.1:8100,$SCHEME://127.0.0.1:8101" DATA_DIR="$RUN/data/dn$n")
  [ "$TLS" = "1" ] && env+=(CERT_FILE="$ROOT/certs/dn$n.crt" KEY_FILE="$ROOT/certs/dn$n.key")
  start_bg "dn$n" env "${env[@]}" "$PY" -m dfsha.datanode.main
}

start_control() {
  local n="$1"
  local env=(CONTROL_ID="control$n" PORT=$((8000+n-1)) INTERNAL_PORT=$((8100+n-1)) \
    ETCD_ENDPOINTS="$(etcd_endpoints)")
  if [ "$TLS" = "1" ]; then
    env+=(CERT_FILE="$ROOT/certs/control.crt" KEY_FILE="$ROOT/certs/control.key" \
          ETCD_CA="$ROOT/certs/ca.crt" ETCD_CERT="$ROOT/certs/control.crt" ETCD_KEY="$ROOT/certs/control.key")
  fi
  start_bg "control$n" env "${env[@]}" "$PY" -m dfsha.control.main
}

case "${1:-up}" in
  up)
    "$0" down >/dev/null 2>&1
    echo "$TLS" > "$RUN/mode"; echo "$ETCD3" > "$RUN/etcd3"
    rm -rf "$RUN"/etcd* "$RUN/data"; mkdir -p "$RUN/data"
    "$PY" deploy/gen-keys.py keys >/dev/null
    if [ "$TLS" = "1" ]; then
      rm -rf certs
      deploy/gen-certs.sh certs etcd:localhost etcd1:127.0.0.1 etcd2:127.0.0.2 etcd3:127.0.0.3 control:localhost \
        dn1:localhost dn2:localhost dn3:localhost dn4:localhost client:localhost >/dev/null
    fi
    if [ "$ETCD3" = "1" ]; then for n in 1 2 3; do start_etcd "$n"; done; else start_etcd 1; fi
    for i in $(seq 1 60); do
      if [ "$TLS" = "1" ]; then
        curl -fs --cacert certs/ca.crt --cert certs/control.crt --key certs/control.key "$SCHEME://127.0.0.1:2379/health" 2>/dev/null | grep -q '"health":"true"' && break
      else curl -fs "$SCHEME://127.0.0.1:2379/health" 2>/dev/null | grep -q '"health":"true"' && break; fi
      sleep 0.5
    done
    start_control 1; start_control 2
    for n in 1 2 3 4; do start_dn "$n"; done
    sleep 4
    echo "Clúster local arriba (TLS=$TLS). Logs en $RUN/logs/"
    "$0" env
    ;;
  down)
    for f in "$RUN"/pids/*.pid; do [ -f "$f" ] && { kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; }; done
    ;;
  etcd-stop)  stop_bg "etcd$2"; echo "etcd$2 detenido";;
  etcd-start) start_etcd "$2"; echo "etcd$2 iniciado";;
  dn-stop)  stop_bg "dn$2"; echo "dn$2 detenido";;
  dn-start) start_dn "$2"; echo "dn$2 iniciado";;
  env)
    printf 'export DFSHA_CONTROL=%q\n' "$SCHEME://127.0.0.1:8000,$SCHEME://127.0.0.1:8001"
    if [ "$TLS" = "1" ]; then printf 'export DFSHA_CA=%q\n' "$ROOT/certs/ca.crt"; fi
    ;;
esac
