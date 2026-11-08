#!/usr/bin/env bash
# En host1: source deploy/aws/client-env.sh
DFSHA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$DFSHA_ROOT"
export DFSHA_CA="$DFSHA_ROOT/deploy/aws/secrets/certs/ca.crt"
export DFSHA_CONTROL="$(python3 -c 'import json,sys; print(",".join("https://"+h["private"]+":8443" for h in json.load(open(sys.argv[1]))))' "$DFSHA_ROOT/deploy/aws/inventory.json")"
