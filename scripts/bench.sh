#!/usr/bin/env bash
# scripts/bench.sh — HTTP/3 baseline benchmark for the proxy.
#
# Usage: scripts/bench.sh [CONNS REQUESTS REQSPERCONN]
# Assumes: backend on 127.0.0.1:3000, proxy on UDP 8443, stats on 9100.
# Backend should be started separately (e.g. python3 -m http.server 3000).
set -euo pipefail
ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
CONNS="${1:-10}"; REQS="${2:-2000}"; PERCONN="${3:-}"   # PERCONN default: spread across conns
W="${4:-1}"                                             # concurrent reqs per conn (-w)
[ -n "$PERCONN" ] || PERCONN=$(( (REQS + CONNS - 1) / CONNS ))
HC="$ROOT/third_party/lsquic/build/bin/http_client"

start=$(date +%s)
"$HC" -s 127.0.0.1:8443 -H localhost -p / -n "$CONNS" -r "$REQS" \
      -R "$PERCONN" -w "$W" -4 -K -t 2>&1 | tail -3
end=$(date +%s)
echo "--- proxy counters after run ---"
curl -sS -m 3 http://127.0.0.1:9100/ | grep -E "requests_total|responses|latency"
echo "--- wall: $((end-start))s for $REQS requests over $CONNS conns ---"
