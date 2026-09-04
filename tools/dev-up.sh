#!/usr/bin/env bash
# Bring up a local lab: lab CA + receiver API on the LAN, so a phone or a
# second machine can talk to it (no Docker). Ctrl+C to stop.
#
#   tools/dev-up.sh [port]
#
# Then in the Android app -> Login -> Server URL:  http://<this-machine-IP>:<port>
# (the debug APK allows plain HTTP; the release APK is HTTPS-only.)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PORT="${1:-8099}"
DEVDIR="$ROOT/dist/dev"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; *) EXE="" ;; esac
mkdir -p "$DEVDIR"

echo ">> build"
( cd tools/ca-admin && go build -o "$DEVDIR/ca-admin$EXE" . )
( cd server && go build -o "$DEVDIR/pqc-api$EXE" ./cmd/api )
( cd apps/windows && go build -o "$DEVDIR/pqcsign-cli$EXE" ./cmd/pqcsign-cli )

if [ ! -f "$DEVDIR/ca/public/root-ca.crt.pem" ]; then
  echo ">> lab CA (dist/dev/ca)"
  "$DEVDIR/ca-admin$EXE" init --dir "$DEVDIR/ca" >/dev/null
fi

# best-effort LAN IP
IP="$(
  {
    command -v powershell >/dev/null 2>&1 && powershell -NoProfile -Command \
      "(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { \$_.IPAddress -notmatch '^(127|169\.254)\.' } | Select-Object -First 1 -ExpandProperty IPAddress)" 2>/dev/null
  } ||
  { hostname -I 2>/dev/null | tr ' ' '\n' | grep -Ev '^(127|169\.254)\.' | head -1; } ||
  echo "127.0.0.1"
)"
IP="$(echo "$IP" | tr -d '\r' | head -1)"
[ -n "$IP" ] || IP="127.0.0.1"

cat <<EOF

  ┌─────────────────────────────────────────────────────────────
  │  Receiver API listening on 0.0.0.0:$PORT  (in-memory store)
  │
  │  Phone / other machine on the same Wi-Fi:
  │    Server URL   ->  http://$IP:$PORT
  │
  │  Public verifier :  http://$IP:$PORT/api/v1/verify
  │  Root CA         :  $DEVDIR/ca/public/root-ca.crt.pem
  │  CA operator CLI :  $DEVDIR/ca-admin$EXE  (issue certs offline)
  │
  │  Register an admin, then in another shell issue device certs:
  │    curl -s $DEVDIR/... (see tests/e2e/local-run.sh for the full flow)
  │
  │  Ctrl+C to stop.
  └─────────────────────────────────────────────────────────────

EOF

exec env PQC_JWT_SECRET="dev-secret-0123456789" PQC_RATE_LIMIT_DISABLED=1 \
  "$DEVDIR/pqc-api$EXE" --addr "0.0.0.0:$PORT" \
  --root-ca "$DEVDIR/ca/public/root-ca.crt.pem" \
  --ca-chain "$DEVDIR/ca/public/ca-chain.pem" \
  --public-base-url "http://$IP:$PORT"
