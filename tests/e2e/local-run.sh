#!/usr/bin/env bash
# Full local end-to-end run (Rencana V1 §25, §31 step 12): lab CA + in-memory
# receiver + client CLI. No Docker. Proves the whole V1 flow works on one box.
#
#   tests/e2e/local-run.sh
#
# Requires: Go 1.27, curl, sha512sum. Builds the binaries it needs into dist/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
DIST="$ROOT/dist"
WORK="$(mktemp -d)"
PORT=18099
BASE="http://127.0.0.1:$PORT"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; *) EXE="" ;; esac
CLI="$DIST/pqcsign-cli$EXE"
CA="$DIST/ca-admin$EXE"
API="$DIST/pqc-api$EXE"
SRV_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  command -v powershell >/dev/null 2>&1 && \
    powershell -Command "Get-Process pqc-api -ErrorAction SilentlyContinue | Stop-Process -Force" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
jval() { sed -n "s/.*\"$1\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }

say "build"
( cd apps/windows && go build -o "$CLI" ./cmd/pqcsign-cli )
( cd tools/ca-admin && go build -o "$CA" . )
( cd server && go build -o "$API" ./cmd/api )

say "lab CA"
"$CA" init --dir "$WORK/ca" >/dev/null
"$CA" status --dir "$WORK/ca" | grep -E "gate|root "

say "start receiver (in-memory, online lab CA issuer)"
PQC_JWT_SECRET="local-e2e-secret-0123456789" PQC_RATE_LIMIT_DISABLED=1 \
  PQC_DEV_LAB_CA_ADMIN="$CA" PQC_DEV_LAB_CA_DIR="$WORK/ca" "$API" --addr "127.0.0.1:$PORT" \
  --root-ca "$WORK/ca/public/root-ca.crt.pem" \
  --ca-chain "$WORK/ca/public/ca-chain.pem" >"$WORK/api.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 40); do
  curl -fsS --max-time 1 "$BASE/api/v1/public/ca/root.crt" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS --max-time 2 "$BASE/api/v1/public/ca/root.crt" >/dev/null || { echo "server did not start"; cat "$WORK/api.log"; exit 1; }
echo "listening on $BASE"

# --- helper: register (RB-1: user starts pending) + admin-approve + login,
#     echoes the bearer token. $3 = admin token (needed for a user). ---
account() {
  local email=$1 role=$2 admtok=${3:-}
  local aid
  aid=$(curl -fsS -X POST "$BASE/api/v1/auth/register" \
    -d "{\"email\":\"$email\",\"password\":\"password123\",\"role\":\"$role\",\"full_name\":\"E2E User\",\"organization\":\"Instansi E2E\"}" \
    | jval account_id)
  if [ "$role" = user ]; then
    curl -fsS -X POST "$BASE/api/v1/admin/accounts/$aid/approve" -H "Authorization: Bearer $admtok" >/dev/null
  fi
  curl -fsS -X POST "$BASE/api/v1/auth/login" -d "{\"email\":\"$email\",\"password\":\"password123\"}" | jval access_token
}

say "accounts (self-register -> admin approve)"
ADMIN=$(account "admin@e2e" admin)
USER=$(account "user@e2e" user "$ADMIN")
echo "admin + user logged in"

say "enrol a device -> server auto-issues the certificate (RB-1)"
DEV=$(curl -fsS -X POST "$BASE/api/v1/devices" -H "Authorization: Bearer $USER" \
      -d '{"label":"E2E Laptop","platform":"windows"}' | jval device_id)
"$CLI" keygen --out "$WORK/dev.key.pem" >/dev/null
"$CLI" csr --key "$WORK/dev.key.pem" --out "$WORK/dev.csr.pem" --cn "ignored-by-ca" >/dev/null
CSRRESP=$(curl -fsS -X POST "$BASE/api/v1/devices/$DEV/csr" -H "Authorization: Bearer $USER" \
      -H "Content-Type: application/x-pem-file" --data-binary @"$WORK/dev.csr.pem")
echo "$CSRRESP"
echo "$CSRRESP" | grep -Eq '"status": ?"issued"' || { echo "CSR SUBMIT DID NOT AUTO-ISSUE"; cat "$WORK/api.log"; exit 1; }

# fetch the auto-issued leaf and build the signing chain
curl -fsS "$BASE/api/v1/devices/$DEV/certificate" -H "Authorization: Bearer $USER" > "$WORK/dev.crt.pem"
cat "$WORK/dev.crt.pem" "$WORK/ca/public/ca-chain.pem" > "$WORK/dev.fullchain.pem"

say "reserve -> server stamp -> sign locally (RB-2c)"
PDF="$ROOT/core/testpdf/sample.pdf"
SHA=$(sha512sum "$PDF" | cut -d' ' -f1)
RES=$(curl -fsS -X POST "$BASE/api/v1/signatures/reserve" -H "Authorization: Bearer $USER" \
      -d "{\"device_id\":\"$DEV\",\"original_sha512\":\"$SHA\",\"file_name\":\"sample.pdf\"}")
PID=$(echo "$RES" | jval public_id)
VURL=$(echo "$RES" | jval verification_url)
echo "reserved public_id=$PID"
curl -fsS -X POST "$BASE/api/v1/signatures/$PID/stamp?reason=End-to-end%20run&x=0.6&y=0.78&w=0.28" -H "Authorization: Bearer $USER" \
  -H "Content-Type: application/pdf" --data-binary @"$PDF" > "$WORK/withcover.pdf"
head -c 5 "$WORK/withcover.pdf" | grep -q "%PDF-" || { echo "STAMP DID NOT RETURN A PDF"; cat "$WORK/withcover.pdf"; exit 1; }
"$CLI" sign --in "$WORK/withcover.pdf" --key "$WORK/dev.key.pem" --chain "$WORK/dev.fullchain.pem" \
  --out "$WORK/signed.pdf" --signer "E2E User" --reason "End-to-end run" \
  --public-id "$PID" --verify-url "$VURL" | grep -E "sha512|serial"

say "submit to the server (strict verification)"
SUB=$(curl -fsS -X PUT "$BASE/api/v1/signatures/$PID/document" -H "Authorization: Bearer $USER" \
      -H "Content-Type: application/pdf" --data-binary @"$WORK/signed.pdf")
echo "$SUB"
echo "$SUB" | grep -Eq '"status": ?"accepted"' || { echo "SUBMIT NOT ACCEPTED"; exit 1; }

say "public verify"
VER=$(cd "$WORK" && curl -fsS -X POST "$BASE/api/v1/verify" -F "file=@signed.pdf")
echo "$VER" | head -c 400; echo
echo "$VER" | grep -Eq '"registered": ?true' || { echo "NOT REGISTERED"; exit 1; }
echo "$VER" | grep -Eq '"valid": ?true'      || { echo "NOT VALID"; exit 1; }

say "history"
curl -fsS "$BASE/api/v1/me/signatures" -H "Authorization: Bearer $USER" | head -c 300; echo

say "local verify (client, offline)"
"$CLI" verify --in "$WORK/signed.pdf" --root "$WORK/ca/public/root-ca.crt.pem" \
  --intermediate "$WORK/ca/public/intermediate-ca.crt.pem" | grep -E '"valid"|"algorithm"' | head -2

printf '\n\033[1;32m✔ LOCAL END-TO-END RUN PASSED\033[0m\n'
