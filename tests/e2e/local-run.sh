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

say "start receiver (in-memory)"
PQC_JWT_SECRET="local-e2e-secret-0123456789" PQC_RATE_LIMIT_DISABLED=1 "$API" --addr "127.0.0.1:$PORT" \
  --root-ca "$WORK/ca/public/root-ca.crt.pem" \
  --ca-chain "$WORK/ca/public/ca-chain.pem" >"$WORK/api.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 40); do
  curl -fsS --max-time 1 "$BASE/api/v1/public/ca/root.crt" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS --max-time 2 "$BASE/api/v1/public/ca/root.crt" >/dev/null || { echo "server did not start"; cat "$WORK/api.log"; exit 1; }
echo "listening on $BASE"

# --- helper: register + MFA + login, echoes the bearer token ---
account() {
  local email=$1 role=$2
  curl -fsS -X POST "$BASE/api/v1/auth/register" \
    -d "{\"email\":\"$email\",\"password\":\"password123\",\"display_name\":\"$email\",\"role\":\"$role\"}" >/dev/null
  local t0
  t0=$(curl -fsS -X POST "$BASE/api/v1/auth/login" -d "{\"email\":\"$email\",\"password\":\"password123\"}" | jval access_token)
  local secret
  secret=$(curl -fsS -X POST "$BASE/api/v1/auth/mfa/setup" -H "Authorization: Bearer $t0" | jval secret)
  local code; code=$("$CLI" totp --secret "$secret")
  curl -fsS -X POST "$BASE/api/v1/auth/mfa/verify" -H "Authorization: Bearer $t0" -d "{\"code\":\"$code\"}" >/dev/null
  code=$("$CLI" totp --secret "$secret")
  curl -fsS -X POST "$BASE/api/v1/auth/login" -d "{\"email\":\"$email\",\"password\":\"password123\",\"code\":\"$code\"}" | jval access_token
}

say "accounts + MFA"
ADMIN=$(account "admin@e2e" admin)
USER=$(account "user@e2e" user)
echo "admin + user logged in with a TOTP-authorized session"

say "enrol a device"
DEV=$(curl -fsS -X POST "$BASE/api/v1/devices" -H "Authorization: Bearer $USER" \
      -d '{"label":"E2E Laptop","platform":"windows"}' | jval device_id)
"$CLI" keygen --out "$WORK/dev.key.pem" >/dev/null
"$CLI" csr --key "$WORK/dev.key.pem" --out "$WORK/dev.csr.pem" --cn "ignored-by-ca" >/dev/null
ENR=$(curl -fsS -X POST "$BASE/api/v1/devices/$DEV/csr" -H "Authorization: Bearer $USER" \
      -H "Content-Type: application/x-pem-file" --data-binary @"$WORK/dev.csr.pem" | jval enrollment_id)
echo "device=$DEV enrollment=$ENR"

say "offline CA issues the certificate"
curl -fsS "$BASE/api/v1/admin/enrollments/$ENR/export" -H "Authorization: Bearer $ADMIN" > "$WORK/export.csr.pem"
"$CA" issue --dir "$WORK/ca" --csr "$WORK/export.csr.pem" \
  --account "user@e2e" --device "E2E Laptop" --cn "E2E User" --org "Instansi E2E" \
  --out "$WORK/dev.crt.pem" | grep -E "serial|subject"
curl -fsS -X POST "$BASE/api/v1/admin/enrollments/$ENR/certificate" -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/x-pem-file" --data-binary @"$WORK/dev.crt.pem" | jval certificate_id | sed 's/^/certificate_id=/'

say "sign a PDF locally"
PDF="$ROOT/core/testpdf/sample.pdf"
SHA=$(sha512sum "$PDF" | cut -d' ' -f1)
RES=$(curl -fsS -X POST "$BASE/api/v1/signatures/reserve" -H "Authorization: Bearer $USER" \
      -d "{\"device_id\":\"$DEV\",\"original_sha512\":\"$SHA\",\"file_name\":\"sample.pdf\"}")
PID=$(echo "$RES" | jval public_id)
VURL=$(echo "$RES" | jval verification_url)
echo "reserved public_id=$PID"
"$CLI" sign --in "$PDF" --key "$WORK/dev.key.pem" --chain "$WORK/dev.crt.pem.fullchain.pem" \
  --out "$WORK/signed.pdf" --signer "E2E User" --reason "End-to-end run" \
  --public-id "$PID" --verify-url "$VURL" --qr | grep -E "sha512|serial"

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
