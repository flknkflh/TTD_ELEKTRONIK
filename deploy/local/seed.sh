#!/usr/bin/env bash
# Create the two starter accounts on the running local stack:
#   admin@local / admin12345   -> /admin console
#   user@local  / user12345    -> the Windows / Android app (already approved)
# Idempotent. Data is persistent, so you normally run this once per fresh volume.
#
#   deploy/local/seed.sh [base-url]
set -euo pipefail
BASE="${1:-http://localhost:8099}"; BASE="${BASE%/}"
jval() { sed -n "s/.*\"$1\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }

curl -fsS "$BASE/api/v1/public/ca/root.crt" >/dev/null || { echo "!! no API at $BASE — run 'docker compose up -d' first"; exit 1; }

curl -sS -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d '{"email":"admin@local","password":"admin12345","role":"admin","full_name":"Administrator","organization":"Lab","position":"Administrator Sistem","nip":"000000000000000000"}' >/dev/null || true
ADM=$(curl -fsS -X POST "$BASE/api/v1/auth/login" -d '{"email":"admin@local","password":"admin12345"}' | jval access_token || true)
[ -n "$ADM" ] || { echo "!! admin login failed"; exit 1; }
echo ">> admin@local ready"

UID_=$(curl -sS -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d '{"email":"user@local","password":"user12345","role":"user","full_name":"Gita Aurora, S.Ap., M.P.A.","organization":"Deputi Bidang Koordinasi Aparatur","display_name":"Gita Aurora","position":"Plt. Asisten Deputi Perumusan dan Koordinasi Kebijakan Penerapan Akuntabilitas Aparatur dan Pengawasan","nip":"198704012011012005"}' | jval account_id || true)
[ -n "$UID_" ] || UID_=$(curl -fsS "$BASE/api/v1/admin/accounts" -H "Authorization: Bearer $ADM" | tr '}' '\n' | grep 'user@local' | jval account_id || true)
[ -n "$UID_" ] && curl -fsS -X POST "$BASE/api/v1/admin/accounts/$UID_/approve" -H "Authorization: Bearer $ADM" >/dev/null && echo ">> user@local approved"

cat <<EOF

  Admin console : $BASE/admin        (admin@local / admin12345)
  App login     : $BASE              (user@local / user12345)
EOF
