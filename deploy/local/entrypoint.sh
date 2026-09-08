#!/bin/sh
# Local prototype entrypoint: create the lab CA once (into the mounted /ca
# volume), then run the receiver API with the online CA issuer and
# rate limiting off — the simple single-box configuration.
set -e

# /ca is a mounted volume (always exists), and `ca-admin init` refuses a
# target directory that already exists — so keep the CA in a subdirectory.
CA_DIR="${PQC_DEV_LAB_CA_DIR:-/ca/store}"
if [ ! -f "$CA_DIR/public/root-ca.crt.pem" ]; then
  echo ">> first boot: generating lab CA in $CA_DIR"
  rm -rf "$CA_DIR"
  ca-admin init --dir "$CA_DIR" >/dev/null
fi

export PQC_ROOT_CA_PEM="$CA_DIR/public/root-ca.crt.pem"
export PQC_CA_CHAIN_PEM="$CA_DIR/public/ca-chain.pem"
export PQC_DEV_LAB_CA_ADMIN="/usr/local/bin/ca-admin"
export PQC_DEV_LAB_CA_DIR="$CA_DIR"
export PQC_RATE_LIMIT_DISABLED=1

echo ">> API on :8099   public-base-url=${PQC_PUBLIC_BASE_URL:-http://localhost:8099}"
exec api --addr ":8099" --public-base-url "${PQC_PUBLIC_BASE_URL:-http://localhost:8099}"
