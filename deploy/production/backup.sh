#!/usr/bin/env bash
# Daily encrypted backup of PQ PDF Sign (RUNBOOK.md section 8).
#
# Dumps PostgreSQL (accounts, certificates, signatures, audit log, admin TOTP
# secrets, CRL history) and tars the signed-PDF volume, each encrypted to an
# age public key. The matching private key must NOT live on this server.
#
#   AGE_RECIPIENT=age1... ./backup.sh
#   cron: 15 2 * * * root AGE_RECIPIENT=age1... /opt/pqsign/deploy/production/backup.sh >> /var/log/pqsign-backup.log 2>&1
set -euo pipefail

cd "$(dirname "$0")"
: "${AGE_RECIPIENT:?set AGE_RECIPIENT to the age public key (private key kept off this server)}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/pqsign}"
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

umask 077
mkdir -p "$BACKUP_DIR"

docker compose exec -T postgres pg_dump -U pqc -d pqc --format=custom \
  | age -r "$AGE_RECIPIENT" > "$BACKUP_DIR/db-$STAMP.dump.age"

docker run --rm -v pqsign_objdata:/objects:ro alpine:3.20 tar -C /objects -cf - . \
  | age -r "$AGE_RECIPIENT" > "$BACKUP_DIR/objects-$STAMP.tar.age"

sha256sum "$BACKUP_DIR/db-$STAMP.dump.age" "$BACKUP_DIR/objects-$STAMP.tar.age" > "$BACKUP_DIR/SHA256SUMS-$STAMP"
find "$BACKUP_DIR" -type f -mtime +"$KEEP_DAYS" -delete

echo "backup $STAMP ok: $(du -ch "$BACKUP_DIR"/*-"$STAMP"* | tail -1)"
