#!/usr/bin/env bash
# pqsign-backup — scheduled local backup of PQ PDF Sign (RUNBOOK §8.1).
#
# Dumps PostgreSQL and backs up the dump plus the signed-PDF and CA volumes
# into a restic repository on this server (encrypted; the password file is
# root-only and a copy must be kept off the server), applies the retention
# policy, checks the repository, and writes a status file that the API shows
# to the super admin. It never sends anything off the server.
#
#   sudo pqsign-backup                 run now
#   /etc/cron.d/pqsign-backup          daily schedule
#   /etc/pqsign-backup.env             settings (pqsign-backup.env.example)
set -uo pipefail

CONF="${PQSIGN_BACKUP_CONF:-/etc/pqsign-backup.env}"
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

PG_CONTAINER="${PQSIGN_PG_CONTAINER:?set PQSIGN_PG_CONTAINER in $CONF}"
PG_USER="${PQSIGN_PG_USER:-pqc}"
PG_DB="${PQSIGN_PG_DB:-pqc}"
VOLUMES="${PQSIGN_VOLUMES:?set PQSIGN_VOLUMES in $CONF}"
ROOT="${PQSIGN_BACKUP_ROOT:-/var/backups/pqsign}"
SCHEDULE_TEXT="${PQSIGN_BACKUP_SCHEDULE_TEXT:-setiap hari}"
KEEP_DAILY="${PQSIGN_KEEP_DAILY:-7}"
KEEP_WEEKLY="${PQSIGN_KEEP_WEEKLY:-4}"
KEEP_MONTHLY="${PQSIGN_KEEP_MONTHLY:-6}"
export RESTIC_REPOSITORY="$ROOT/repo"
export RESTIC_PASSWORD_FILE="${PQSIGN_RESTIC_PASSWORD_FILE:-/root/.config/pqsign-backup/restic-password}"

STAGING="$ROOT/staging"
STATUS_DIR="$ROOT/status"
DUMP="$STAGING/pqsign-db.dump"
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
T0=$(date +%s)
DB_BYTES=0
VOL_SIZES=""

umask 077
mkdir -p "$STAGING" "$STATUS_DIR"
chmod 700 "$ROOT" "$STAGING"
chmod 755 "$STATUS_DIR"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

# write_status ok|fail [error] — atomically rewrites status/status.json (no
# secrets: paths, snapshot ids, sizes, times).
write_status() {
  local result="$1" err="${2:-}" snaps repo_bytes
  snaps=$(restic snapshots --json --tag pqsign 2>/dev/null || echo "[]")
  repo_bytes=$(du -sb "$RESTIC_REPOSITORY" 2>/dev/null | cut -f1)
  RESULT="$result" ERR="$err" SNAPS="$snaps" REPO_BYTES="${repo_bytes:-0}" STARTED="$STARTED" \
    DURATION=$(( $(date +%s) - T0 )) STATUS_FILE="$STATUS_DIR/status.json" DUMP="$DUMP" \
    VOLUMES="$VOLUMES" PG_CONTAINER="$PG_CONTAINER" PG_USER="$PG_USER" PG_DB="$PG_DB" \
    SCHEDULE_TEXT="$SCHEDULE_TEXT" KEEP="$KEEP_DAILY/$KEEP_WEEKLY/$KEEP_MONTHLY" \
    DB_BYTES="$DB_BYTES" VOL_SIZES="$VOL_SIZES" \
    python3 - <<'PY'
import json, os, tempfile

path = os.environ["STATUS_FILE"]
try:
    with open(path) as f:
        prev = json.load(f)
except Exception:
    prev = {}
ok = os.environ["RESULT"] == "ok"
now = os.environ["STARTED"]
try:
    snaps = json.loads(os.environ["SNAPS"] or "[]") or []
except ValueError:
    snaps = []
snaps.sort(key=lambda s: s.get("time", ""), reverse=True)
daily, weekly, monthly = (int(x) for x in os.environ["KEEP"].split("/"))
volumes = {}
for pair in filter(None, os.environ["VOL_SIZES"].split(",")):
    name, size = pair.split("=")
    volumes[name] = int(size)
status = {
    "version": 1,
    "schedule": os.environ["SCHEDULE_TEXT"],
    "keep": {"daily": daily, "weekly": weekly, "monthly": monthly},
    "repository": os.environ["RESTIC_REPOSITORY"],
    "password_file": os.environ["RESTIC_PASSWORD_FILE"],
    "database_container": os.environ["PG_CONTAINER"],
    "database_user": os.environ["PG_USER"],
    "database_name": os.environ["PG_DB"],
    "db_dump_path": os.environ["DUMP"],
    "volumes": os.environ["VOLUMES"].split(),
    "last_run_at": now,
    "last_result": "ok" if ok else "fail",
    "last_error": "" if ok else os.environ["ERR"],
    "last_duration_seconds": int(os.environ["DURATION"]),
    "last_success_at": now if ok else prev.get("last_success_at", ""),
    "repository_bytes": int(os.environ["REPO_BYTES"] or 0),
    "data_bytes": {"database_dump": int(os.environ["DB_BYTES"] or 0), "volumes": volumes}
    if ok else prev.get("data_bytes", {}),
    "snapshot_count": len(snaps),
    "snapshots": [{"id": s.get("short_id") or s.get("id", "")[:8], "time": s.get("time", "")} for s in snaps[:10]],
}
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
with os.fdopen(fd, "w") as f:
    json.dump(status, f, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
}

fail() {
  log "FAIL: $1"
  rm -f "$DUMP"
  write_status fail "$1"
  exit 1
}

command -v restic >/dev/null || fail "restic tidak terpasang"
command -v python3 >/dev/null || { log "FAIL: python3 tidak terpasang"; exit 1; }
[ -r "$RESTIC_PASSWORD_FILE" ] || fail "file kata sandi backup tidak ada: $RESTIC_PASSWORD_FILE"
if ! restic cat config >/dev/null 2>&1; then
  log "initialising repository $RESTIC_REPOSITORY"
  restic init >/dev/null || fail "gagal membuat repositori backup"
fi

log "dumping database $PG_DB from $PG_CONTAINER"
docker exec "$PG_CONTAINER" pg_dump -U "$PG_USER" -d "$PG_DB" -Fc > "$DUMP" || fail "pg_dump gagal"
DB_BYTES=$(stat -c %s "$DUMP")
[ "$DB_BYTES" -gt 0 ] || fail "dump database kosong"

PATHS=("$DUMP")
for v in $VOLUMES; do
  mp=$(docker volume inspect "$v" --format '{{.Mountpoint}}' 2>/dev/null) || fail "volume tidak ditemukan: $v"
  PATHS+=("$mp")
  VOL_SIZES="$VOL_SIZES$v=$(du -sb "$mp" | cut -f1),"
done

log "backing up ${PATHS[*]}"
restic backup --tag pqsign --host pqsign "${PATHS[@]}" >/dev/null || fail "restic backup gagal"
log "retention: $KEEP_DAILY daily, $KEEP_WEEKLY weekly, $KEEP_MONTHLY monthly"
restic forget --tag pqsign --keep-daily "$KEEP_DAILY" --keep-weekly "$KEEP_WEEKLY" \
  --keep-monthly "$KEEP_MONTHLY" --prune >/dev/null || fail "restic forget/prune gagal"
restic check >/dev/null 2>&1 || fail "pemeriksaan repositori backup gagal"
rm -f "$DUMP"
write_status ok
log "backup ok in $(( $(date +%s) - T0 ))s"
