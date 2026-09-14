package api

import (
	"encoding/json"
	"math"
	"net/http"
	"os"
	"time"
)

// Backup report for the super admin. Backups are taken on the host by
// tools/backup/pqsign-backup.sh (restic, encrypted, local repository), which
// writes a status file mounted into the container. The API only reads that
// file: it never runs, downloads or restores a backup — the console shows the
// operator steps instead.

func (s *Server) backupMaxAge() time.Duration {
	if s.cfg.BackupMaxAge > 0 {
		return s.cfg.BackupMaxAge
	}
	return 72 * time.Hour
}

// backupReport is the status file plus what the API derives from it:
// available (a readable report exists), failed (the last run failed) and
// stale (no successful backup within BackupMaxAge).
func (s *Server) backupReport() map[string]any {
	path := s.cfg.BackupStatusFile
	if path == "" {
		return map[string]any{"configured": false}
	}
	out := map[string]any{
		"configured":    true,
		"available":     false,
		"stale":         true,
		"failed":        false,
		"max_age_hours": int(s.backupMaxAge().Hours()),
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		out["error"] = "laporan backup tidak terbaca"
		return out
	}
	out["available"] = true
	out["status"] = st
	out["failed"] = str(st["last_result"]) == "fail"
	if last, err := time.Parse(time.RFC3339, str(st["last_success_at"])); err == nil {
		age := time.Since(last)
		out["age_hours"] = math.Round(age.Hours()*10) / 10
		out["stale"] = age > s.backupMaxAge()
	}
	return out
}

// hBackupReport (super admin): GET /api/v1/admin/backup.
func (s *Server) hBackupReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.backupReport())
}
