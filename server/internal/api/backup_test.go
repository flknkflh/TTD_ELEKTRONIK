package api_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

func writeBackupStatus(t *testing.T, path string, result string, lastSuccess time.Time) {
	t.Helper()
	st := map[string]any{
		"last_result":     result,
		"last_run_at":     time.Now().UTC().Format(time.RFC3339),
		"last_success_at": lastSuccess.UTC().Format(time.RFC3339),
		"repository":      "/var/backups/pqsign/repo",
		"snapshot_count":  3,
	}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The super admin reads the host's backup report; admins get a reminder when
// it is missing, failed or stale, and nobody can fetch backup data via the API.
func TestBackupReport(t *testing.T) {
	statusFile := filepath.Join(t.TempDir(), "status.json")
	e := newEnvWith(t, func(c *api.Config) {
		c.BackupStatusFile = statusFile
		c.BackupMaxAge = 72 * time.Hour
	})
	admin := e.account("admin@test", store.RoleAdmin)
	report := func() map[string]any {
		t.Helper()
		w := e.do("GET", "/api/v1/admin/backup", e.su, nil)
		mustCode(t, w, http.StatusOK)
		return jbody(t, w)
	}
	notices := func() []any {
		t.Helper()
		n, _ := jbody(t, e.do("GET", "/api/v1/admin/capabilities", admin, nil))["notices"].([]any)
		return n
	}

	mustCode(t, e.do("GET", "/api/v1/admin/backup", admin, nil), http.StatusForbidden)

	// no report yet
	if r := report(); r["configured"] != true || r["available"] != false || r["stale"] != true {
		t.Fatalf("missing report = %v", r)
	}
	if !hasNotice(notices(), "backup_missing") {
		t.Fatal("no reminder while no backup report exists")
	}

	// fresh successful backup: no reminder
	writeBackupStatus(t, statusFile, "ok", time.Now().Add(-2*time.Hour))
	if r := report(); r["available"] != true || r["stale"] != false || r["failed"] != false {
		t.Fatalf("fresh report = %v", r)
	}
	for _, code := range []string{"backup_missing", "backup_failed", "backup_stale"} {
		if hasNotice(notices(), code) {
			t.Fatalf("reminder %s with a fresh backup", code)
		}
	}

	// last run failed
	writeBackupStatus(t, statusFile, "fail", time.Now().Add(-26*time.Hour))
	if r := report(); r["failed"] != true || !hasNotice(notices(), "backup_failed") {
		t.Fatalf("failed run: report %v", r)
	}

	// no success for more than the allowed age
	writeBackupStatus(t, statusFile, "ok", time.Now().Add(-96*time.Hour))
	if r := report(); r["stale"] != true || !hasNotice(notices(), "backup_stale") {
		t.Fatalf("stale backup: report %v", r)
	}

	// no endpoint serves backup data
	for _, p := range []string{"/api/v1/admin/backup/download", "/api/v1/admin/backup/restore"} {
		if w := e.do("POST", p, e.su, nil); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s answered %d", p, w.Code)
		}
	}
}

func TestBackupReportNotConfigured(t *testing.T) {
	e := newEnv(t)
	if r := jbody(t, e.do("GET", "/api/v1/admin/backup", e.su, nil)); r["configured"] != false {
		t.Fatalf("report without a status file = %v", r)
	}
	n, _ := jbody(t, e.do("GET", "/api/v1/admin/capabilities", e.su, nil))["notices"].([]any)
	if hasNotice(n, "backup_missing") {
		t.Fatal("backup reminder on a server without a backup report configured")
	}
}
