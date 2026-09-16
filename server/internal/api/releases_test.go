package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseDownloads(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "windows.json"), []byte(`{"version_code":7}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{ReleaseDir: dir}}
	for _, tc := range []struct {
		name string
		code int
	}{{"windows.json", 200}, {"../secret.json", 404}, {".env", 404}, {"missing.exe", 404}, {"", 404}} {
		r := httptest.NewRequest("GET", "/updates/test", nil)
		r.SetPathValue("file", tc.name)
		w := httptest.NewRecorder()
		s.hAppRelease(w, r)
		if w.Code != tc.code {
			t.Errorf("%s: %d", tc.name, w.Code)
		}
		if tc.code == 200 && w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("manifest may be cached")
		}
	}
}
