package api

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var releaseFilename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.(json|apk|exe)$`)

func (s *Server) hAppRelease(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if s.cfg.ReleaseDir == "" || !releaseFilename.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.cfg.ReleaseDir, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".json") {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	http.ServeFile(w, r, path)
}
