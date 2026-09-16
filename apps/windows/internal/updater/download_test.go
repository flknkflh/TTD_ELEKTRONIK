package updater

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDownloadIntegrity(t *testing.T) {
	original := client
	defer func() { client = original }()
	body := "test executable bytes"
	r := Release{Platform: "windows", Version: "0.8.0", Code: VersionCode + 1, Path: "/updates/app.exe", Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(body)))}
	for _, tc := range []struct {
		body string
		ok   bool
	}{{body, true}, {"tampered", false}, {body + "extra", false}} {
		client = &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != Origin+r.Path {
				t.Fatalf("unexpected URL %s", req.URL)
			}
			if req.Header.Get("Authorization") != "" {
				t.Fatal("leaked auth")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
		})}
		lastPercent := -1
		dir, err := DownloadProgress(r, func(pct int) {
			if pct < lastPercent || pct < 0 || pct > 100 {
				t.Fatalf("invalid progress %d after %d", pct, lastPercent)
			}
			lastPercent = pct
		})
		if tc.ok {
			if lastPercent != 100 {
				t.Fatalf("incomplete progress: %d", lastPercent)
			}
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(dir, "update.exe"))
			if err != nil || string(b) != body {
				t.Fatal("bad staged file")
			}
			os.RemoveAll(dir)
		} else if err == nil {
			os.RemoveAll(dir)
			t.Fatal("accepted corrupt artifact")
		}
	}
}
