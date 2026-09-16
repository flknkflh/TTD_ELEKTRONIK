package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
)

const Origin = "https://136.244.116.132"
const Version = "0.7.2"
const VersionCode = 9
const maxSize = 256 << 20

type Release struct {
	Platform string `json:"platform"`
	Version  string `json:"version"`
	Code     int    `json:"version_code"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Notes    string `json:"notes"`
}

var client = &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect pembaruan ditolak") }}
var pathRE = regexp.MustCompile(`^/updates/[A-Za-z0-9._-]+\.exe$`)
var hashRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (r Release) Validate() error {
	if r.Platform != "windows" || r.Code <= VersionCode || r.Version == "" || !pathRE.MatchString(r.Path) || !hashRE.MatchString(r.SHA256) || r.Size <= 0 || r.Size > maxSize {
		return errors.New("manifest pembaruan tidak valid")
	}
	return nil
}

func Check() (*Release, error) {
	resp, err := client.Get(Origin + "/updates/windows.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("pembaruan HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, errors.New("manifest terlalu besar")
	}
	var r Release
	if err = json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Code <= VersionCode {
		return nil, nil
	}
	if err = r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Download returns a private staging directory. The caller does not accept a
// path or hash from JavaScript; it re-fetches the trusted release manifest.
func Download(r Release) (string, error) {
	return DownloadProgress(r, nil)
}

type progressWriter struct {
	total, size int64
	report      func(int)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.total += int64(len(b))
	if p.report != nil {
		pct := int(p.total * 100 / p.size)
		if pct > 100 {
			pct = 100
		}
		p.report(pct)
	}
	return len(b), nil
}

func DownloadProgress(r Release, report func(int)) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	resp, err := client.Get(Origin + r.Path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unduhan HTTP %d", resp.StatusCode)
	}
	dir, err := os.MkdirTemp("", "pqsign-update-")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()
	file, err := os.OpenFile(dir+"/update.exe", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, h, &progressWriter{size: r.Size, report: report}), io.LimitReader(resp.Body, r.Size+1))
	closeErr := file.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n != r.Size || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		return "", errors.New("ukuran/checksum pembaruan tidak cocok")
	}
	ok = true
	return dir, nil
}
