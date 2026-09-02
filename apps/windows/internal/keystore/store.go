package keystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Layout under %LOCALAPPDATA%\PQC-PDF-Sign\ (Rencana V1 §12.1):
//
//	keys\device-key.pqk        DPAPI-wrapped ML-DSA-65 key
//	certificates\device.crt.pem
//	certificates\ca-chain.pem
//	certificates\root-ca.crt.pem
//	state.json                 non-secret local state
const (
	keyFile    = "keys/device-key.pqk"
	deviceCert = "certificates/device.crt.pem"
	chainCert  = "certificates/ca-chain.pem"
	rootCert   = "certificates/root-ca.crt.pem"
	stateFile  = "state.json"
)

// State is non-secret local bookkeeping.
type State struct {
	ServerBaseURL string    `json:"server_base_url,omitempty"`
	AccountEmail  string    `json:"account_email,omitempty"`
	DeviceID      string    `json:"device_id,omitempty"`
	EnrollmentID  string    `json:"enrollment_id,omitempty"`
	CertificateSN string    `json:"certificate_serial,omitempty"`
	HasPIN        bool      `json:"has_pin"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Store is the on-disk client vault. Not safe for concurrent writers.
type Store struct{ dir string }

// DefaultDir is %LOCALAPPDATA%\PQC-PDF-Sign (falls back to the OS config dir).
func DefaultDir() (string, error) {
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		return filepath.Join(la, "PQC-PDF-Sign"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "PQC-PDF-Sign"), nil
}

// Open returns a Store rooted at dir (created if missing). Pass "" for DefaultDir.
func Open(dir string) (*Store, error) {
	if dir == "" {
		var err error
		if dir, err = DefaultDir(); err != nil {
			return nil, err
		}
	}
	for _, d := range []string{dir, filepath.Join(dir, "keys"), filepath.Join(dir, "certificates")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(rel string) string { return filepath.Join(s.dir, filepath.FromSlash(rel)) }

// HasKey reports whether a device key blob is present.
func (s *Store) HasKey() bool {
	_, err := os.Stat(s.path(keyFile))
	return err == nil
}

// SaveKey wraps a PKCS#8 key and writes device-key.pqk. A fresh GCM nonce is
// used on every write (Protect generates one); the wrapping key is new too.
func (s *Store) SaveKey(pkcs8 []byte, opt Options) error {
	b, err := Protect(pkcs8, opt)
	if err != nil {
		return err
	}
	return writeFile(s.path(keyFile), b, 0o600)
}

// LoadKey unwraps device-key.pqk. The caller MUST zero the returned bytes as
// soon as the single sign/CSR operation completes.
func (s *Store) LoadKey(opt Options) ([]byte, error) {
	b, err := os.ReadFile(s.path(keyFile))
	if err != nil {
		return nil, err
	}
	return Unprotect(b, opt)
}

// DeleteKey removes the key blob (used on re-enrollment / reset, §12.3).
func (s *Store) DeleteKey() error {
	err := os.Remove(s.path(keyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) SaveDeviceCertPEM(pem []byte) error { return writeFile(s.path(deviceCert), pem, 0o644) }
func (s *Store) SaveChainPEM(pem []byte) error      { return writeFile(s.path(chainCert), pem, 0o644) }
func (s *Store) SaveRootPEM(pem []byte) error       { return writeFile(s.path(rootCert), pem, 0o644) }

func (s *Store) DeviceCertPEM() ([]byte, error) { return os.ReadFile(s.path(deviceCert)) }
func (s *Store) ChainPEM() ([]byte, error)      { return os.ReadFile(s.path(chainCert)) }
func (s *Store) RootPEM() ([]byte, error)       { return os.ReadFile(s.path(rootCert)) }

func (s *Store) State() (State, error) {
	var st State
	b, err := os.ReadFile(s.path(stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	return st, json.Unmarshal(b, &st)
}

func (s *Store) SaveState(st State) error {
	st.UpdatedAt = time.Now().UTC()
	b, _ := json.MarshalIndent(&st, "", "  ")
	return writeFile(s.path(stateFile), b, 0o600)
}

// Reset removes the whole vault (uninstall / lost-key recovery, §12.3, M4 gate).
func (s *Store) Reset() error { return os.RemoveAll(s.dir) }

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
