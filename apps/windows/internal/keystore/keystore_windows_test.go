//go:build windows

package keystore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

var samplePKCS8 = bytes.Repeat([]byte("ML-DSA-65-secret"), 8) // stand-in for a real key

func TestProtectUnprotectRoundTrip(t *testing.T) {
	for _, pin := range []string{"", "123456"} {
		opt := Options{PIN: pin}
		blob, err := Protect(samplePKCS8, opt)
		if err != nil {
			t.Fatalf("pin=%q protect: %v", pin, err)
		}
		got, err := Unprotect(blob, opt)
		if err != nil {
			t.Fatalf("pin=%q unprotect: %v", pin, err)
		}
		if !bytes.Equal(got, samplePKCS8) {
			t.Fatalf("pin=%q round-trip mismatch", pin)
		}
		// Two Protect calls must differ (fresh wrapping key + nonces).
		blob2, _ := Protect(samplePKCS8, opt)
		if bytes.Equal(blob, blob2) {
			t.Fatalf("pin=%q blob is deterministic", pin)
		}
	}
}

func TestTamperedBlobRejected(t *testing.T) {
	blob, err := Protect(samplePKCS8, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(blob, &b); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"key_ct", "dpapi_blob"} {
		mutated := map[string]any{}
		for k, v := range b {
			mutated[k] = v
		}
		s, _ := mutated[field].(string)
		if len(s) < 4 {
			t.Fatalf("field %s missing", field)
		}
		mutated[field] = "AAAA" + s[4:]
		raw, _ := json.Marshal(mutated)
		if _, err := Unprotect(raw, Options{}); err == nil {
			t.Fatalf("tampered %s was accepted", field)
		}
	}
}

func TestWrongPINRejected(t *testing.T) {
	blob, err := Protect(samplePKCS8, Options{PIN: "111111"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unprotect(blob, Options{PIN: "999999"}); err == nil {
		t.Fatal("wrong PIN accepted")
	}
	if _, err := Unprotect(blob, Options{}); err == nil {
		t.Fatal("missing PIN accepted for a PIN-protected key")
	}
}

func TestStoreLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.HasKey() {
		t.Fatal("fresh store already has a key")
	}
	if err := s.SaveKey(samplePKCS8, Options{}); err != nil {
		t.Fatal(err)
	}
	if !s.HasKey() {
		t.Fatal("HasKey false after SaveKey")
	}
	got, err := s.LoadKey(Options{})
	if err != nil || !bytes.Equal(got, samplePKCS8) {
		t.Fatalf("LoadKey: %v", err)
	}

	_ = s.SaveState(State{DeviceID: "dev_1", AccountEmail: "a@b"})
	st, _ := s.State()
	if st.DeviceID != "dev_1" {
		t.Fatalf("state not persisted: %+v", st)
	}

	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("Reset left the vault directory behind")
	}
}

// TestSimulatedForeignCopy: a blob whose DPAPI ciphertext is replaced with
// bytes that did not come from this account's CryptProtectData must fail to
// open — the Windows §26 "copy to another account" check, approximated by
// corrupting the protected region.
func TestSimulatedForeignCopy(t *testing.T) {
	blob, _ := Protect(samplePKCS8, Options{})
	var b map[string]any
	_ = json.Unmarshal(blob, &b)
	b["dpapi_blob"] = "Zm9yZWlnbi1ieXRlcy1ub3QtZnJvbS1kcGFwaQ==" // "foreign-bytes-not-from-dpapi"
	raw, _ := json.Marshal(b)
	if _, err := Unprotect(raw, Options{}); err == nil {
		t.Fatal("a foreign DPAPI blob was accepted")
	}
}
