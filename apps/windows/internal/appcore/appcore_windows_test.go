//go:build windows

package appcore_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/testpdf"

	"example.internal/pqc-pdf-sign/apps/windows/internal/apiclient"
	"example.internal/pqc-pdf-sign/apps/windows/internal/appcore"
)

// TestClientEndToEnd drives the full M4 desktop flow against a fake receiver
// (submissions are checked with the real core/verification): login, on-device
// key generation + DPAPI wrap, enrollment, offline cert issuance, sign (local
// verify + submit), verify, history, reset (Rencana V1 §20, §25).
func TestClientEndToEnd(t *testing.T) {
	root, err := labpki.NewRootCA("Client Root", 24*time.Hour)
	must(t, err)
	inter, err := labpki.NewIntermediateCA(root, "Client Intermediate", 24*time.Hour)
	must(t, err)

	ts := newFakeReceiver(t, root, inter)
	defer ts.Close()
	admin := apiclient.New(ts.URL, true)

	app, err := appcore.New(appcore.Config{
		VaultDir: filepath.Join(t.TempDir(), "vault"), ServerURL: ts.URL, InsecureTLS: true,
	})
	must(t, err)

	must(t, app.Login("user@c", "password123"))

	enr, err := app.RegisterDevice("Test Laptop", "1357")
	must(t, err)
	if enr.DeviceID == "" || enr.EnrollmentID == "" {
		t.Fatalf("bad enroll result: %+v", enr)
	}

	// Certificate is pending until the offline CA issues it.
	if cs, _ := app.CertificateStatus("1357"); cs.State != "pending" {
		t.Fatalf("pre-issue state = %q, want pending", cs.State)
	}
	issueForEnrollment(t, admin, inter, enr.EnrollmentID)

	cs, err := app.CertificateStatus("1357")
	must(t, err)
	if cs.State != "active" || cs.Info == nil {
		t.Fatalf("cert status = %+v", cs)
	}
	if !cs.Info.HasDocumentSigning {
		t.Fatal("issued cert lacks the document-signing EKU")
	}

	in := filepath.Join(t.TempDir(), "doc.pdf")
	must(t, os.WriteFile(in, testpdf.Sample(), 0o644))
	out := filepath.Join(t.TempDir(), "doc.signed.pdf")
	sr, err := app.SignPDF(in, out, "M4 e2e", "Test User", "1357", `[{"page":1,"x":0.6,"y":0.8,"w":0.25}]`, "Jakarta")
	must(t, err)
	if sr.ServerStatus != "accepted" {
		t.Fatalf("server status = %q", sr.ServerStatus)
	}
	if sr.OriginalSHA512 == sr.SignedSHA512 {
		t.Fatal("original and signed hash must differ")
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("signed file missing: %v", err)
	}

	vjson, err := app.VerifyPDF(out)
	must(t, err)
	var vr map[string]any
	must(t, json.Unmarshal(vjson, &vr))
	if vr["valid"] != true {
		t.Fatalf("local verify not valid: %s", vjson)
	}

	// Public verifier must work from a fresh client with NO login.
	nolo, err := appcore.New(appcore.Config{
		VaultDir: filepath.Join(t.TempDir(), "vault2"), ServerURL: ts.URL, InsecureTLS: true,
	})
	must(t, err)
	pjson, err := nolo.VerifyPublic(ts.URL, out)
	must(t, err)
	var pv map[string]any
	must(t, json.Unmarshal(pjson, &pv))
	if v, _ := pv["verification"].(map[string]any); v["valid"] != true || pv["registered"] != true {
		t.Fatalf("public verify (no login) failed: %s", pjson)
	}

	hist, err := app.History()
	must(t, err)
	if len(hist) != 1 {
		t.Fatalf("history len = %d, want 1", len(hist))
	}

	// Wrong PIN must be refused when signing again.
	if _, err := app.SignPDF(in, out, "x", "x", "9999", "", ""); err == nil {
		t.Fatal("SignPDF accepted the wrong PIN")
	}

	must(t, app.Reset())
	if cs, _ := app.CertificateStatus("1357"); cs.State != "none" {
		t.Fatalf("post-reset state = %q, want none", cs.State)
	}
}

// TestRegisterAndSilentEnrol covers the RB-3 path: self-register, then a
// single EnsureEnrolled that generates the key and enrols with no manual
// step, and is a safe no-op when called again.
func TestRegisterAndSilentEnrol(t *testing.T) {
	root, err := labpki.NewRootCA("RB Root", 24*time.Hour)
	must(t, err)
	inter, err := labpki.NewIntermediateCA(root, "RB Intermediate", 24*time.Hour)
	must(t, err)
	ts := newFakeReceiver(t, root, inter)
	defer ts.Close()

	app, err := appcore.New(appcore.Config{
		VaultDir: filepath.Join(t.TempDir(), "vault"), ServerURL: ts.URL, InsecureTLS: true,
	})
	must(t, err)

	rr, err := app.Register("Budi Santoso", "Dinas Kominfo", "budi@c", "budi12345", "Kepala Seksi", "199001012020121001")
	must(t, err)
	if rr.AccountID == "" {
		t.Fatalf("register returned no account id: %+v", rr)
	}

	must(t, app.Login("budi@c", "budi12345"))

	cs, err := app.EnsureEnrolled("") // first run: key generated + enrolled
	must(t, err)
	if cs.State != "pending" { // the fake CA has not issued yet
		t.Fatalf("state after first enrol = %q, want pending", cs.State)
	}

	cs2, err := app.EnsureEnrolled("") // idempotent
	must(t, err)
	if cs2.State != "pending" {
		t.Fatalf("second EnsureEnrolled state = %q", cs2.State)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
