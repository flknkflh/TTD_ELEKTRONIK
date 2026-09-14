package api_test

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

const (
	testRootPass  = "root passphrase for issuer tests"
	testInterPass = "intermediate passphrase for issuer tests"
)

// The online issuer drives the real ca-admin binary:
//
//	go build -o /tmp/ca-admin ./tools/ca-admin
//	PQC_TEST_CA_ADMIN=/tmp/ca-admin go test ./internal/api/ -run OnlineIssuer
func caAdminBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("PQC_TEST_CA_ADMIN")
	if bin == "" {
		t.Skip("set PQC_TEST_CA_ADMIN to a ca-admin binary to run the online issuer tests")
	}
	return bin
}

func runCAAdmin(t *testing.T, bin string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ca-admin %s: %v\n%s", args[0], err, out)
	}
}

// enrolDevice creates a device and submits a fresh CSR; it returns the
// enrollment response.
func (e *env) enrolDevice(userTok, label string) map[string]any {
	e.t.Helper()
	w := e.do("POST", "/api/v1/devices", userTok, map[string]string{"label": label, "platform": "android"})
	mustCode(e.t, w, http.StatusCreated)
	deviceID := jbody(e.t, w)["device_id"].(string)
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "ignored"})
	if err != nil {
		e.t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/devices/"+deviceID+"/csr", userTok, csrPEM)
	mustCode(e.t, w, http.StatusCreated)
	return jbody(e.t, w)
}

func TestOnlineIssuerLifecycle(t *testing.T) {
	bin := caAdminBin(t)
	base := t.TempDir()
	rootDir, issuerDir := filepath.Join(base, "root"), filepath.Join(base, "issuer")
	rootEnv := []string{"PQC_CA_ROOT_PASSPHRASE=" + testRootPass}
	runCAAdmin(t, bin, rootEnv, "init-root", "--dir", rootDir, "--root-cn", "Test Split Root")
	rootPEM, err := os.ReadFile(filepath.Join(rootDir, "public", "root-ca.crt.pem"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := api.Config{
		RootCAPEM:          rootPEM,
		JWTSecret:          []byte("test-secret-0123456789"),
		PublicBaseURL:      "https://verify.test",
		RateLimits:         &api.RateLimits{},
		SuperAdminUsername: "_su@test",
		SuperAdminPassword: "password123",
		UploadDir:          t.TempDir(),
		LabIssuer: &api.LabIssuer{
			Online: true, Bin: bin, Dir: issuerDir, Passphrase: testInterPass, InterCN: "Test Issuer",
			CRLURL: "https://verify.test/api/v1/public/ca/crl.pem", CertDays: 30,
		},
	}
	st := backendStore(t)
	srv, err := api.New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: srv.Routes(), st: st, cfg: cfg}
	e.su = e.login("_su@test")
	e.badmin = e.su

	// pending: the server created the Intermediate key + CSR, holds no Root key
	status := jbody(t, e.do("GET", "/api/v1/admin/ca/issuer", e.su, nil))
	if status["mode"] != "online" || status["state"] != "pending" || status["csr_available"] != true {
		t.Fatalf("issuer status = %v, want online/pending with a CSR", status)
	}
	for _, name := range []string{"key.pem", "key.pem.enc"} {
		if _, err := os.Stat(filepath.Join(issuerDir, "root", name)); err == nil {
			t.Fatal("issuer directory holds a Root key")
		}
	}
	w := e.do("GET", "/api/v1/admin/ca/intermediate.csr", e.su, nil)
	mustCode(t, w, http.StatusOK)
	csrPath := filepath.Join(base, "inter.csr.pem")
	if err := os.WriteFile(csrPath, w.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// nothing is issued while pending
	user := e.account("user@test", store.RoleUser)
	if got := e.enrolDevice(user, "Phone 1")["status"]; got != store.EnrollmentSubmitted {
		t.Fatalf("enrolment while pending: status %v, want submitted", got)
	}

	// the offline Root signs; only the super admin installs, junk is refused
	certPath := filepath.Join(base, "inter.crt.pem")
	runCAAdmin(t, bin, rootEnv, "sign-intermediate", "--dir", rootDir, "--csr", csrPath, "--inter-cn", "Test Issuer", "--out", certPath)
	certPEM, _ := os.ReadFile(certPath)
	admin := e.account("admin@test", store.RoleAdmin)
	mustCode(t, e.do("POST", "/api/v1/admin/ca/intermediate", admin, certPEM), http.StatusForbidden)
	otherRoot, _ := labpki.NewRootCA("Other Root", 24*3600*1e9)
	otherInter, _ := labpki.NewIntermediateCA(otherRoot, "Other", 24*3600*1e9)
	mustCode(t, e.do("POST", "/api/v1/admin/ca/intermediate", e.su, labpki.CertPEM(otherInter.Cert)), http.StatusBadRequest)

	w = e.do("POST", "/api/v1/admin/ca/intermediate", e.su, certPEM)
	mustCode(t, w, http.StatusOK)
	if b := jbody(t, w); b["crl_published"] != true {
		t.Fatalf("install body = %s, want the first CRL published", w.Body.String())
	}
	mustCode(t, e.do("POST", "/api/v1/admin/ca/intermediate", e.su, certPEM), http.StatusConflict)

	if s := jbody(t, e.do("GET", "/api/v1/admin/ca/issuer", e.su, nil)); s["state"] != "active" {
		t.Fatalf("issuer status after install = %v", s)
	}
	w = e.do("GET", "/api/v1/public/ca/chain.pem", "", nil)
	mustCode(t, w, http.StatusOK)
	if n := strings.Count(w.Body.String(), "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("chain.pem has %d certificates, want 2", n)
	}
	if n := e.servedCRLNumber(); n != 1 {
		t.Fatalf("first CRL is #%d, want #1", n)
	}

	// enrolment now issues automatically, and a revoke republishes the CRL
	enr := e.enrolDevice(user, "Phone 2")
	if enr["status"] != store.EnrollmentIssued {
		t.Fatalf("enrolment after install: %v, want issued", enr)
	}
	cert, err := st.CertificateBySerial(enr["certificate_serial"].(string))
	if err != nil {
		t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/admin/certificates/"+cert.ID+"/revoke", e.su, map[string]string{"reason": "keyCompromise"})
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["crl_published"] != true {
		t.Fatalf("revoke body = %s, want crl_published", w.Body.String())
	}
	if n := e.servedCRLNumber(); n != 2 {
		t.Fatalf("CRL after revoke is #%d, want #2", n)
	}

	// restart: chain and CRL come back
	e.restart()
	if s := jbody(t, e.do("GET", "/api/v1/admin/ca/issuer", e.su, nil)); s["state"] != "active" {
		t.Fatalf("issuer status after restart = %v", s)
	}
	if n := e.servedCRLNumber(); n != 2 {
		t.Fatalf("CRL after restart is #%d, want #2", n)
	}

	// a Root key placed on the issuer stops the server from starting
	rootKey, _ := os.ReadFile(filepath.Join(rootDir, "root", "key.pem.enc"))
	if err := os.WriteFile(filepath.Join(issuerDir, "root", "key.pem.enc"), rootKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := api.New(st, cfg); err == nil || !strings.Contains(err.Error(), "Root CA private key") {
		t.Fatalf("server started with a Root key on the issuer: %v", err)
	}
}
