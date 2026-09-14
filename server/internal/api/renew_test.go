package api_test

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// readyIssuer returns a config and store whose online issuer already has an
// installed Intermediate (Root created and signing through ca-admin).
func readyIssuer(t *testing.T, certDays int) (api.Config, api.Store) {
	t.Helper()
	bin := caAdminBin(t)
	base := t.TempDir()
	rootDir, issuerDir := filepath.Join(base, "root"), filepath.Join(base, "issuer")
	rootEnv := []string{"PQC_CA_ROOT_PASSPHRASE=" + testRootPass}
	runCAAdmin(t, bin, rootEnv, "init-root", "--dir", rootDir)
	rootCert := filepath.Join(rootDir, "public", "root-ca.crt.pem")
	rootPEM, err := os.ReadFile(rootCert)
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
			Online: true, Bin: bin, Dir: issuerDir, Passphrase: testInterPass, CertDays: certDays,
		},
	}
	st := backendStore(t)
	if _, err := api.New(st, cfg); err != nil { // creates the Intermediate key + CSR
		t.Fatal(err)
	}
	crt := filepath.Join(base, "inter.crt.pem")
	runCAAdmin(t, bin, rootEnv, "sign-intermediate", "--dir", rootDir,
		"--csr", filepath.Join(issuerDir, "intermediate", "request.csr.pem"), "--inter-cn", "Issuer", "--out", crt)
	runCAAdmin(t, bin, []string{"PQC_CA_INTERMEDIATE_PASSPHRASE=" + testInterPass},
		"install-intermediate", "--dir", issuerDir, "--cert", crt, "--root-cert", rootCert)
	return cfg, st
}

func TestDeviceCertificateRenewal(t *testing.T) {
	cfg, st := readyIssuer(t, 10)
	srv, err := api.New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: srv.Routes(), st: st, cfg: cfg}
	e.su = e.login("_su@test")
	e.badmin = e.su
	ctx := context.Background()
	user := e.account("user@test", store.RoleUser)

	// a device enrols and gets a 10-day certificate; it keeps its key
	w := e.do("POST", "/api/v1/devices", user, map[string]string{"label": "Laptop", "platform": "windows"})
	mustCode(t, w, http.StatusCreated)
	deviceID := jbody(t, w)["device_id"].(string)
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/devices/"+deviceID+"/csr", user, csrPEM)
	mustCode(t, w, http.StatusCreated)
	if s := jbody(t, w)["status"]; s != store.EnrollmentIssued {
		t.Fatalf("enrolment status %v, want issued", s)
	}
	certOf := func() []byte {
		t.Helper()
		w := e.do("GET", "/api/v1/devices/"+deviceID+"/certificate", user, nil)
		mustCode(t, w, http.StatusOK)
		return w.Body.Bytes()
	}
	oldPEM := certOf()
	chain := e.do("GET", "/api/v1/public/ca/chain.pem", "", nil).Body.Bytes()
	old := device{id: deviceID, keyPEM: keyPEM, chainPEM: append(append([]byte(nil), oldPEM...), chain...)}

	// due, but a new 10-day certificate would not last longer: nothing happens
	if n := srv.RenewDueCertificates(ctx); n != 0 {
		t.Fatalf("renewed %d certificates that a new one would not outlast", n)
	}

	// with a 365-day lifetime the 10-day certificate is renewed, once
	cfg.LabIssuer.CertDays = 365
	if n := srv.RenewDueCertificates(ctx); n != 1 {
		t.Fatalf("renewed %d certificates, want 1", n)
	}
	newPEM := certOf()
	if bytes.Equal(newPEM, oldPEM) {
		t.Fatal("the device still gets the old certificate")
	}
	oldCert, _ := certutil.ParseCertificatePEM(oldPEM)
	newCert, err := certutil.ParseCertificatePEM(newPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !keys.SameKeyPair(sk, newCert.PublicKey) {
		t.Fatal("the renewed certificate is for a different key")
	}
	if newCert.NotAfter.Sub(oldCert.NotAfter) < 300*24*time.Hour {
		t.Fatalf("renewed certificate ends %s, barely after the old %s", newCert.NotAfter, oldCert.NotAfter)
	}
	if n := srv.RenewDueCertificates(ctx); n != 0 {
		t.Fatalf("a second pass renewed %d certificates", n)
	}

	// the old certificate was not revoked: it still signs until it expires
	pid := e.reserve(user, deviceID)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, old, pid)), http.StatusOK)
}
