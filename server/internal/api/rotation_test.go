package api_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// An Intermediate rotation on the online issuer: prepared automatically when
// due, signed by the Root, installed by the super admin. Accounts and device
// keys are untouched, certificates from the old Intermediate are re-issued,
// documents signed before the rotation keep verifying, and certificates from
// the retired Intermediate stay revocable.
func TestOnlineIssuerRotation(t *testing.T) {
	cfg, st, rootDir := readyIssuer(t, 365)
	cfg.LabIssuer.RotateDays = 1 // the new Intermediate has ~10 years: not due
	srv, err := api.New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: srv.Routes(), st: st, cfg: cfg}
	e.su = e.login("_su@test")
	e.badmin = e.su
	ctx := context.Background()
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)

	// a device signs a document before the rotation
	w := e.do("POST", "/api/v1/devices", user, map[string]string{"label": "Laptop", "platform": "windows"})
	mustCode(t, w, http.StatusCreated)
	deviceID := jbody(t, w)["device_id"].(string)
	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, _ := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "ignored"})
	w = e.do("POST", "/api/v1/devices/"+deviceID+"/csr", user, csrPEM)
	mustCode(t, w, http.StatusCreated)
	oldSerial := jbody(t, w)["certificate_serial"].(string)
	certPEM := func() []byte {
		t.Helper()
		w := e.do("GET", "/api/v1/devices/"+deviceID+"/certificate", user, nil)
		mustCode(t, w, http.StatusOK)
		return w.Body.Bytes()
	}
	oldChain := e.do("GET", "/api/v1/public/ca/chain.pem", "", nil).Body.Bytes()
	old := device{id: deviceID, keyPEM: keyPEM, chainPEM: append(certPEM(), oldChain...)}
	pid := e.reserve(user, deviceID)
	signed := signWith(t, old, pid)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusOK)
	valid := func() bool {
		t.Helper()
		w := e.verifyMultipart(signed)
		mustCode(t, w, http.StatusOK)
		return jbody(t, w)["verification"].(map[string]any)["valid"] == true
	}

	// not due yet
	if srv.CheckIntermediateRotation(ctx) {
		t.Fatal("rotation started while the Intermediate is far from its end")
	}
	// due: the server prepares the next Intermediate and reminds the admins
	cfg.LabIssuer.RotateDays = 20 * 365
	if !srv.CheckIntermediateRotation(ctx) {
		t.Fatal("rotation not started inside the window")
	}
	status := jbody(t, e.do("GET", "/api/v1/admin/ca/issuer", e.su, nil))
	if status["state"] != "active" || status["next_pending"] != true {
		t.Fatalf("issuer status = %v, want active with next_pending", status)
	}
	notices, _ := jbody(t, e.do("GET", "/api/v1/admin/capabilities", admin, nil))["notices"].([]any)
	if !hasNotice(notices, "intermediate_rotation_pending") {
		t.Fatalf("admin notices = %v, want intermediate_rotation_pending", notices)
	}
	mustCode(t, e.do("POST", "/api/v1/admin/ca/rotate", e.su, nil), http.StatusConflict)
	mustCode(t, e.do("POST", "/api/v1/admin/ca/rotate", admin, nil), http.StatusForbidden)

	// the Root signs the next Intermediate; the super admin installs it
	w = e.do("GET", "/api/v1/admin/ca/intermediate.csr", e.su, nil)
	mustCode(t, w, http.StatusOK)
	base := t.TempDir()
	csr, crt := filepath.Join(base, "next.csr"), filepath.Join(base, "next.crt")
	if err := os.WriteFile(csr, w.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	runCAAdmin(t, caAdminBin(t), []string{"PQC_CA_ROOT_PASSPHRASE=" + testRootPass},
		"sign-intermediate", "--dir", rootDir, "--csr", csr, "--inter-cn", "Issuer 2", "--out", crt)
	next, _ := os.ReadFile(crt)
	w = e.do("POST", "/api/v1/admin/ca/intermediate", e.su, next)
	mustCode(t, w, http.StatusOK)
	if b := jbody(t, w); b["rotated"] != true || b["crl_published"] != true {
		t.Fatalf("install body = %s", w.Body.String())
	}
	status = jbody(t, e.do("GET", "/api/v1/admin/ca/issuer", e.su, nil))
	if status["next_pending"] != false || len(status["retired"].([]any)) != 1 {
		t.Fatalf("issuer status after rotation = %v", status)
	}
	chain, err := certutil.ParseChainPEM(e.do("GET", "/api/v1/public/ca/chain.pem", "", nil).Body.Bytes())
	if err != nil || len(chain) != 3 || chain[0].Subject.CommonName != "Issuer 2" {
		t.Fatalf("chain after rotation: %d certs, %v", len(chain), err)
	}

	// accounts and keys untouched; the device certificate is re-issued from
	// the new Intermediate, for the same key
	if n := srv.RenewDueCertificates(ctx); n != 1 {
		t.Fatalf("re-issued %d certificates after the rotation, want 1", n)
	}
	newCert, err := certutil.ParseCertificatePEM(certPEM())
	if err != nil {
		t.Fatal(err)
	}
	if err := newCert.CheckSignatureFrom(chain[0]); err != nil || !keys.SameKeyPair(sk, newCert.PublicKey) {
		t.Fatalf("re-issued certificate: issuer err %v, same key %v", err, keys.SameKeyPair(sk, newCert.PublicKey))
	}
	if n := srv.RenewDueCertificates(ctx); n != 0 {
		t.Fatalf("a second pass re-issued %d certificates", n)
	}

	// the document signed before the rotation still verifies
	if !valid() {
		t.Fatal("a document signed before the rotation no longer verifies")
	}

	// the old certificate is still revocable, through the retired
	// Intermediate's CRL in the bundle
	oldCert, err := st.CertificateBySerial(oldSerial)
	if err != nil {
		t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/admin/certificates/"+oldCert.ID+"/revoke", e.su, map[string]string{"reason": "keyCompromise"})
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["crl_published"] != true {
		t.Fatalf("revoke body = %s", w.Body.String())
	}
	crl := e.do("GET", "/api/v1/public/ca/crl.pem", "", nil).Body.String()
	if n := strings.Count(crl, "BEGIN X509 CRL"); n != 2 {
		t.Fatalf("CRL bundle has %d CRLs, want 2", n)
	}
	if valid() {
		t.Fatal("a document signed with the revoked old certificate still verifies")
	}
}

func hasNotice(list []any, code string) bool {
	for _, n := range list {
		if m, ok := n.(map[string]any); ok && m["code"] == code {
			return true
		}
	}
	return false
}
