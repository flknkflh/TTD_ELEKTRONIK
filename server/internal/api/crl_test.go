package api_test

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

const crlWeek = 7 * 24 * time.Hour

// restart builds a fresh server over the same store and config, as a process
// restart or redeploy would. Tokens stay valid (same JWT secret).
func (e *env) restart() {
	e.t.Helper()
	srv, err := api.New(e.st, e.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.h = srv.Routes()
}

func (e *env) servedCRLNumber() int64 {
	e.t.Helper()
	w := e.do("GET", "/api/v1/public/ca/crl.pem", "", nil)
	mustCode(e.t, w, http.StatusOK)
	blk, _ := pem.Decode(w.Body.Bytes())
	if blk == nil {
		e.t.Fatalf("crl.pem is not PEM: %q", w.Body.String())
	}
	rl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		e.t.Fatal(err)
	}
	return rl.Number.Int64()
}

func mustCRL(t *testing.T, ca *labpki.CA, number int64) []byte {
	t.Helper()
	b, err := ca.NewCRL(nil, number, crlWeek)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCRLSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	mustCode(t, e.do("GET", "/api/v1/public/ca/crl.pem", "", nil), http.StatusNotFound)

	mustCode(t, e.do("POST", "/api/v1/admin/crl/import", e.su, mustCRL(t, e.inter, 1)), http.StatusOK)
	e.restart()

	if n := e.servedCRLNumber(); n != 1 {
		t.Fatalf("after restart crl.pem is #%d, want #1", n)
	}
	c, _ := jbody(t, e.do("GET", "/api/v1/admin/capabilities", e.su, nil))["crl"].(map[string]any)
	if c["number"] != "1" || c["stale"] != false {
		t.Fatalf("capabilities crl = %v, want number 1, not stale", c)
	}
}

func TestCRLImportValidation(t *testing.T) {
	e := newEnv(t)
	imp := func(b []byte) int { return e.do("POST", "/api/v1/admin/crl/import", e.su, b).Code }

	if imp([]byte("not a crl")) != http.StatusBadRequest {
		t.Fatal("garbage accepted as a CRL")
	}
	otherRoot, _ := labpki.NewRootCA("Other Root", 365*24*time.Hour)
	otherInter, _ := labpki.NewIntermediateCA(otherRoot, "Other Intermediate", 365*24*time.Hour)
	if imp(mustCRL(t, otherInter, 9)) != http.StatusBadRequest {
		t.Fatal("CRL signed by another CA accepted")
	}

	if imp(mustCRL(t, e.inter, 2)) != http.StatusOK {
		t.Fatal("valid CRL #2 rejected")
	}
	if imp(mustCRL(t, e.inter, 1)) != http.StatusBadRequest {
		t.Fatal("older CRL #1 replaced #2")
	}
	if imp(mustCRL(t, e.inter, 2)) != http.StatusBadRequest {
		t.Fatal("CRL number #2 accepted twice")
	}
	user := e.account("user@test", store.RoleUser)
	mustCode(t, e.do("POST", "/api/v1/admin/crl/import", user, mustCRL(t, e.inter, 3)), http.StatusForbidden)

	if n := e.servedCRLNumber(); n != 2 {
		t.Fatalf("crl.pem is #%d, want #2", n)
	}
}

// PQC_CRL_PEM must be a CRL of this CA; a newer one wins and is recorded.
func TestCRLFromConfig(t *testing.T) {
	e := newEnv(t)
	otherRoot, _ := labpki.NewRootCA("Other Root", 365*24*time.Hour)
	otherInter, _ := labpki.NewIntermediateCA(otherRoot, "Other Intermediate", 365*24*time.Hour)

	bad := e.cfg
	bad.CRLPEM = mustCRL(t, otherInter, 5)
	if _, err := api.New(e.st, bad); err == nil {
		t.Fatal("server started with a CRL from another CA")
	}

	mustCode(t, e.do("POST", "/api/v1/admin/crl/import", e.su, mustCRL(t, e.inter, 3)), http.StatusOK)

	older := e.cfg
	older.CRLPEM = mustCRL(t, e.inter, 2)
	e.cfg = older
	e.restart()
	if n := e.servedCRLNumber(); n != 3 {
		t.Fatalf("an older PQC_CRL_PEM replaced the stored CRL: #%d, want #3", n)
	}

	newer := e.cfg
	newer.CRLPEM = mustCRL(t, e.inter, 7)
	e.cfg = newer
	e.restart()
	e.cfg.CRLPEM = nil
	e.restart()
	if n := e.servedCRLNumber(); n != 7 {
		t.Fatalf("newer PQC_CRL_PEM was not recorded: #%d, want #7", n)
	}
}

// The database decides revocation for the upload verifier: a certificate
// revoked on the server fails even before any CRL lists it (offline CA).
func TestPublicVerifyHonoursServerRevocation(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	d := e.enrolledDevice(user, e.su, "Laptop")
	pid := e.reserve(user, d.id)
	signed := signWith(t, d, pid)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusOK)

	verdict := func() (valid, revoked bool) {
		t.Helper()
		w := e.verifyMultipart(signed)
		mustCode(t, w, http.StatusOK)
		v := jbody(t, w)["verification"].(map[string]any)
		sig := v["signatures"].([]any)[0].(map[string]any)
		return v["valid"] == true, sig["revoked"] == true
	}
	if valid, revoked := verdict(); !valid || revoked {
		t.Fatalf("before revoke: valid=%v revoked=%v, want true/false", valid, revoked)
	}

	w := e.do("POST", "/api/v1/admin/certificates/"+d.certID+"/revoke", e.su, map[string]string{"reason": "keyCompromise"})
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["crl_published"] != false {
		t.Fatalf("revoke body = %s, want crl_published false without a lab issuer", w.Body.String())
	}
	if valid, revoked := verdict(); valid || !revoked {
		t.Fatalf("after revoke (no CRL yet): valid=%v revoked=%v, want false/true", valid, revoked)
	}

	e.restart()
	if valid, revoked := verdict(); valid || !revoked {
		t.Fatalf("after restart: valid=%v revoked=%v, want false/true", valid, revoked)
	}
}
