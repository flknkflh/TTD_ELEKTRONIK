package api_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"

	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

type env struct {
	t     *testing.T
	h     http.Handler
	inter *labpki.CA
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root, err := labpki.NewRootCA("Test Root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := labpki.NewIntermediateCA(root, "Test Intermediate", 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(store.NewMemory(), api.Config{
		RootCAPEM:     labpki.CertPEM(root.Cert),
		CAChainPEM:    labpki.ChainPEM(inter.Cert, root.Cert),
		JWTSecret:     []byte("test-secret-0123456789"),
		PublicBaseURL: "https://verify.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, h: srv.Routes(), inter: inter}
}

func (e *env) do(method, path, token string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

func jbody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

func mustCode(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
	}
}

func (e *env) account(email, role string) string {
	e.t.Helper()
	mustCode(e.t, e.do("POST", "/api/v1/auth/register", "", map[string]string{
		"email": email, "password": "password123", "display_name": email, "role": role,
	}), http.StatusCreated)
	w := e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": email, "password": "password123"})
	mustCode(e.t, w, http.StatusOK)
	return jbody(e.t, w)["access_token"].(string)
}

type device struct {
	id, certID string
	keyPEM     []byte
	chainPEM   []byte
}

func (e *env) enrolledDevice(userTok, adminTok, label string) device {
	e.t.Helper()
	w := e.do("POST", "/api/v1/devices", userTok, map[string]string{"label": label, "platform": "windows"})
	mustCode(e.t, w, http.StatusCreated)
	deviceID := jbody(e.t, w)["device_id"].(string)

	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "ignored", Platform: "windows"})
	if err != nil {
		e.t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/devices/"+deviceID+"/csr", userTok, csrPEM)
	mustCode(e.t, w, http.StatusCreated)
	enrID := jbody(e.t, w)["enrollment_id"].(string)

	csr, _, _ := enrollment.ParseAndValidateCSR(csrPEM)
	cert, err := e.inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: label, Organization: []string{"Test"}}, Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	w = e.do("POST", "/api/v1/admin/enrollments/"+enrID+"/certificate", adminTok, labpki.CertPEM(cert))
	mustCode(e.t, w, http.StatusCreated)
	certID := jbody(e.t, w)["certificate_id"].(string)

	return device{id: deviceID, certID: certID, keyPEM: keyPEM, chainPEM: labpki.ChainPEM(cert, e.inter.Cert)}
}

func (e *env) reserve(userTok, deviceID string) string {
	e.t.Helper()
	w := e.do("POST", "/api/v1/signatures/reserve", userTok, map[string]string{
		"device_id": deviceID, "original_sha512": hashutil.CalculateSHA512(testpdf.Sample()), "file_name": "x.pdf",
	})
	mustCode(e.t, w, http.StatusCreated)
	return jbody(e.t, w)["public_id"].(string)
}

func signWith(t *testing.T, d device, publicID string) []byte {
	t.Helper()
	res, err := signing.SignPDF(testpdf.Sample(), d.keyPEM, d.chainPEM, signing.Options{
		SignerName: "Tester", PublicID: publicID,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return res.SignedPDF
}

func (e *env) verifyMultipart(pdf []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "doc.pdf")
	_, _ = fw.Write(pdf)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/verify", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

// --- tests ---

func TestHappyPath(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")

	mustCode(t, e.do("GET", "/api/v1/devices/"+d.id+"/certificate", user, nil), http.StatusOK)

	pid := e.reserve(user, d.id)
	signed := signWith(t, d, pid)

	w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["status"] != "accepted" {
		t.Fatalf("want accepted: %s", w.Body.String())
	}

	// idempotent
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusOK)

	w = e.do("GET", "/api/v1/public/signatures/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["signer_name"] != "user@test" {
		t.Fatalf("public record: %s", w.Body.String())
	}

	w = e.verifyMultipart(signed)
	mustCode(t, w, http.StatusOK)
	vb := jbody(t, w)
	if vb["registered"] != true {
		t.Fatalf("verify registered=false: %s", w.Body.String())
	}
	if vb["verification"].(map[string]any)["valid"] != true {
		t.Fatalf("verify not valid: %s", w.Body.String())
	}

	// audit trail recorded the key events
	w = e.do("GET", "/api/v1/admin/audit-events", admin, nil)
	mustCode(t, w, http.StatusOK)
	if !contains(w.Body.String(), "signature.submit") || !contains(w.Body.String(), "certificate.issue") {
		t.Fatalf("audit missing events: %s", w.Body.String())
	}
}

func TestSubmissionRejections(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d1 := e.enrolledDevice(user, admin, "Dev1")
	d2 := e.enrolledDevice(user, admin, "Dev2")

	t.Run("tampered PDF", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		signed := signWith(t, d1, pid)
		signed[len(signed)/2] ^= 0xFF
		mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusUnprocessableEntity)
	})

	t.Run("certificate of a different device", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		signed := signWith(t, d2, pid) // Dev2 signed, submitted under Dev1's reservation
		w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
		mustCode(t, w, http.StatusUnprocessableEntity)
		if !contains(w.Body.String(), "different device") {
			t.Fatalf("reason = %s", w.Body.String())
		}
	})

	t.Run("public id mismatch", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		signed := signWith(t, d1, "sig_not_the_reservation")
		w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
		mustCode(t, w, http.StatusUnprocessableEntity)
		if !contains(w.Body.String(), "public id") {
			t.Fatalf("reason = %s", w.Body.String())
		}
	})

	t.Run("revoked certificate", func(t *testing.T) {
		pid := e.reserve(user, d1.id)
		mustCode(t, e.do("POST", "/api/v1/admin/certificates/"+d1.certID+"/revoke", admin,
			map[string]string{"reason": "keyCompromise"}), http.StatusOK)
		signed := signWith(t, d1, pid)
		w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
		mustCode(t, w, http.StatusUnprocessableEntity)
		if !contains(w.Body.String(), "revoked") {
			t.Fatalf("reason = %s", w.Body.String())
		}
		// a revoked device cert also blocks new reservations
		mustCode(t, e.do("POST", "/api/v1/signatures/reserve", user,
			map[string]string{"device_id": d1.id, "file_name": "x.pdf"}), http.StatusForbidden)
	})

	t.Run("another account cannot read the record", func(t *testing.T) {
		pid := e.reserve(user, d2.id)
		mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d2, pid)), http.StatusOK)
		other := e.account("intruder@test", store.RoleUser)
		mustCode(t, e.do("GET", "/api/v1/signatures/"+pid, other, nil), http.StatusNotFound)
	})
}

func TestNoSigningEndpoint(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/v1/sign", "/api/v1/users/acct_x/sign"} {
		if w := e.do("POST", p, "", nil); w.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d, must not exist", p, w.Code)
		}
	}
}

func TestAuthGuards(t *testing.T) {
	e := newEnv(t)
	user := e.account("u@test", store.RoleUser)
	mustCode(t, e.do("GET", "/api/v1/devices", "", nil), http.StatusUnauthorized)
	mustCode(t, e.do("GET", "/api/v1/admin/enrollments", user, nil), http.StatusForbidden)
	mustCode(t, e.do("GET", "/api/v1/devices", user, nil), http.StatusOK)
}
