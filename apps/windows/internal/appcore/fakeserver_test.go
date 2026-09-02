//go:build windows

package appcore_test

import (
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/verification"

	"example.internal/pqc-pdf-sign/apps/windows/internal/apiclient"
)

// fakeReceiver is a minimal stand-in for the real server (§17) — just enough
// for the desktop client's flow. Submissions are checked with the real
// core/verification, so the client's local-verify-then-upload path is
// exercised end to end without importing the server's internal packages.
type fakeReceiver struct {
	mu       sync.Mutex
	root     *labpki.CA
	inter    *labpki.CA
	csr      map[string][]byte // enrollmentID -> CSR PEM
	cert     map[string][]byte // deviceID -> cert PEM
	enrDev   map[string]string // enrollmentID -> deviceID
	reserved map[string]bool   // publicID -> exists
	accepted map[string]bool   // publicID -> submitted
	nextID   int
}

func newFakeReceiver(t *testing.T, root, inter *labpki.CA) *httptest.Server {
	f := &fakeReceiver{
		root: root, inter: inter,
		csr: map[string][]byte{}, cert: map[string][]byte{}, enrDev: map[string]string{},
		reserved: map[string]bool{}, accepted: map[string]bool{},
	}
	return httptest.NewTLSServer(f.mux(t))
}

func (f *fakeReceiver) id(prefix string) string {
	f.nextID++
	return prefix + "_" + time.Now().Format("150405") + "_" + itoa(f.nextID)
}

func (f *fakeReceiver) mux(t *testing.T) http.Handler {
	m := http.NewServeMux()
	j := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}

	m.HandleFunc("POST /api/v1/auth/register", func(w http.ResponseWriter, r *http.Request) {
		j(w, 201, map[string]string{"account_id": f.id("acct")})
	})
	m.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 900})
	})
	m.HandleFunc("POST /api/v1/auth/mfa/setup", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, map[string]string{"secret": "AAAAAAAAAAAAAAAA", "otpauth_url": "otpauth://totp/x?secret=AAAAAAAAAAAAAAAA"})
	})
	m.HandleFunc("POST /api/v1/auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, map[string]bool{"confirmed": true})
	})

	m.HandleFunc("POST /api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		j(w, 201, map[string]string{"device_id": f.id("dev"), "status": "active"})
	})
	m.HandleFunc("POST /api/v1/devices/{device_id}/csr", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if _, _, err := enrollment.ParseAndValidateCSR(body); err != nil {
			j(w, 400, map[string]string{"error": err.Error()})
			return
		}
		f.mu.Lock()
		enrID := f.id("enr")
		f.csr[enrID] = body
		f.enrDev[enrID] = r.PathValue("device_id")
		f.mu.Unlock()
		j(w, 201, map[string]string{"enrollment_id": enrID, "status": "submitted"})
	})
	m.HandleFunc("GET /api/v1/devices/{device_id}/certificate", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		pem := f.cert[r.PathValue("device_id")]
		f.mu.Unlock()
		if pem == nil {
			j(w, 404, map[string]string{"error": "not issued"})
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pem)
	})
	m.HandleFunc("GET /api/v1/admin/enrollments/{id}/export", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		csr := f.csr[r.PathValue("id")]
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(csr)
	})
	m.HandleFunc("POST /api/v1/admin/enrollments/{id}/certificate", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		dev := f.enrDev[r.PathValue("id")]
		f.cert[dev] = body
		f.mu.Unlock()
		j(w, 201, map[string]string{"certificate_id": f.id("cert")})
	})

	m.HandleFunc("GET /api/v1/public/ca/root.crt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(labpki.CertPEM(f.root.Cert))
	})
	m.HandleFunc("GET /api/v1/public/ca/chain.pem", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(labpki.CertPEM(f.inter.Cert))
	})
	m.HandleFunc("GET /api/v1/public/ca/crl.pem", func(w http.ResponseWriter, r *http.Request) {
		crl, _ := f.inter.NewCRL(nil, 1, time.Hour)
		_, _ = w.Write(crl)
	})

	m.HandleFunc("POST /api/v1/signatures/reserve", func(w http.ResponseWriter, r *http.Request) {
		pid := f.id("sig")
		f.mu.Lock()
		f.reserved[pid] = true
		f.mu.Unlock()
		j(w, 201, map[string]string{"public_id": pid, "verification_url": "https://verify.test/v/" + pid, "expires_at": "later"})
	})
	m.HandleFunc("PUT /api/v1/signatures/{public_id}/document", func(w http.ResponseWriter, r *http.Request) {
		pid := r.PathValue("public_id")
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		reserved := f.reserved[pid]
		f.mu.Unlock()
		if !reserved {
			j(w, 404, map[string]string{"error": "no reservation"})
			return
		}
		vr, err := verification.VerifyPDF(body, verification.Options{
			RootPEM: labpki.CertPEM(f.root.Cert), IntermediatePEM: labpki.CertPEM(f.inter.Cert),
			RequireMLDSAOnly: true, Timeout: 15 * time.Second,
		})
		if err != nil || !vr.Valid {
			j(w, 422, map[string]string{"error": "server verification failed"})
			return
		}
		if len(vr.Signatures) == 0 || vr.Signatures[0].PublicID() != pid {
			j(w, 422, map[string]string{"error": "public id mismatch"})
			return
		}
		f.mu.Lock()
		f.accepted[pid] = true
		f.mu.Unlock()
		j(w, 200, map[string]string{"public_id": pid, "status": "accepted"})
	})
	m.HandleFunc("GET /api/v1/me/signatures", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		var sigs []map[string]any
		for pid := range f.accepted {
			sigs = append(sigs, map[string]any{"public_id": pid, "status": "accepted"})
		}
		f.mu.Unlock()
		j(w, 200, map[string]any{"signatures": sigs})
	})
	return m
}

// issueForEnrollment: export the CSR, sign it with the lab intermediate, post
// the cert back — mimics the offline CA operator.
func issueForEnrollment(t *testing.T, admin *apiclient.Client, inter *labpki.CA, enrollmentID string) {
	t.Helper()
	csrPEM, err := admin.ExportEnrollmentCSR(enrollmentID)
	must(t, err)
	csr, _, err := enrollment.ParseAndValidateCSR(csrPEM)
	must(t, err)
	leaf, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject: pkix.Name{CommonName: "Test Laptop"}, Validity: 24 * time.Hour,
	})
	must(t, err)
	_, err = admin.IssueCertificate(enrollmentID, labpki.CertPEM(leaf))
	must(t, err)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
