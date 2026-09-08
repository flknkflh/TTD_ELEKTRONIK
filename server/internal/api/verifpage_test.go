package api_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"

	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// RB-2b: the server composes the verification page (POST .../cover-page); the
// client signs what comes back. The result passes strict re-verification and
// the public verifier, and carries one extra page.
func TestCoverPageThenSubmit(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")

	w := e.do("POST", "/api/v1/signatures/reserve", user, map[string]string{
		"device_id": d.id, "file_name": "x.pdf",
	})
	mustCode(t, w, http.StatusCreated)
	pid := jbody(t, w)["public_id"].(string)

	// cover-page: one more page than the original
	before, _ := pdfcpu.PageCount(bytes.NewReader(testpdf.Sample()), nil)
	w = e.do("POST", "/api/v1/signatures/"+pid+"/cover-page?reason=Persetujuan", user, testpdf.Sample())
	mustCode(t, w, http.StatusOK)
	augmented := w.Body.Bytes()
	after, err := pdfcpu.PageCount(bytes.NewReader(augmented), nil)
	if err != nil {
		t.Fatalf("page count: %v", err)
	}
	if after != before+1 {
		t.Fatalf("pages: before=%d after=%d, want +1", before, after)
	}

	signed := e.coverAndSign(user, d, pid) // signs a fresh cover-page copy
	w = e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed)
	mustCode(t, w, http.StatusOK)
	if jbody(t, w)["status"] != "accepted" {
		t.Fatalf("submit not accepted: %s", w.Body.String())
	}

	w = e.verifyMultipart(signed)
	mustCode(t, w, http.StatusOK)
	vb := jbody(t, w)
	if vb["registered"] != true || vb["verification"].(map[string]any)["valid"] != true {
		t.Fatalf("public verify failed: %s", w.Body.String())
	}
}

// the QR landing page (GET /v/{id}) renders the record as HTML, and reports
// "DICABUT" once the certificate is revoked.
func TestQRLandingPage(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d, pid)), http.StatusOK)

	w := e.do("GET", "/v/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	if b := w.Body.String(); !strings.Contains(b, "TERVERIFIKASI") || !strings.Contains(b, "Verifikasi Tanda Tangan") {
		t.Fatalf("landing page missing expected content: %s", b[:min(400, len(b))])
	}
	if b := w.Body.String(); !strings.Contains(b, "/v/"+pid+"/document") || !strings.Contains(b, "Dokumen asli yang ditandatangani") {
		t.Fatalf("landing page should embed the signed document: %s", b[:min(600, len(b))])
	}

	// the authoritative signed PDF is served publicly (no token)
	w = e.do("GET", "/v/"+pid+"/document", "", nil)
	mustCode(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("document content-type = %q", ct)
	}
	if !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
		t.Fatalf("document response is not a PDF")
	}
	mustCode(t, e.do("GET", "/v/sig_does_not_exist/document", "", nil), http.StatusNotFound)

	// unknown id -> 404 HTML, not a JSON error
	w = e.do("GET", "/v/sig_does_not_exist", "", nil)
	mustCode(t, w, http.StatusNotFound)
	if !strings.Contains(w.Body.String(), "Tidak ditemukan") {
		t.Fatalf("unknown-id page: %s", w.Body.String())
	}

	// revoke the cert -> page shows DICABUT
	mustCode(t, e.do("POST", "/api/v1/admin/certificates/"+d.certID+"/revoke", admin,
		map[string]string{"reason": "keyCompromise"}), http.StatusOK)
	w = e.do("GET", "/v/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "DICABUT") {
		t.Fatalf("revoked page should say DICABUT: %s", w.Body.String())
	}
}

// cover-page is refused for a reservation the caller does not own and for a
// device with no active certificate.
func TestCoverPageGuards(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	other := e.account("intruder@test", store.RoleUser)
	mustCode(t, e.do("POST", "/api/v1/signatures/"+pid+"/cover-page", other, testpdf.Sample()), http.StatusNotFound)

	mustCode(t, e.do("POST", "/api/v1/signatures/"+pid+"/cover-page", user, []byte("not a pdf")), http.StatusUnprocessableEntity)
}
