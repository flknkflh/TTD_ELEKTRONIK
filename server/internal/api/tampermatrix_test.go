package api_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// verifyNamed is verifyMultipart with control over the upload's filename, so
// the "renamed file" case can be expressed honestly.
func (e *env) verifyNamed(pdf []byte, filename string) *httptest.ResponseRecorder {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write(pdf)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/verify", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

var brRe = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)

// sigGap returns the byte span of the /Contents signature blob: the hole
// between the two signed ranges.
func sigGap(t *testing.T, pdf []byte) (int, int) {
	t.Helper()
	m := brRe.FindSubmatch(pdf)
	if m == nil {
		t.Fatal("no /ByteRange in signed PDF")
	}
	a, _ := strconv.Atoi(string(m[1]))
	b, _ := strconv.Atoi(string(m[2]))
	c, _ := strconv.Atoi(string(m[3]))
	return a + b, c
}

// verdict reports whether POST /api/v1/verify accepted the document, plus the
// hash_match it reported. A non-2xx (the parser refusing the file outright) is
// a rejection too.
func verdict(t *testing.T, w *httptest.ResponseRecorder) (valid bool, hashMatch any) {
	t.Helper()
	if w.Code != http.StatusOK {
		return false, nil
	}
	b := jbody(t, w)
	v, _ := b["verification"].(map[string]any)
	if v == nil {
		return false, b["hash_match"]
	}
	ok, _ := v["valid"].(bool)
	return ok, b["hash_match"]
}

// TestTamperMatrix is the acceptance matrix for web verification. Each case
// states what a user actually does to a file and what the verdict must be.
//
//	1. signed file, untouched      -> VERIFIED
//	2. signed file, edited         -> NOT verified
//	3. signature moved onto another document -> NOT verified
//	4. signed file re-saved by a PDF tool ("Save As") -> NOT verified
//	5. signed file renamed         -> STILL verified
func TestTamperMatrix(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")

	// Two independently signed documents: A is the subject, B donates a body
	// for the signature-transplant case.
	pidA := e.reserve(user, d.id)
	docA := e.stampAndSign(user, d, pidA)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pidA+"/document", user, docA), http.StatusOK)

	pidB := e.reserve(user, d.id)
	docB := e.stampAndSign(user, d, pidB)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pidB+"/document", user, docB), http.StatusOK)

	t.Run("1 berkas asli -> TERVERIFIKASI", func(t *testing.T) {
		valid, hm := verdict(t, e.verifyNamed(docA, "surat.pdf"))
		if !valid {
			t.Fatal("an untouched signed document must verify")
		}
		if hm != true {
			t.Fatalf("hash_match = %v, want true", hm)
		}
	})

	t.Run("2 isi diubah -> TIDAK terverifikasi", func(t *testing.T) {
		// Flip a bit well inside the signed range: a real content edit, not
		// an append. The CMS digest covers this, and so does the stored hash.
		gapStart, _ := sigGap(t, docA)
		edited := append([]byte(nil), docA...)
		edited[gapStart/2] ^= 0x20
		valid, hm := verdict(t, e.verifyNamed(edited, "surat.pdf"))
		if valid {
			t.Fatal("an edited document must not verify")
		}
		if hm != nil && hm != false {
			t.Fatalf("hash_match = %v, want false or absent", hm)
		}
	})

	t.Run("3 tanda tangan dipindah ke berkas lain -> TIDAK terverifikasi", func(t *testing.T) {
		// Splice A's signature blob into B, same length, so B stays a
		// structurally valid PDF carrying someone else's signature.
		aStart, aEnd := sigGap(t, docA)
		bStart, bEnd := sigGap(t, docB)
		n := aEnd - aStart
		if m := bEnd - bStart; m < n {
			n = m
		}
		transplant := append([]byte(nil), docB...)
		copy(transplant[bStart:bStart+n], docA[aStart:aStart+n])
		if bytes.Equal(transplant, docB) {
			t.Fatal("transplant produced an unchanged file; the test proves nothing")
		}
		if valid, _ := verdict(t, e.verifyNamed(transplant, "surat.pdf")); valid {
			t.Fatal("a transplanted signature must not verify")
		}
	})

	t.Run("4 disimpan ulang (Save As) -> TIDAK terverifikasi", func(t *testing.T) {
		// What a PDF reader does on "Save As": parse and write back out. The
		// page content is unchanged but the bytes are not the signed ones.
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		var out bytes.Buffer
		if err := pdfcpu.Optimize(bytes.NewReader(docA), &out, conf); err != nil {
			t.Skipf("pdfcpu could not re-save this PDF: %v", err)
		}
		resaved := out.Bytes()
		if bytes.Equal(resaved, docA) {
			t.Skip("re-save produced identical bytes; nothing to test")
		}
		if valid, _ := verdict(t, e.verifyNamed(resaved, "surat.pdf")); valid {
			t.Fatal("a re-saved document must not verify: its bytes are not the signed ones")
		}
	})

	t.Run("5 hanya diganti nama -> TETAP terverifikasi", func(t *testing.T) {
		// Identical bytes, different filename. Verification is over content,
		// so the name must not matter in either direction.
		valid, hm := verdict(t, e.verifyNamed(docA, "LAPORAN-FINAL-revisi-3.pdf"))
		if !valid {
			t.Fatal("renaming a file must not affect its verification")
		}
		if hm != true {
			t.Fatalf("hash_match = %v, want true", hm)
		}
	})
}
