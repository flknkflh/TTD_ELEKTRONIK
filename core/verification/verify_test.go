package verification_test

import (
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/verification"
)

func verifyFixture(t *testing.T, fx fixture, pdf []byte) *verification.Result {
	t.Helper()
	res, err := verification.VerifyPDF(pdf, verification.Options{
		RootPEM: fx.rootPEM, IntermediatePEM: fx.interPEM, CRLPEM: fx.crlPEM,
		RequireMLDSAOnly: true, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("VerifyPDF: %v", err)
	}
	return res
}

func hasTamperError(res *verification.Result) bool {
	for _, e := range res.Errors {
		if strings.Contains(e, "diubah setelah ditandatangani") {
			return true
		}
	}
	return false
}

// TestVerify_AcceptsUntouchedPDF is the control: the valid path must stay
// green, otherwise the coverage rule below proves nothing.
func TestVerify_AcceptsUntouchedPDF(t *testing.T) {
	fx := buildFixture(t)
	res := verifyFixture(t, fx, fx.signedPDF)
	if !res.Valid {
		t.Fatalf("untouched signed PDF must verify: errors=%v sigs=%+v", res.Errors, res.Signatures)
	}
}

// TestVerify_RejectsAppendedBytes covers the real attack: the ML-DSA signature
// stays cryptographically valid over its own /ByteRange, so only the coverage
// check can catch content appended by an incremental update.
func TestVerify_RejectsAppendedBytes(t *testing.T) {
	fx := buildFixture(t)
	tampered := append(append([]byte(nil), fx.signedPDF...), []byte("\n1 0 obj<<>>endobj\n")...)

	res := verifyFixture(t, fx, tampered)
	if res.Valid {
		t.Fatalf("a PDF with bytes appended after the signed range must be invalid")
	}
	if !hasTamperError(res) {
		t.Fatalf("expected a tamper error, got %v", res.Errors)
	}
	for i, s := range res.Signatures {
		if s.Valid {
			t.Fatalf("signature %d must be marked invalid too", i)
		}
	}
}

// TestVerify_RejectsAppendedIncrementalUpdate uses a shape closer to what a
// stamping tool emits: a whole trailer + %%EOF appended after the signed one.
// Such a tail may be rejected two ways -- the PDF parser can refuse the second
// cross-reference section outright, or, when it parses, the coverage check
// catches it. Either is a rejection; the test asserts the document never comes
// back valid. (A genuine tool-written incremental update, which always parses,
// is exercised end-to-end in the server package where pdfcpu is available.)
func TestVerify_RejectsAppendedIncrementalUpdate(t *testing.T) {
	fx := buildFixture(t)
	update := "\n9 0 obj\n<< /Type /Annot >>\nendobj\ntrailer\n<< /Prev 100 >>\nstartxref\n123\n%%EOF\n"
	tampered := append(append([]byte(nil), fx.signedPDF...), []byte(update)...)

	res, err := verification.VerifyPDF(tampered, verification.Options{
		RootPEM: fx.rootPEM, IntermediatePEM: fx.interPEM, CRLPEM: fx.crlPEM,
		RequireMLDSAOnly: true, Timeout: 10 * time.Second,
	})
	if err != nil {
		return // parser refused it before verification -- still a rejection
	}
	if res.Valid || !hasTamperError(res) {
		t.Fatalf("appended incremental update must be rejected: valid=%v errors=%v", res.Valid, res.Errors)
	}
}

// TestVerify_AcceptsTrailingWhitespace: the signer's own final bytes are
// whitespace and at most one %%EOF. Those must not read as tampering, or every
// genuine document would fail.
func TestVerify_AcceptsTrailingWhitespace(t *testing.T) {
	fx := buildFixture(t)
	for _, tc := range []struct{ name, tail string }{
		{"newlines", "\n\n"},
		{"eof marker", "%%EOF\n"},
		{"eof with padding", "\n%%EOF\n  \n"},
		{"spaces and tabs", " \t\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pdf := append(append([]byte(nil), fx.signedPDF...), []byte(tc.tail)...)
			res := verifyFixture(t, fx, pdf)
			if !res.Valid {
				t.Fatalf("trailing %q must stay valid: errors=%v", tc.tail, res.Errors)
			}
		})
	}
}
