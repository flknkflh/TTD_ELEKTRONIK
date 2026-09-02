package verification_test

import (
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/verification"
)

// TestOversizedRejected: input past MaxPDFBytes is refused before the parser
// ever runs (Rencana V1 §24, §26).
func TestOversizedRejected(t *testing.T) {
	big := make([]byte, verification.MaxPDFBytes+1)
	copy(big, "%PDF-1.7\n")
	_, err := verification.VerifyPDF(big, verification.Options{RootPEM: []byte("x"), Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("want size-limit error, got %v", err)
	}
}

// TestMalformedNeverPanics: a spread of broken inputs all return an error
// (never a panic, never valid).
func TestMalformedNeverPanics(t *testing.T) {
	fx := buildFixture(t)
	inputs := [][]byte{
		nil,
		[]byte("%PDF-"),
		[]byte("%PDF-1.7\nnot really"),
		[]byte("\x00\x00\x00\x00"),
		[]byte(strings.Repeat("%PDF-1.7 trailer <<>> ", 500)),
		append([]byte("%PDF-1.7\n"), make([]byte, 4096)...),
	}
	for i, in := range inputs {
		res, err := verification.VerifyPDF(in, verification.Options{
			RootPEM: fx.rootPEM, RequireMLDSAOnly: true, Timeout: 3 * time.Second,
		})
		if err == nil && (res == nil || res.Valid) {
			t.Fatalf("input %d: err=nil and result missing/valid", i)
		}
	}
}
