// Package verification checks a signed PDF against an explicitly supplied
// Root CA and (optionally) a CRL, and reports the result in the JSON shape
// shared by the Windows client, the Android client, and the server
// (Rencana V1 §11.3, §16).
package verification

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/digitorus/pdfsign"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/hashutil"
)

// Options controls verification.
type Options struct {
	// RootPEM is the trust anchor. Required. A root embedded in the PDF or in
	// the signature chain is never used as an anchor (Rencana V1 §5.3).
	RootPEM []byte
	// IntermediatePEM adds intermediates not carried in the signature.
	IntermediatePEM []byte
	// CRLPEM, if present, is checked offline against the signer certificate.
	CRLPEM []byte
	// RequireMLDSAOnly rejects any non-ML-DSA signature (PQC-only profile).
	RequireMLDSAOnly bool
	// At is the validation time; zero means now.
	At time.Time
	// AllowExternalRevocation lets digitorus/pdfsign fetch OCSP/CRL over the
	// network. Off by default; V1 clients verify offline.
	AllowExternalRevocation bool

	// Timeout bounds how long the parse+verify may run. 0 means no watchdog.
	// A crafted PDF can drive the third-party parser into a CPU-bound loop
	// (see docs/security-findings.md); a network-facing caller MUST set this
	// (the server uses 15s) AND keep upstream rate limiting on. On timeout an
	// error is returned but the parse goroutine may keep running until the
	// process is recycled.
	Timeout time.Duration
}

// MaxPDFBytes is the hard input ceiling for VerifyPDF. Anything larger is
// rejected before the parser sees it.
const MaxPDFBytes = 64 << 20

// SignatureResult mirrors one entry of the shared verification JSON.
type SignatureResult struct {
	Valid                    bool     `json:"valid"`
	Algorithm                string   `json:"algorithm"`
	CertificateSerial        string   `json:"certificate_serial"`
	CertificateFingerprint   string   `json:"certificate_fingerprint"`
	Subject                  string   `json:"subject"`
	TrustedChain             bool     `json:"trusted_chain"`
	Revoked                  bool     `json:"revoked"`
	ClientClaimedSigningTime string   `json:"client_claimed_signing_time"`
	TimestampValid           bool     `json:"timestamp_valid"`
	Warnings                 []string `json:"warnings"`
	Errors                   []string `json:"errors,omitempty"`

	// Reason and Contact are copied from the PDF signature dictionary (inside
	// the signed byte range). The client puts "pqc-public-id:<id>" in Contact
	// so the server can bind a submission to its reservation (§15.2, §15.3).
	Reason  string `json:"reason,omitempty"`
	Contact string `json:"contact,omitempty"`
}

// PublicIDPrefix marks the reservation id the client binds into the CMS
// Contact attribute.
const PublicIDPrefix = "pqc-public-id:"

// PublicID returns the reservation id bound into this signature, or "".
func (s SignatureResult) PublicID() string {
	if len(s.Contact) > len(PublicIDPrefix) && s.Contact[:len(PublicIDPrefix)] == PublicIDPrefix {
		return s.Contact[len(PublicIDPrefix):]
	}
	return ""
}

// Result is the shared verification JSON (Rencana V1 §11.3).
type Result struct {
	Valid          bool              `json:"valid"`
	DocumentSHA512 string            `json:"document_sha512"`
	Signatures     []SignatureResult `json:"signatures"`
	Errors         []string          `json:"errors,omitempty"`
}

// VerifyPDF verifies every signature in pdf. It is hardened for hostile input
// (Rencana V1 §24, §26): oversized input is rejected up front, a panic in the
// third-party PDF/CMS parser becomes an error, and Timeout bounds a parser
// that loops.
func VerifyPDF(pdf []byte, o Options) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("verification: recovered from panic parsing PDF: %v", r)
		}
	}()
	if int64(len(pdf)) > MaxPDFBytes {
		return nil, fmt.Errorf("verification: PDF is %d bytes, over the %d-byte limit", len(pdf), MaxPDFBytes)
	}
	if o.Timeout <= 0 {
		return verifyPDF(pdf, o)
	}
	type out struct {
		res *Result
		err error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- out{nil, fmt.Errorf("verification: recovered from panic parsing PDF: %v", r)}
			}
		}()
		r, e := verifyPDF(pdf, o)
		ch <- out{r, e}
	}()
	select {
	case v := <-ch:
		return v.res, v.err
	case <-time.After(o.Timeout):
		return nil, fmt.Errorf("verification: gave up after %s (malformed PDF?)", o.Timeout)
	}
}

func verifyPDF(pdf []byte, o Options) (*Result, error) {
	if len(pdf) == 0 {
		return nil, errors.New("verification: empty PDF input")
	}
	if len(o.RootPEM) == 0 {
		return nil, errors.New("verification: RootPEM (explicit trust anchor) is required")
	}
	at := o.At
	if at.IsZero() {
		at = time.Now()
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(o.RootPEM) {
		return nil, errors.New("verification: no valid certificates in RootPEM")
	}

	res := &Result{DocumentSHA512: hashutil.CalculateSHA512(pdf)}

	doc, err := pdfsign.Open(bytes.NewReader(pdf), int64(len(pdf)))
	if err != nil {
		return nil, fmt.Errorf("verification: open PDF: %w", err)
	}

	vb := doc.Verify().
		TrustedRoots(roots).
		ValidateFullChain(true).
		AtTime(at)
	if o.RequireMLDSAOnly {
		vb.AllowedAlgorithms(x509.MLDSA)
	}
	if o.AllowExternalRevocation {
		vb.ExternalChecks(true)
	} else {
		// Offline: PAdES-B embeds no revocation data. Revocation is handled
		// separately below via the supplied CRL.
		vb.SkipRevocationCheck(true)
	}

	if err := vb.Err(); err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res, nil
	}

	sigs := vb.Signatures()
	if len(sigs) == 0 {
		res.Errors = append(res.Errors, "no processable signatures found")
		return res, nil
	}

	// Parse any caller-supplied intermediates once.
	var extraInter []*x509.Certificate
	if len(o.IntermediatePEM) > 0 {
		extraInter, _ = certutil.ParseChainPEM(o.IntermediatePEM)
	}

	allValid := true
	for _, s := range sigs {
		sr := SignatureResult{
			Valid:          s.Valid,
			TrustedChain:   s.TrustedChain,
			Revoked:        s.Revoked,
			TimestampValid: s.TimestampValid,
			Reason:         s.Reason,
			Contact:        s.Contact,
			Warnings:       errStrings(s.Warnings),
			Errors:         errStrings(s.Errors),
		}
		if !s.SigningTime.IsZero() {
			sr.ClientClaimedSigningTime = s.SigningTime.Format(time.RFC3339)
		}
		if s.Certificate != nil {
			c := s.Certificate
			sr.Subject = c.Subject.String()
			sr.CertificateSerial = fmt.Sprintf("%x", c.SerialNumber)
			sr.CertificateFingerprint = certutil.FingerprintSHA256(c)
			sr.Algorithm = algorithmName(c)

			if o.RequireMLDSAOnly && !certutil.IsMLDSA(c) {
				sr.Valid = false
				sr.Errors = append(sr.Errors, "signer certificate is not ML-DSA (PQC-only profile)")
			}

			// Offline CRL check (Rencana V1 §16.1).
			if len(o.CRLPEM) > 0 {
				issuer := crlIssuerFor(c, extraInter)
				st, err := certutil.ValidateCRL(o.CRLPEM, issuer, c, at)
				switch {
				case err != nil:
					sr.Warnings = append(sr.Warnings, "CRL check failed: "+err.Error())
				case st.Revoked:
					sr.Revoked = true
					sr.Valid = false
					sr.Errors = append(sr.Errors, "signer certificate is revoked (CRL)")
				case st.Stale:
					sr.Warnings = append(sr.Warnings, "CRL is stale (past nextUpdate "+st.NextUpdate.Format(time.RFC3339)+")")
				}
			}
		} else {
			sr.Valid = false
			sr.Errors = append(sr.Errors, "no signer certificate in signature")
		}

		if sr.Warnings == nil {
			sr.Warnings = []string{}
		}
		if !sr.Valid {
			allValid = false
		}
		res.Signatures = append(res.Signatures, sr)
	}
	res.Valid = allValid && len(res.Errors) == 0

	// Whole-document coverage: the signature must cover the file to its end.
	// Bytes appended after the signed /ByteRange (a barcode added via an
	// incremental update, a shadow-attack overlay) are NOT covered by the
	// ML-DSA signature, yet the CMS check over the byte range still passes --
	// digitorus/pdfsign only reads what /ByteRange names, and its own
	// incremental-update detection fires only for a certification (DocMDP)
	// signature, which ours (ETSI.CAdES.detached, approval) is not.
	if end := signedRangeEnd(pdf); end >= 0 && !tailIsBenign(pdf, end) {
		res.Valid = false
		for i := range res.Signatures {
			res.Signatures[i].Valid = false
			res.Signatures[i].Errors = append(res.Signatures[i].Errors,
				"dokumen diubah setelah ditandatangani: ada konten yang ditambahkan setelah rentang byte bertanda tangan")
		}
		res.Errors = append(res.Errors,
			"dokumen diubah setelah ditandatangani: ada byte di luar rentang yang ditandatangani "+
				"(konten ditambahkan, atau berkas disimpan ulang oleh aplikasi lain)")
	}
	return res, nil
}

// byteRangeRe matches the /ByteRange array of a signature dictionary. The
// array is always cleartext in the PDF -- it sits outside the /Contents hex
// string, and a signer cannot compress the dictionary that names its own
// signed span -- so scanning for it is safe and parser-independent.
var byteRangeRe = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)

// signedRangeEnd returns the byte offset where the LAST signature's
// /ByteRange ends (start2 + len2), or -1 when no parsable ByteRange is found.
// "Last" is by file position, which for incremental-update multi-signing is
// the outermost signature -- the one that covers the most of the file.
//
// LIMIT: if an incremental update is written with a cross-reference stream and
// its signature dictionary lives inside a compressed object stream, the array
// is not cleartext and this scan misses it. Tools that append a barcode or an
// annotation the ordinary way keep /ByteRange in the clear, so this covers the
// realistic case; the stored-hash comparison in the server's verify handler
// (docs/CHANGE-hash-verification.md) closes the remainder.
func signedRangeEnd(pdf []byte) int64 {
	m := byteRangeRe.FindAllSubmatch(pdf, -1)
	if len(m) == 0 {
		return -1
	}
	last := m[len(m)-1]
	start2, err1 := strconv.ParseInt(string(last[3]), 10, 64)
	len2, err2 := strconv.ParseInt(string(last[4]), 10, 64)
	if err1 != nil || err2 != nil || start2 < 0 || len2 < 0 {
		return -1
	}
	return start2 + len2
}

// tailIsBenign reports whether everything after off is only whitespace and at
// most one trailing "%%EOF" marker -- i.e. the signer's own final bytes, not
// an appended incremental update.
func tailIsBenign(pdf []byte, off int64) bool {
	if off < 0 || off > int64(len(pdf)) {
		return false
	}
	tail := bytes.TrimSpace(pdf[off:])
	tail = bytes.TrimSuffix(tail, []byte("%%EOF"))
	return len(bytes.TrimSpace(tail)) == 0
}

// VerifyPDFJSON is the gomobile-friendly entry point matching mobilebridge:
// it takes root and CRL PEM and returns the marshalled Result.
func VerifyPDFJSON(pdf, rootPEM, crlPEM []byte) (string, error) {
	res, err := VerifyPDF(pdf, Options{
		RootPEM:          rootPEM,
		CRLPEM:           crlPEM,
		RequireMLDSAOnly: true,
	})
	if err != nil {
		return "", err
	}
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ListPDFSignatures returns a light summary of each signature without running
// full trust verification (Rencana V1 §11.1 ListPDFSignatures). Panic-safe
// like VerifyPDF.
func ListPDFSignatures(pdf []byte) (out []certutil.CertInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("verification: recovered from panic parsing PDF: %v", r)
		}
	}()
	doc, oerr := pdfsign.Open(bytes.NewReader(pdf), int64(len(pdf)))
	if oerr != nil {
		return nil, fmt.Errorf("verification: open PDF: %w", oerr)
	}
	for _, s := range doc.Verify().TrustSelfSigned(true).SkipRevocationCheck(true).Signatures() {
		if s.Certificate != nil {
			out = append(out, certutil.Describe(s.Certificate))
		}
	}
	return out, nil
}

func algorithmName(c *x509.Certificate) string {
	if certutil.IsMLDSA(c) {
		return "ML-DSA-65"
	}
	return c.PublicKeyAlgorithm.String()
}

func errStrings(errs []error) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		if e != nil {
			out = append(out, e.Error())
		}
	}
	return out
}

// crlIssuerFor picks the certificate that should have signed the CRL: the
// first supplied intermediate whose subject matches the signer's issuer.
func crlIssuerFor(signer *x509.Certificate, intermediates []*x509.Certificate) *x509.Certificate {
	for _, c := range intermediates {
		if c.Subject.String() == signer.Issuer.String() {
			return c
		}
	}
	return nil
}
