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
}

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
}

// Result is the shared verification JSON (Rencana V1 §11.3).
type Result struct {
	Valid          bool              `json:"valid"`
	DocumentSHA512 string            `json:"document_sha512"`
	Signatures     []SignatureResult `json:"signatures"`
	Errors         []string          `json:"errors,omitempty"`
}

// VerifyPDF verifies every signature in pdf.
func VerifyPDF(pdf []byte, o Options) (*Result, error) {
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
	return res, nil
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
// full trust verification (Rencana V1 §11.1 ListPDFSignatures).
func ListPDFSignatures(pdf []byte) ([]certutil.CertInfo, error) {
	doc, err := pdfsign.Open(bytes.NewReader(pdf), int64(len(pdf)))
	if err != nil {
		return nil, fmt.Errorf("verification: open PDF: %w", err)
	}
	var out []certutil.CertInfo
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
