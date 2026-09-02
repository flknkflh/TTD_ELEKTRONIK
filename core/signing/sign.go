// Package signing produces PAdES-B ML-DSA-65 signatures over a PDF, entirely
// on the client. It never contacts the network and never writes key material
// anywhere (Rencana V1 §4, §11.2, §15.2).
package signing

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/digitorus/pdfsign"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/keys"
)

// Options configures one signature.
type Options struct {
	Reason          string  `json:"reason,omitempty"`
	Location        string  `json:"location,omitempty"`
	SignerName      string  `json:"signer_name,omitempty"`
	PublicID        string  `json:"public_id,omitempty"`        // reservation id (Rencana V1 §15.1)
	VerificationURL string  `json:"verification_url,omitempty"` // encoded in the QR
	IncludeQR       bool    `json:"include_qr,omitempty"`
	Page            int     `json:"page,omitempty"` // 1-based; 0 -> page 1
	X               float64 `json:"x,omitempty"`
	Y               float64 `json:"y,omitempty"`

	// ClaimedSigningTime is written into the appearance. It is the client's
	// clock and is NOT a trusted timestamp (Rencana V1 §4). Zero -> now.
	ClaimedSigningTime time.Time `json:"client_claimed_signing_time,omitempty"`
}

// Result is returned alongside the signed PDF bytes.
type Result struct {
	SignedPDF          []byte    `json:"-"`
	OriginalSHA512     string    `json:"original_sha512"`
	SignedSHA512       string    `json:"signed_pdf_sha512"`
	Algorithm          string    `json:"algorithm"`
	PDFProfile         string    `json:"pdf_profile"`
	CertificateSerial  string    `json:"certificate_serial"`
	CertificateFP      string    `json:"certificate_fingerprint_sha256"`
	PublicID           string    `json:"public_id,omitempty"`
	ClaimedSigningTime time.Time `json:"client_claimed_signing_time"`
}

// SignPDF signs pdf with the device key and certificate chain.
//
//   - privateKeyPKCS8: the device ML-DSA-65 key (PKCS#8), just unwrapped by the
//     platform layer for this one operation.
//   - certChainPEM: leaf certificate first, then intermediates (root optional).
//
// The signature is PAdES Baseline-B, digest SHA-512, per the V1 crypto
// profile. No timestamp is added in V1 (Rencana V1 §4).
func SignPDF(pdf, privateKeyPKCS8, certChainPEM []byte, o Options) (*Result, error) {
	if len(pdf) == 0 {
		return nil, errors.New("signing: empty PDF input")
	}
	sk, err := keys.ParsePKCS8(privateKeyPKCS8)
	if err != nil {
		return nil, err
	}
	chain, err := certutil.ParseChainPEM(certChainPEM)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	intermediates := chain[1:]

	if !certutil.IsMLDSA(leaf) {
		return nil, fmt.Errorf("signing: leaf certificate is %s, want ML-DSA", leaf.PublicKeyAlgorithm)
	}
	if !keys.SameKeyPair(sk, leaf.PublicKey) {
		return nil, errors.New("signing: certificate public key does not match the device private key")
	}
	if !certutil.HasDocumentSigningEKU(leaf) {
		return nil, errors.New("signing: leaf certificate lacks id-kp-documentSigning EKU")
	}

	claimed := o.ClaimedSigningTime
	if claimed.IsZero() {
		claimed = time.Now()
	}

	doc, err := pdfsign.Open(bytes.NewReader(pdf), int64(len(pdf)))
	if err != nil {
		return nil, fmt.Errorf("signing: open PDF: %w", err)
	}

	app, err := BuildSignatureAppearance(leaf, o)
	if err != nil {
		return nil, err
	}

	page := o.Page
	if page <= 0 {
		page = 1
	}
	x, y := o.X, o.Y
	if x == 0 && y == 0 {
		x, y = 40, 40 // bottom-left margin
	}

	signerName := o.SignerName
	if signerName == "" {
		signerName = leaf.Subject.CommonName
	}

	b := doc.Sign(sk, leaf, intermediates...).
		Format(pdfsign.PAdES_B).
		Digest(crypto.SHA512).
		SignerName(signerName).
		Appearance(app, x, y).
		Page(page)
	if o.Reason != "" {
		b.Reason(o.Reason)
	}
	if o.Location != "" {
		b.Location(o.Location)
	}
	// Bind the public transaction id into the signed byte range via Contact
	// (a CMS signed attribute) in addition to the visible appearance
	// (Rencana V1 §15.2). Full /Info metadata binding is a later step.
	if o.PublicID != "" {
		b.Contact("pqc-public-id:" + o.PublicID)
	}

	var out bytes.Buffer
	if _, err := doc.Write(&out); err != nil {
		return nil, fmt.Errorf("signing: write signed PDF: %w", err)
	}

	return &Result{
		SignedPDF:          out.Bytes(),
		OriginalSHA512:     hashutil.CalculateSHA512(pdf),
		SignedSHA512:       hashutil.CalculateSHA512(out.Bytes()),
		Algorithm:          keys.Algorithm,
		PDFProfile:         "PAdES_B",
		CertificateSerial:  fmt.Sprintf("%x", leaf.SerialNumber),
		CertificateFP:      certutil.FingerprintSHA256(leaf),
		PublicID:           o.PublicID,
		ClaimedSigningTime: claimed,
	}, nil
}

// SignPDFFromJSON is the gomobile-friendly entry point: options are a JSON
// object matching Options, and the result is the signed PDF bytes.
func SignPDFFromJSON(pdf, privateKeyPKCS8, certChainPEM []byte, optionsJSON string) ([]byte, error) {
	var o Options
	if optionsJSON != "" {
		if err := json.Unmarshal([]byte(optionsJSON), &o); err != nil {
			return nil, fmt.Errorf("signing: decode options JSON: %w", err)
		}
	}
	res, err := SignPDF(pdf, privateKeyPKCS8, certChainPEM, o)
	if err != nil {
		return nil, err
	}
	return res.SignedPDF, nil
}
