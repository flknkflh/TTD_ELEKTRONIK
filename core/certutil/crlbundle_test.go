package certutil_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
)

func leafFrom(t *testing.T, ca *labpki.CA) *x509.Certificate {
	t.Helper()
	key, err := keys.GenerateMLDSA65Key()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "d"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	c, err := ca.IssueDeviceCert(csr, labpki.DeviceCertOptions{Subject: pkix.Name{CommonName: "d"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A bundle from an active and a retired Intermediate: each certificate is
// checked against the CRL of its own issuer.
func TestValidateCRLBundle(t *testing.T) {
	root, _ := labpki.NewRootCA("Root", 10*365*24*time.Hour)
	oldInter, _ := labpki.NewIntermediateCA(root, "Old", 5*365*24*time.Hour)
	newInter, _ := labpki.NewIntermediateCA(root, "New", 5*365*24*time.Hour)
	oldLeaf, newLeaf := leafFrom(t, oldInter), leafFrom(t, newInter)

	newCRL, err := newInter.NewCRL([]*big.Int{oldLeaf.SerialNumber}, 3, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCRL, err := oldInter.NewCRL([]*big.Int{oldLeaf.SerialNumber}, 3, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(append([]byte(nil), newCRL...), oldCRL...)
	now := time.Now()

	if st, err := certutil.ValidateCRL(bundle, oldInter.Cert, oldLeaf, now); err != nil || !st.Revoked || !st.SignatureOK {
		t.Fatalf("old leaf via its issuer's CRL: %+v, %v", st, err)
	}
	if st, err := certutil.ValidateCRL(bundle, newInter.Cert, newLeaf, now); err != nil || st.Revoked || !st.SignatureOK {
		t.Fatalf("new leaf via its issuer's CRL: %+v, %v", st, err)
	}
	if st, err := certutil.ValidateCRL(bundle, nil, oldLeaf, now); err != nil || !st.Revoked {
		t.Fatalf("no issuer known: %+v, %v", st, err)
	}
	other, _ := labpki.NewIntermediateCA(root, "Other", 24*time.Hour)
	if _, err := certutil.ValidateCRL(bundle, other.Cert, leafFrom(t, other), now); err == nil {
		t.Fatal("a bundle without the issuer's CRL passed the signature check")
	}
	if crls, err := certutil.ParseCRLs(bundle); err != nil || len(crls) != 2 {
		t.Fatalf("ParseCRLs: %d CRLs, %v", len(crls), err)
	}
	// a single CRL still works
	if st, err := certutil.ValidateCRL(oldCRL, oldInter.Cert, oldLeaf, now); err != nil || !st.Revoked {
		t.Fatalf("single CRL: %+v, %v", st, err)
	}
}
