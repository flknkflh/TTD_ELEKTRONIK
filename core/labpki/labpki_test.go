package labpki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/keys"
)

func TestCertificatesNeverOutliveTheirIssuer(t *testing.T) {
	root, err := NewRootCA("Root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if inter, err := NewIntermediateCA(root, "Long", 20*365*24*time.Hour); err != nil {
		t.Fatal(err)
	} else if inter.Cert.NotAfter.After(root.Cert.NotAfter) {
		t.Fatalf("intermediate NotAfter %s is after the root's %s", inter.Cert.NotAfter, root.Cert.NotAfter)
	}

	inter, err := NewIntermediateCA(root, "Short", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.GenerateMLDSA65Key()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := inter.IssueDeviceCert(csr, DeviceCertOptions{Subject: pkix.Name{CommonName: "device"}, Validity: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(inter.Cert.NotAfter) {
		t.Fatalf("device NotAfter %s is after the intermediate's %s", leaf.NotAfter, inter.Cert.NotAfter)
	}
	if !leaf.NotAfter.Equal(inter.Cert.NotAfter) {
		t.Fatalf("device NotAfter %s, want it capped at the intermediate's %s", leaf.NotAfter, inter.Cert.NotAfter)
	}
}
