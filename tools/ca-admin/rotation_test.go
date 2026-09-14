package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
)

// An installed Intermediate is replaced only by an explicit rotation; the old
// one retires into the chain and CRL bundle, so certificates on both sides of
// the rotation chain to the Root and stay revocable.
func TestIntermediateRotation(t *testing.T) {
	rootDir, issuerDir := splitCA(t)
	rootCert := filepath.Join(rootDir, "public", "root-ca.crt.pem")
	rootPEM := mustRead(t, rootCert)
	work := t.TempDir()
	n := 0
	issue := func() *x509.Certificate {
		t.Helper()
		n++
		sk, _ := keys.GenerateMLDSA65Key()
		keyPEM, _ := keys.MarshalPKCS8PEM(sk)
		csrPEM, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "device"})
		if err != nil {
			t.Fatal(err)
		}
		csr, out := filepath.Join(work, "d.csr"), filepath.Join(work, "d.crt")
		mustOK(t, os.WriteFile(csr, csrPEM, 0o600))
		mustOK(t, cmdIssue([]string{"--dir", issuerDir, "--csr", csr, "--account", "a@x", "--device", "D", "--cn", "Budi", "--out", out}))
		c, err := certutil.ParseCertificatePEM(mustRead(t, out))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	issuer := Store{Dir: issuerDir, Passphrase: interPass}

	oldLeaf := issue()
	oldInter, err := issuer.Intermediate()
	if err != nil {
		t.Fatal(err)
	}

	// no accidental replacement
	if err := cmdIntermediateCSR([]string{"--dir", issuerDir}); err == nil {
		t.Fatal("intermediate-csr without --next replaced the installed Intermediate")
	}
	mustOK(t, cmdIntermediateCSR([]string{"--dir", issuerDir, "--next", "--out", filepath.Join(work, "next.csr")}))
	if err := cmdIntermediateCSR([]string{"--dir", issuerDir, "--next"}); err == nil {
		t.Fatal("a second rotation request replaced the pending one")
	}
	mustOK(t, cmdSignIntermediate([]string{"--dir", rootDir, "--csr", filepath.Join(work, "next.csr"),
		"--inter-cn", "Split Issuer 2", "--out", filepath.Join(work, "next.crt")}))
	install := []string{"--dir", issuerDir, "--cert", filepath.Join(work, "next.crt"), "--root-cert", rootCert}
	if err := cmdInstallIntermediate(install); err == nil {
		t.Fatal("installed over the current Intermediate without --rotate")
	}
	mustOK(t, cmdInstallIntermediate(append(install, "--rotate")))
	if _, err := os.Stat(filepath.Join(issuerDir, nextDir)); err == nil {
		t.Fatal("next/ left behind after the rotation")
	}

	newInter, err := issuer.Intermediate()
	if err != nil {
		t.Fatal(err)
	}
	if newInter.Cert.Equal(oldInter.Cert) || newInter.Cert.Subject.CommonName != "Split Issuer 2" {
		t.Fatalf("active Intermediate after rotation: %s", newInter.Cert.Subject)
	}
	chain, err := certutil.ParseChainPEM(mustRead(t, filepath.Join(issuerDir, "public", "ca-chain.pem")))
	if err != nil || len(chain) != 3 || !chain[0].Equal(newInter.Cert) || !chain[1].Equal(oldInter.Cert) {
		t.Fatalf("ca-chain.pem after rotation: %d certs, err %v", len(chain), err)
	}

	newLeaf := issue()
	if err := newLeaf.CheckSignatureFrom(newInter.Cert); err != nil {
		t.Fatalf("a certificate issued after the rotation is not from the new Intermediate: %v", err)
	}
	for name, leaf := range map[string]*x509.Certificate{"old": oldLeaf, "new": newLeaf} {
		if res := certutil.ValidateCertificateChain(leaf, chain, rootPEM, time.Now()); res.Error != nil || !res.TrustedChain {
			t.Fatalf("%s device certificate does not chain to the Root: %+v", name, res)
		}
	}

	// the old certificate stays revocable through the retired Intermediate's CRL
	mustOK(t, cmdRevoke([]string{"--dir", issuerDir, "--serial", certSerialHex(oldLeaf), "--reason", "keyCompromise"}))
	mustOK(t, cmdCRL([]string{"--dir", issuerDir}))
	bundle := mustRead(t, filepath.Join(issuerDir, "public", "crl.pem"))
	if n := strings.Count(string(bundle), "BEGIN X509 CRL"); n != 2 {
		t.Fatalf("CRL bundle has %d CRLs, want 2 (active + retired)", n)
	}
	if st, err := certutil.ValidateCRL(bundle, oldInter.Cert, oldLeaf, time.Now()); err != nil || !st.Revoked || !st.SignatureOK {
		t.Fatalf("old certificate via the retired Intermediate's CRL: %+v, %v", st, err)
	}
	if st, err := certutil.ValidateCRL(bundle, newInter.Cert, newLeaf, time.Now()); err != nil || st.Revoked || !st.SignatureOK {
		t.Fatalf("new certificate via the active CRL: %+v, %v", st, err)
	}
	if st, err := certutil.ValidateCRL(bundle, nil, oldLeaf, time.Now()); err != nil || !st.Revoked {
		t.Fatalf("bundle without a known issuer: %+v, %v", st, err)
	}
	mustOK(t, cmdStatus([]string{"--dir", issuerDir}))
}
