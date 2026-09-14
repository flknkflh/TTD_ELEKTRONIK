package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
)

const (
	rootPass  = "root passphrase for split CA tests"
	interPass = "intermediate passphrase for split CA tests"
)

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func splitEnv(t *testing.T) {
	t.Setenv("PQC_CA_PASSPHRASE", "")
	t.Setenv("PQC_CA_ROOT_PASSPHRASE", rootPass)
	t.Setenv("PQC_CA_INTERMEDIATE_PASSPHRASE", interPass)
	t.Setenv("PQC_CA_ROOT_PASSPHRASE_FILE", "")
	t.Setenv("PQC_CA_INTERMEDIATE_PASSPHRASE_FILE", "")
}

// splitCA runs the mode-B flow through the real commands: Root, issuer CSR,
// Root signs, issuer installs. It returns the Root and issuer directories.
func splitCA(t *testing.T) (rootDir, issuerDir string) {
	t.Helper()
	splitEnv(t)
	base := t.TempDir()
	rootDir, issuerDir = filepath.Join(base, "root"), filepath.Join(base, "issuer")
	csr, crt := filepath.Join(base, "inter.csr.pem"), filepath.Join(base, "inter.crt.pem")
	mustOK(t, cmdInitRoot([]string{"--dir", rootDir, "--root-cn", "Split Root"}))
	mustOK(t, cmdIntermediateCSR([]string{"--dir", issuerDir, "--inter-cn", "ignored by the Root", "--out", csr}))
	mustOK(t, cmdSignIntermediate([]string{"--dir", rootDir, "--csr", csr, "--inter-cn", "Split Issuer", "--out", crt}))
	mustOK(t, cmdInstallIntermediate([]string{"--dir", issuerDir, "--cert", crt,
		"--root-cert", filepath.Join(rootDir, "public", "root-ca.crt.pem")}))
	return rootDir, issuerDir
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// The issuer issues, revokes and publishes CRLs with no Root key and without
// the Root passphrase, and its chain verifies to the offline Root.
func TestSplitCAIssuesWithoutRootKey(t *testing.T) {
	rootDir, issuerDir := splitCA(t)
	t.Setenv("PQC_CA_ROOT_PASSPHRASE", "")

	if exists(filepath.Join(issuerDir, "root", "key.pem")) || exists(filepath.Join(issuerDir, "root", "key.pem.enc")) {
		t.Fatal("issuer directory holds a Root private key")
	}
	rootPEM := mustRead(t, filepath.Join(rootDir, "public", "root-ca.crt.pem"))
	if !bytes.Equal(mustRead(t, filepath.Join(issuerDir, "public", "root-ca.crt.pem")), rootPEM) {
		t.Fatal("issuer publishes a different Root certificate")
	}

	sk, _ := keys.GenerateMLDSA65Key()
	keyPEM, _ := keys.MarshalPKCS8PEM(sk)
	csrPEM, err := enrollment.CreateDeviceCSR(keyPEM, enrollment.Request{CommonName: "device"})
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	csrPath, out := filepath.Join(work, "d.csr.pem"), filepath.Join(work, "d.crt.pem")
	mustOK(t, os.WriteFile(csrPath, csrPEM, 0o600))
	mustOK(t, cmdIssue([]string{"--dir", issuerDir, "--csr", csrPath, "--account", "a@x", "--device", "Laptop", "--cn", "Budi", "--out", out}))

	leaf, err := certutil.ParseCertificatePEM(mustRead(t, out))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := certutil.ParseChainPEM(mustRead(t, filepath.Join(issuerDir, "public", "ca-chain.pem")))
	if err != nil || len(chain) != 2 {
		t.Fatalf("ca-chain.pem: %v (%d certs)", err, len(chain))
	}
	if res := certutil.ValidateCertificateChain(leaf, chain, rootPEM, time.Now()); res.Error != nil || !res.TrustedChain {
		t.Fatalf("device cert does not chain to the offline Root: %+v", res)
	}
	if chain[0].Subject.CommonName != "Split Issuer" {
		t.Fatalf("Intermediate CN = %q, want the Root operator's %q", chain[0].Subject.CommonName, "Split Issuer")
	}

	mustOK(t, cmdRevoke([]string{"--dir", issuerDir, "--serial", certSerialHex(leaf), "--reason", "keyCompromise"}))
	mustOK(t, cmdCRL([]string{"--dir", issuerDir}))
	st, err := certutil.ValidateCRL(mustRead(t, filepath.Join(issuerDir, "public", "crl.pem")), chain[0], leaf, time.Now())
	if err != nil || !st.Revoked {
		t.Fatalf("CRL from the issuer: revoked=%v err=%v", st.Revoked, err)
	}
	mustOK(t, cmdStatus([]string{"--dir", issuerDir}))
}

func TestSplitCAPassphrasesAreSeparate(t *testing.T) {
	rootDir, issuerDir := splitCA(t)

	if _, err := (Store{Dir: rootDir, Passphrase: interPass}).Root(); err == nil {
		t.Fatal("the Intermediate passphrase opened the Root key")
	}
	if _, err := (Store{Dir: issuerDir, Passphrase: rootPass}).Intermediate(); err == nil {
		t.Fatal("the Root passphrase opened the Intermediate key")
	}

	// split commands refuse the legacy single passphrase
	t.Setenv("PQC_CA_ROOT_PASSPHRASE", "")
	t.Setenv("PQC_CA_PASSPHRASE", rootPass)
	if err := cmdInitRoot([]string{"--dir", filepath.Join(t.TempDir(), "r2")}); err == nil {
		t.Fatal("init-root accepted PQC_CA_PASSPHRASE")
	}

	// issuer commands never read the Root passphrase
	t.Setenv("PQC_CA_PASSPHRASE", "")
	t.Setenv("PQC_CA_INTERMEDIATE_PASSPHRASE", "")
	t.Setenv("PQC_CA_ROOT_PASSPHRASE", interPass)
	if _, err := open(issuerDir); err == nil {
		t.Fatal("issuer opened with only the Root passphrase variable set")
	}

	// too short
	t.Setenv("PQC_CA_ROOT_PASSPHRASE", "short")
	if err := cmdInitRoot([]string{"--dir", filepath.Join(t.TempDir(), "r3")}); err == nil {
		t.Fatal("init-root accepted a short passphrase")
	}
}

func TestPassphraseFromFile(t *testing.T) {
	splitEnv(t)
	f := filepath.Join(t.TempDir(), "secret")
	mustOK(t, os.WriteFile(f, []byte(interPass+"\n"), 0o600))
	t.Setenv("PQC_CA_INTERMEDIATE_PASSPHRASE", "")
	t.Setenv("PQC_CA_INTERMEDIATE_PASSPHRASE_FILE", f)
	if p, err := passphraseFor(roleIntermediate); err != nil || p != interPass {
		t.Fatalf("passphrase from file = %q, %v", p, err)
	}
	mustOK(t, os.WriteFile(f, nil, 0o600))
	if _, err := passphraseFor(roleIntermediate); err == nil {
		t.Fatal("empty passphrase file accepted")
	}
}

func TestInstallIntermediateRejects(t *testing.T) {
	splitEnv(t)
	base := t.TempDir()
	p := func(name string) string { return filepath.Join(base, name) }
	rootCert := filepath.Join(p("root"), "public", "root-ca.crt.pem")
	install := func(cert string) error {
		return cmdInstallIntermediate([]string{"--dir", p("issuer"), "--cert", cert, "--root-cert", rootCert})
	}

	mustOK(t, cmdInitRoot([]string{"--dir", p("root")}))
	mustOK(t, cmdInitRoot([]string{"--dir", p("other-root")}))
	mustOK(t, cmdIntermediateCSR([]string{"--dir", p("issuer"), "--out", p("i.csr")}))
	mustOK(t, cmdIntermediateCSR([]string{"--dir", p("issuer2"), "--out", p("i2.csr")}))

	// signed by another Root
	mustOK(t, cmdSignIntermediate([]string{"--dir", p("other-root"), "--csr", p("i.csr"), "--inter-cn", "X", "--out", p("wrong-root.crt")}))
	if err := install(p("wrong-root.crt")); err == nil || !strings.Contains(err.Error(), "not signed by this Root") {
		t.Fatalf("certificate from another Root: err = %v", err)
	}
	// right Root, but for another issuer's key
	mustOK(t, cmdSignIntermediate([]string{"--dir", p("root"), "--csr", p("i2.csr"), "--inter-cn", "X", "--out", p("other-key.crt")}))
	if err := install(p("other-key.crt")); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("certificate for another key: err = %v", err)
	}
	// wrong Root passphrase cannot sign
	t.Setenv("PQC_CA_ROOT_PASSPHRASE", "not the root passphrase at all")
	if err := cmdSignIntermediate([]string{"--dir", p("root"), "--csr", p("i.csr"), "--inter-cn", "X", "--out", p("nope.crt")}); err == nil {
		t.Fatal("signed with a wrong Root passphrase")
	}
	t.Setenv("PQC_CA_ROOT_PASSPHRASE", rootPass)
	mustOK(t, cmdSignIntermediate([]string{"--dir", p("root"), "--csr", p("i.csr"), "--inter-cn", "Issuer", "--out", p("good.crt")}))

	// a Root key placed in the issuer directory is refused
	mustOK(t, os.MkdirAll(filepath.Join(p("issuer"), "root"), 0o700))
	mustOK(t, os.WriteFile(filepath.Join(p("issuer"), "root", "key.pem.enc"), mustRead(t, filepath.Join(p("root"), "root", "key.pem.enc")), 0o600))
	if err := install(p("good.crt")); err == nil || err != errRootKeyOnIssuer {
		t.Fatalf("Root key on the issuer: err = %v", err)
	}
	mustOK(t, os.Remove(filepath.Join(p("issuer"), "root", "key.pem.enc")))

	mustOK(t, install(p("good.crt")))
	if err := install(p("good.crt")); err == nil {
		t.Fatal("a second install replaced the Intermediate")
	}
	if err := cmdIntermediateCSR([]string{"--dir", p("issuer")}); err == nil {
		t.Fatal("intermediate-csr replaced an installed Intermediate")
	}
}
