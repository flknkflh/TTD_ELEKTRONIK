package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
)

// Split CA (production mode B). The Root lives only in an offline or ephemeral
// environment; the Intermediate key is generated where it is used — the online
// issuer — and never leaves it. The Root only ever sees the Intermediate's CSR.
//
//	Root env   init-root                       <root>/root/{key.pem.enc,cert.pem}  public/root-ca.crt.pem
//	issuer     intermediate-csr                <issuer>/intermediate/{key.pem.enc,request.csr.pem}
//	Root env   sign-intermediate               CSR -> Intermediate certificate (CA:TRUE, pathlen:0)
//	issuer     install-intermediate            -> a CA directory without root/key.pem*; issue,
//	                                              batch-issue, revoke, crl, status, backup work as usual
//
// Rotation, on the issuer:
//
//	intermediate-csr --next          next/{key.pem.enc,request.csr.pem}
//	install-intermediate --rotate    intermediate/ -> retired/<serial>/, next/ -> intermediate/
//
// A retired Intermediate stays in ca-chain.pem and keeps signing its own CRL
// (crl publishes a bundle) while it is valid: certificates it issued may still
// be in use. Device certificates never outlive their issuer, so once it has
// expired its key is deleted by the next crl.
//
// The two keys are sealed under different passphrases (passphrase.go).

const (
	pendingCSR = "request.csr.pem"
	nextDir    = "next"
	retiredDir = "retired"
)

var errRootKeyOnIssuer = errors.New("ca-admin: this directory holds a Root private key; an online issuer must never have one")

// IntermediateRecord is one line of intermediates.jsonl in a Root directory.
type IntermediateRecord struct {
	Serial      string    `json:"serial"`
	Subject     string    `json:"subject"`
	Fingerprint string    `json:"fingerprint_sha256"`
	NotAfter    time.Time `json:"not_after"`
	IssuedAt    time.Time `json:"issued_at"`
	CSRFP       string    `json:"csr_public_key_fingerprint"`
}

// retiredCA is an Intermediate replaced by a rotation.
type retiredCA struct {
	Dir    string // relative to the CA directory
	Cert   *x509.Certificate
	HasKey bool
}

func (s Store) retired() []retiredCA {
	entries, _ := os.ReadDir(s.path(retiredDir))
	var out []retiredCA
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(retiredDir, e.Name())
		raw, err := os.ReadFile(s.path(dir, "cert.pem"))
		if err != nil {
			continue
		}
		c, err := certutil.ParseCertificatePEM(raw)
		if err != nil {
			continue
		}
		_, encErr := os.Stat(s.path(dir, "key.pem.enc"))
		_, plainErr := os.Stat(s.path(dir, "key.pem"))
		out = append(out, retiredCA{Dir: dir, Cert: c, HasKey: encErr == nil || plainErr == nil})
	}
	return out
}

func (s Store) appendJSONL(name string, v any) error {
	f, err := os.OpenFile(s.path(name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(v)
	_, err = f.Write(append(line, '\n'))
	return err
}

// InitRoot creates a Root-only CA directory, its key sealed under s.Passphrase.
func (s Store) InitRoot(commonName string, validity time.Duration) (*labpki.CA, error) {
	if s.Passphrase == "" {
		return nil, errors.New("ca-admin: init-root needs a Root passphrase")
	}
	if _, err := os.Stat(s.Dir); err == nil {
		return nil, fmt.Errorf("ca-admin: %s already exists; refusing to overwrite", s.Dir)
	}
	root, err := labpki.NewRootCA(commonName, validity)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"root", "public"} {
		if err := os.MkdirAll(s.path(d), 0o700); err != nil {
			return nil, err
		}
	}
	if err := s.writeCA("root", root); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.path("public", "root-ca.crt.pem"), labpki.CertPEM(root.Cert), 0o644); err != nil {
		return nil, err
	}
	return root, nil
}

// IntermediateCSR generates an Intermediate key, sealed under s.Passphrase,
// and its CSR in an issuer directory. The first one goes to intermediate/ (the
// directory may be an empty mounted volume); with next it goes to next/ for a
// rotation of the installed one. Nothing is ever replaced here.
func (s Store) IntermediateCSR(commonName string, next bool) ([]byte, error) {
	if s.Passphrase == "" {
		return nil, errors.New("ca-admin: intermediate-csr needs an Intermediate passphrase")
	}
	if s.hasRootKey() {
		return nil, errRootKeyOnIssuer
	}
	dir := "intermediate"
	if next {
		if !s.exists() {
			return nil, errors.New("ca-admin: --next rotates an installed Intermediate; there is none yet")
		}
		dir = nextDir
	}
	if _, err := os.Stat(s.path(dir)); err == nil {
		if next {
			return nil, fmt.Errorf("ca-admin: a rotation request is already pending in %s", s.path(dir))
		}
		return nil, fmt.Errorf("ca-admin: %s already exists; to replace an installed Intermediate use --next", s.path(dir))
	}
	key, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName, OrganizationalUnit: []string{"PQC Device Signing CA"}},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("ca-admin: create intermediate CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	for _, d := range []string{dir, "public"} {
		if err := os.MkdirAll(s.path(d), 0o700); err != nil {
			return nil, err
		}
	}
	if err := s.writeKey(dir, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.path(dir, pendingCSR), csrPEM, 0o644); err != nil {
		return nil, err
	}
	return csrPEM, nil
}

// SignIntermediate has the Root in s sign an Intermediate CSR. The subject is
// the operator's commonName, never the CSR's.
func (s Store) SignIntermediate(csrPEM []byte, commonName string, validity time.Duration) (*x509.Certificate, IntermediateRecord, error) {
	root, err := s.Root()
	if err != nil {
		return nil, IntermediateRecord{}, err
	}
	csr, info, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		return nil, IntermediateRecord{}, fmt.Errorf("intermediate CSR rejected: %w", err)
	}
	pub, ok := csr.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, IntermediateRecord{}, errors.New("intermediate CSR rejected: not an ML-DSA key")
	}
	cert, err := root.IssueIntermediateCert(pub, commonName, validity)
	if err != nil {
		return nil, IntermediateRecord{}, err
	}
	rec := IntermediateRecord{
		Serial: certSerialHex(cert), Subject: cert.Subject.String(), Fingerprint: certutil.FingerprintSHA256(cert),
		NotAfter: cert.NotAfter, IssuedAt: time.Now().UTC(), CSRFP: info.PublicKeyFP,
	}
	return cert, rec, s.appendJSONL("intermediates.jsonl", rec)
}

// InstallIntermediate installs a Root-signed Intermediate certificate after
// checking it is a pathlen:0 signing CA, issued by the Root, for the key this
// directory generated. Without rotate it completes a new issuer directory;
// with rotate it replaces the installed Intermediate by the pending next/ one
// (same Root) and retires the old one.
func (s Store) InstallIntermediate(certPEM, rootPEM []byte, rotate bool) (*labpki.CA, error) {
	if s.hasRootKey() {
		return nil, errRootKeyOnIssuer
	}
	keyDir := "intermediate"
	switch {
	case rotate && !s.exists():
		return nil, errors.New("ca-admin: --rotate needs an installed Intermediate")
	case rotate:
		keyDir = nextDir
	case s.exists():
		return nil, errors.New("ca-admin: an Intermediate is already installed here; to replace it run intermediate-csr --next, then install-intermediate --rotate")
	}
	if _, err := os.Stat(s.path(keyDir, pendingCSR)); err != nil {
		return nil, fmt.Errorf("ca-admin: no pending Intermediate request in %s", s.path(keyDir))
	}
	root, err := certutil.ParseCertificatePEM(rootPEM)
	if err != nil {
		return nil, fmt.Errorf("root certificate: %w", err)
	}
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("ca-admin: --root-cert is not a self-signed CA certificate")
	}
	if rotate {
		current, err := s.rootCert()
		if err != nil {
			return nil, err
		}
		if !current.Equal(root) {
			return nil, errors.New("ca-admin: a rotation keeps the Root; --root-cert is a different Root")
		}
	}
	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("intermediate certificate: %w", err)
	}
	if err := cert.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("ca-admin: the Intermediate certificate is not signed by this Root: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.MaxPathLen != 0 ||
		cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, errors.New("ca-admin: the certificate is not a CA:TRUE, pathlen:0 certificate with keyCertSign and cRLSign")
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("ca-admin: the Intermediate certificate is not valid now")
	}
	key, err := s.loadKey(keyDir)
	if err != nil {
		return nil, err
	}
	if !keys.SameKeyPair(key, cert.PublicKey) {
		return nil, errors.New("ca-admin: the certificate is for a different key than the one generated here")
	}

	if rotate {
		old, err := s.Intermediate()
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(retiredDir, certSerialHex(old.Cert))
		if err := os.MkdirAll(s.path(dst), 0o700); err != nil {
			return nil, err
		}
		for _, f := range []string{"key.pem.enc", "key.pem", "cert.pem"} {
			if _, err := os.Stat(s.path("intermediate", f)); err == nil {
				if err := os.Rename(s.path("intermediate", f), s.path(dst, f)); err != nil {
					return nil, err
				}
			}
		}
		for _, f := range []string{"key.pem.enc", "key.pem"} {
			if _, err := os.Stat(s.path(nextDir, f)); err == nil {
				if err := os.Rename(s.path(nextDir, f), s.path("intermediate", f)); err != nil {
					return nil, err
				}
			}
		}
	} else {
		if err := os.MkdirAll(s.path("root"), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(s.path("root", "cert.pem"), labpki.CertPEM(root), 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(s.path("intermediate", "cert.pem"), labpki.CertPEM(cert), 0o644); err != nil {
		return nil, err
	}
	inter := &labpki.CA{Key: key, Cert: cert}
	if err := s.publish(inter, nil); err != nil {
		return nil, err
	}
	if _, err := s.loadLedger(); err != nil {
		if err := s.saveLedger(&Ledger{}); err != nil {
			return nil, err
		}
	}
	if rotate {
		_ = os.RemoveAll(s.path(nextDir))
	} else {
		_ = os.Remove(s.path("intermediate", pendingCSR))
	}
	return inter, nil
}

func cmdInitRoot(args []string) error {
	fs := flag.NewFlagSet("init-root", flag.ExitOnError)
	dir := fs.String("dir", "", "Root CA directory to create (required)")
	cn := fs.String("root-cn", "PQC PDF Root CA", "Root CA common name")
	years := fs.Int("years", 20, "validity in years")
	_ = fs.Parse(args)
	if *dir == "" {
		return errors.New("-dir is required")
	}
	pass, err := requireRolePassphrase(roleRoot)
	if err != nil {
		return err
	}
	s := Store{Dir: *dir, Passphrase: pass, Operator: operator()}
	root, err := s.InitRoot(*cn, time.Duration(*years)*365*24*time.Hour)
	if err != nil {
		return err
	}
	_ = s.logCeremony("root.init", "Root generated (split CA)", "root/key.pem.enc", "root/cert.pem", "public/root-ca.crt.pem")
	fmt.Printf("Root CA initialised in %s/\n", *dir)
	fmt.Printf("  root      : %s\n  fp        : %s\n  not_after : %s\n", root.Cert.Subject,
		certutil.FingerprintSHA256(root.Cert), root.Cert.NotAfter.Format(time.RFC3339))
	fmt.Println("  key       : ENCRYPTED under the Root passphrase")
	fmt.Println("Only public/root-ca.crt.pem goes to the server. Keep this directory offline.")
	return nil
}

func cmdIntermediateCSR(args []string) error {
	fs := flag.NewFlagSet("intermediate-csr", flag.ExitOnError)
	dir := fs.String("dir", "", "issuer CA directory (required; may be an empty mounted volume)")
	cn := fs.String("inter-cn", "PQC Device Signing CA", "Intermediate CA common name")
	next := fs.Bool("next", false, "prepare the next Intermediate for a rotation of the installed one")
	out := fs.String("out", "", "also write the CSR here (optional)")
	_ = fs.Parse(args)
	if *dir == "" {
		return errors.New("-dir is required")
	}
	pass, err := requireRolePassphrase(roleIntermediate)
	if err != nil {
		return err
	}
	s := Store{Dir: *dir, Passphrase: pass, Operator: operator()}
	csrPEM, err := s.IntermediateCSR(*cn, *next)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, csrPEM, 0o644); err != nil {
			return err
		}
	}
	keyDir, action := "intermediate", "intermediate.csr"
	if *next {
		keyDir, action = nextDir, "intermediate.rotation.csr"
	}
	_ = s.logCeremony(action, *cn, keyDir+"/key.pem.enc", keyDir+"/"+pendingCSR)
	_, info, _ := enrollment.ParseAndValidateCSR(csrPEM)
	fmt.Printf("Intermediate key + CSR created in %s/\n", s.path(keyDir))
	fmt.Printf("  key        : ENCRYPTED under the Intermediate passphrase (never leaves this directory)\n")
	fmt.Printf("  csr        : %s\n  csr key fp : %s\n", s.path(keyDir, pendingCSR), info.PublicKeyFP)
	fmt.Println("Carry ONLY the CSR to the Root environment and run sign-intermediate.")
	return nil
}

func cmdSignIntermediate(args []string) error {
	fs := flag.NewFlagSet("sign-intermediate", flag.ExitOnError)
	dir := fs.String("dir", "", "Root CA directory (required)")
	csrPath := fs.String("csr", "", "Intermediate CSR PEM (required)")
	cn := fs.String("inter-cn", "", "Intermediate common name to ASSIGN (required)")
	years := fs.Int("years", 10, "validity in years (capped at the Root's)")
	out := fs.String("out", "", "output certificate PEM (required)")
	_ = fs.Parse(args)
	if *dir == "" || *csrPath == "" || *cn == "" || *out == "" {
		return errors.New("-dir, -csr, -inter-cn and -out are required")
	}
	pass, err := requireRolePassphrase(roleRoot)
	if err != nil {
		return err
	}
	s := Store{Dir: *dir, Passphrase: pass, Operator: operator()}
	if !s.hasRootKey() {
		return fmt.Errorf("ca-admin: %s holds no Root key", *dir)
	}
	raw, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	cert, rec, err := s.SignIntermediate(raw, *cn, time.Duration(*years)*365*24*time.Hour)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, labpki.CertPEM(cert), 0o644); err != nil {
		return err
	}
	_ = s.logCeremony("intermediate.sign", rec.Subject+" serial "+rec.Serial, "intermediates.jsonl")
	fmt.Printf("signed Intermediate %s\n  subject    : %s\n  serial     : %s\n  fp         : %s\n  not_after  : %s\n  csr key fp : %s\n",
		*out, rec.Subject, rec.Serial, rec.Fingerprint, rec.NotAfter.Format(time.RFC3339), rec.CSRFP)
	return nil
}

func cmdInstallIntermediate(args []string) error {
	fs := flag.NewFlagSet("install-intermediate", flag.ExitOnError)
	dir := fs.String("dir", "", "issuer CA directory (required)")
	certPath := fs.String("cert", "", "signed Intermediate certificate PEM (required)")
	rootPath := fs.String("root-cert", "", "Root certificate PEM (required)")
	rotate := fs.Bool("rotate", false, "replace the installed Intermediate by the pending next one and retire the old")
	_ = fs.Parse(args)
	if *dir == "" || *certPath == "" || *rootPath == "" {
		return errors.New("-dir, -cert and -root-cert are required")
	}
	pass, err := requireRolePassphrase(roleIntermediate)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(*certPath)
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(*rootPath)
	if err != nil {
		return err
	}
	s := Store{Dir: *dir, Passphrase: pass, Operator: operator()}
	inter, err := s.InstallIntermediate(certPEM, rootPEM, *rotate)
	if err != nil {
		return err
	}
	action := "intermediate.install"
	if *rotate {
		action = "intermediate.rotate"
	}
	_ = s.logCeremony(action, inter.Cert.Subject.String(),
		"root/cert.pem", "intermediate/cert.pem", "public/root-ca.crt.pem", "public/ca-chain.pem")
	if name, leak := s.hasPrivateKeyLeak(); leak {
		return fmt.Errorf("GATE FAIL: %s/public/%s contains private key material", *dir, name)
	}
	fmt.Printf("Intermediate installed in %s/\n  intermediate : %s\n  fp           : %s\n  not_after    : %s\n",
		*dir, inter.Cert.Subject, certutil.FingerprintSHA256(inter.Cert), inter.Cert.NotAfter.Format(time.RFC3339))
	if *rotate {
		fmt.Println("  previous     : retired (kept in ca-chain.pem and the CRL bundle while valid)")
	}
	fmt.Println("  root key     : absent (as required for an online issuer)")
	return nil
}
