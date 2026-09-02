package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
)

// Store is the on-disk layout of a CA directory.
//
//	<dir>/
//	  root/key.pem  root/cert.pem
//	  intermediate/key.pem  intermediate/cert.pem
//	  public/  root-ca.crt.pem  intermediate-ca.crt.pem  ca-chain.pem  crl.pem
//	  ledger.json      { crl_number, revocations[] }
//	  issued.jsonl     one line per issued device certificate
//
// LAB ONLY: private keys are stored unencrypted. The production ceremony
// (docs/pki-ceremony.md) is performed by hand on an air-gapped machine.
type Store struct{ Dir string }

type Ledger struct {
	CRLNumber   int64        `json:"crl_number"`
	Revocations []Revocation `json:"revocations"`
}

type Revocation struct {
	Serial    string    `json:"serial"` // hex
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

type IssuedRecord struct {
	Serial      string    `json:"serial"`
	Subject     string    `json:"subject"`
	Account     string    `json:"account"`
	DeviceLabel string    `json:"device_label"`
	Fingerprint string    `json:"fingerprint_sha256"`
	NotAfter    time.Time `json:"not_after"`
	IssuedAt    time.Time `json:"issued_at"`
	CSRFP       string    `json:"csr_public_key_fingerprint"`
}

func (s Store) path(parts ...string) string {
	return filepath.Join(append([]string{s.Dir}, parts...)...)
}

func (s Store) exists() bool {
	_, err := os.Stat(s.path("intermediate", "cert.pem"))
	return err == nil
}

// Init creates a fresh Root + Intermediate CA under s.Dir.
func (s Store) Init(rootCN, interCN string) error {
	if _, err := os.Stat(s.Dir); err == nil {
		return fmt.Errorf("ca-admin: %s already exists; refusing to overwrite", s.Dir)
	}
	root, err := labpki.NewRootCA(rootCN, 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	inter, err := labpki.NewIntermediateCA(root, interCN, 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	for _, d := range []string{"root", "intermediate", "public"} {
		if err := os.MkdirAll(s.path(d), 0o700); err != nil {
			return err
		}
	}
	if err := s.writeCA("root", root); err != nil {
		return err
	}
	if err := s.writeCA("intermediate", inter); err != nil {
		return err
	}
	if err := s.publish(inter, nil); err != nil {
		return err
	}
	return s.saveLedger(&Ledger{})
}

func (s Store) writeCA(name string, ca *labpki.CA) error {
	keyPEM, err := keys.MarshalPKCS8PEM(ca.Key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path(name, "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(s.path(name, "cert.pem"), labpki.CertPEM(ca.Cert), 0o644)
}

func (s Store) loadCA(name string) (*labpki.CA, error) {
	keyRaw, err := os.ReadFile(s.path(name, "key.pem"))
	if err != nil {
		return nil, err
	}
	sk, err := keys.ParsePKCS8(keyRaw)
	if err != nil {
		return nil, err
	}
	certRaw, err := os.ReadFile(s.path(name, "cert.pem"))
	if err != nil {
		return nil, err
	}
	cert, err := certutil.ParseCertificatePEM(certRaw)
	if err != nil {
		return nil, err
	}
	return &labpki.CA{Key: sk, Cert: cert}, nil
}

// Intermediate is the signing CA for device certs and CRLs.
func (s Store) Intermediate() (*labpki.CA, error) { return s.loadCA("intermediate") }
func (s Store) Root() (*labpki.CA, error)         { return s.loadCA("root") }

func (s Store) loadLedger() (*Ledger, error) {
	raw, err := os.ReadFile(s.path("ledger.json"))
	if err != nil {
		return nil, err
	}
	var l Ledger
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s Store) saveLedger(l *Ledger) error {
	raw, _ := json.MarshalIndent(l, "", "  ")
	return os.WriteFile(s.path("ledger.json"), raw, 0o644)
}

func (s Store) appendIssued(r IssuedRecord) error {
	f, err := os.OpenFile(s.path("issued.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(r)
	_, err = f.Write(append(line, '\n'))
	return err
}

// publish (re)writes the public trust material. crlPEM may be nil.
func (s Store) publish(inter *labpki.CA, crlPEM []byte) error {
	root, err := s.Root()
	if err != nil {
		return err
	}
	writes := map[string][]byte{
		"root-ca.crt.pem":         labpki.CertPEM(root.Cert),
		"intermediate-ca.crt.pem": labpki.CertPEM(inter.Cert),
		"ca-chain.pem":            labpki.ChainPEM(inter.Cert, root.Cert),
	}
	if crlPEM != nil {
		writes["crl.pem"] = crlPEM
	}
	for name, b := range writes {
		if err := os.WriteFile(s.path("public", name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

var errNotInitialised = errors.New("ca-admin: CA directory not initialised (run `ca-admin init` first)")

func openStore(dir string) (Store, error) {
	s := Store{Dir: dir}
	if !s.exists() {
		return s, errNotInitialised
	}
	return s, nil
}

// certSerialHex renders a certificate serial the way `revoke` expects it.
func certSerialHex(c *x509.Certificate) string { return fmt.Sprintf("%x", c.SerialNumber) }
