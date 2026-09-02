// Command ca-admin runs the offline CA operator workflow for PQC PDF Sign V1
// (Rencana V1 §13, §14, §17.5): validate device CSRs, issue device
// certificates whose identity is assigned by the operator (never taken from
// the CSR subject), record revocations, and publish CRLs.
//
// LAB milestone (M2 / M7 foundation). Private keys are stored unencrypted
// under the CA directory. The production ceremony is docs/pki-ceremony.md and
// is done by hand on an air-gapped machine.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/labpki"
)

func pkixName(cn, org string) pkix.Name {
	n := pkix.Name{CommonName: cn}
	if org != "" {
		n.Organization = []string{org}
	}
	return n
}

const usage = `ca-admin — offline CA operator for PQC PDF Sign V1 (LAB)

usage: ca-admin <command> [flags]

  init      create a Root + Intermediate ML-DSA-65 CA under --dir
  validate  check a device CSR (proof of possession, ML-DSA-65)
  issue     issue a device certificate for a validated CSR (identity from flags)
  revoke    record a certificate serial as revoked
  crl       publish a fresh CRL signed by the Intermediate CA
  show      inspect a certificate or CRL PEM file

Run "ca-admin <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "crl":
		err = cmdCRL(os.Args[2:])
	case "show":
		err = cmdShow(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory to create")
	rootCN := fs.String("root-cn", "PQC PDF Root CA (LAB)", "Root CA common name")
	interCN := fs.String("inter-cn", "PQC Device Signing CA (LAB)", "Intermediate CA common name")
	_ = fs.Parse(args)

	s := Store{Dir: *dir}
	if err := s.Init(*rootCN, *interCN); err != nil {
		return err
	}
	root, _ := s.Root()
	inter, _ := s.Intermediate()
	fmt.Printf("CA initialised in %s/\n", *dir)
	fmt.Printf("  root         : %s\n", root.Cert.Subject)
	fmt.Printf("  intermediate : %s\n", inter.Cert.Subject)
	fmt.Printf("  published    : %s/public/{root-ca.crt.pem,intermediate-ca.crt.pem,ca-chain.pem}\n", *dir)
	fmt.Println("LAB only — keys are unencrypted. Production: docs/pki-ceremony.md")
	return nil
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	csrPath := fs.String("csr", "", "device CSR PEM (required)")
	_ = fs.Parse(args)
	if *csrPath == "" {
		return errors.New("-csr is required")
	}
	raw, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	_, info, err := enrollment.ParseAndValidateCSR(raw)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(out))
	fmt.Println("NOTE: the CSR subject above is advisory; identity is assigned at `issue` time.")
	return nil
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	csrPath := fs.String("csr", "", "device CSR PEM (required)")
	account := fs.String("account", "", "verified account id (required)")
	device := fs.String("device", "", "device label (required)")
	cn := fs.String("cn", "", "certificate common name to ASSIGN (required)")
	org := fs.String("org", "PQC PDF Sign", "certificate organization")
	days := fs.Int("days", 365, "validity in days")
	crlURL := fs.String("crl-url", "", "CRL distribution point URL (optional)")
	out := fs.String("out", "device.crt.pem", "output certificate PEM")
	_ = fs.Parse(args)
	if *csrPath == "" || *account == "" || *device == "" || *cn == "" {
		return errors.New("-csr, -account, -device and -cn are required")
	}

	s, err := openStore(*dir)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	csr, csrInfo, err := enrollment.ParseAndValidateCSR(raw)
	if err != nil {
		return fmt.Errorf("CSR rejected: %w", err)
	}
	inter, err := s.Intermediate()
	if err != nil {
		return err
	}
	cert, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject:  pkixName(*cn, *org),
		Validity: time.Duration(*days) * 24 * time.Hour,
		CRLURL:   *crlURL,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, labpki.CertPEM(cert), 0o644); err != nil {
		return err
	}
	fullchain := *out + ".fullchain.pem"
	if err := os.WriteFile(fullchain, labpki.ChainPEM(cert, inter.Cert), 0o644); err != nil {
		return err
	}
	rec := IssuedRecord{
		Serial:      certSerialHex(cert),
		Subject:     cert.Subject.String(),
		Account:     *account,
		DeviceLabel: *device,
		Fingerprint: certutil.FingerprintSHA256(cert),
		NotAfter:    cert.NotAfter,
		IssuedAt:    time.Now().UTC(),
		CSRFP:       csrInfo.PublicKeyFP,
	}
	if err := s.appendIssued(rec); err != nil {
		return err
	}
	fmt.Printf("issued %s\n  serial      : %s\n  subject     : %s\n  account     : %s\n  device      : %s\n  fingerprint : %s\n  not_after   : %s\n  chain       : %s\n",
		*out, rec.Serial, rec.Subject, rec.Account, rec.DeviceLabel, rec.Fingerprint,
		rec.NotAfter.Format(time.RFC3339), fullchain)
	return nil
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	serial := fs.String("serial", "", "certificate serial in hex (required)")
	reason := fs.String("reason", "unspecified", "revocation reason")
	_ = fs.Parse(args)
	if *serial == "" {
		return errors.New("-serial is required (hex, as printed by `issue` or `show`)")
	}
	if _, ok := new(big.Int).SetString(*serial, 16); !ok {
		return fmt.Errorf("invalid hex serial %q", *serial)
	}
	s, err := openStore(*dir)
	if err != nil {
		return err
	}
	l, err := s.loadLedger()
	if err != nil {
		return err
	}
	for _, r := range l.Revocations {
		if r.Serial == *serial {
			return fmt.Errorf("serial %s is already revoked (%s)", *serial, r.RevokedAt.Format(time.RFC3339))
		}
	}
	l.Revocations = append(l.Revocations, Revocation{
		Serial: *serial, Reason: *reason, RevokedAt: time.Now().UTC(),
	})
	if err := s.saveLedger(l); err != nil {
		return err
	}
	fmt.Printf("recorded revocation of %s (%s). Run `ca-admin crl` to publish.\n", *serial, *reason)
	return nil
}

func cmdCRL(args []string) error {
	fs := flag.NewFlagSet("crl", flag.ExitOnError)
	dir := fs.String("dir", "ca", "CA directory")
	days := fs.Int("days", 7, "CRL validity in days (nextUpdate)")
	out := fs.String("out", "", "also write the CRL here (optional)")
	_ = fs.Parse(args)

	s, err := openStore(*dir)
	if err != nil {
		return err
	}
	l, err := s.loadLedger()
	if err != nil {
		return err
	}
	inter, err := s.Intermediate()
	if err != nil {
		return err
	}
	serials := make([]*big.Int, 0, len(l.Revocations))
	for _, r := range l.Revocations {
		n, _ := new(big.Int).SetString(r.Serial, 16)
		serials = append(serials, n)
	}
	l.CRLNumber++
	crlPEM, err := inter.NewCRL(serials, l.CRLNumber, time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := s.publish(inter, crlPEM); err != nil {
		return err
	}
	if err := s.saveLedger(l); err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, crlPEM, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("published CRL #%d with %d revoked serial(s) -> %s/public/crl.pem\n",
		l.CRLNumber, len(serials), *dir)
	return nil
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	in := fs.String("in", "", "certificate or CRL PEM file (required)")
	_ = fs.Parse(args)
	if *in == "" {
		return errors.New("-in is required")
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("no PEM block found")
	}
	switch block.Type {
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(certutil.Describe(c), "", "  ")
		fmt.Println(string(out))
	case "X509 CRL":
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return err
		}
		fmt.Printf("CRL issuer      : %s\n", crl.Issuer)
		fmt.Printf("number          : %s\n", crl.Number)
		fmt.Printf("this/next update: %s .. %s\n", crl.ThisUpdate.Format(time.RFC3339), crl.NextUpdate.Format(time.RFC3339))
		fmt.Printf("signature alg   : %s\n", crl.SignatureAlgorithm)
		fmt.Printf("revoked entries : %d\n", len(crl.RevokedCertificateEntries))
		for _, e := range crl.RevokedCertificateEntries {
			fmt.Printf("  - %x  at %s\n", e.SerialNumber, e.RevocationTime.Format(time.RFC3339))
		}
	default:
		return fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	return nil
}
