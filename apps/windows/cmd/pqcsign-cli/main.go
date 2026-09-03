// Command pqcsign-cli is the M1 desktop spike from Rencana V1 §10.1 / §32.
//
// It proves the core-go ML-DSA-65 signing/verification path works on Windows
// amd64 before any UI is built. It also exposes the individual steps (keygen,
// csr, sign, verify) and a lab-only PKI generator so the same signed PDF can
// be produced here and on Android and cross-verified.
//
// This binary writes private key material to disk UNENCRYPTED for lab use.
// The shipping Windows client will wrap keys with DPAPI (Rencana V1 §12.1);
// that is out of scope for the spike.
package main

import (
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/labpki"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/spike"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/core/verification"
)

const usage = `pqcsign-cli — PQC PDF Sign V1 desktop spike (ML-DSA-65 / PAdES-B)

usage: pqcsign-cli <command> [flags]

commands:
  spike     run the full M1 proof (lab PKI, sign, verify, negative checks)
  genpki    generate a lab Root+Intermediate CA and one device key+certificate
  keygen    generate a device ML-DSA-65 key (PKCS#8 PEM)
  pubkey    print the PKIX public key PEM for a device key
  csr       create a device CSR from a device key
  sign      sign a PDF with a device key + certificate chain
  verify    verify a signed PDF against an explicit Root CA (+ optional CRL)
  version   print build/runtime info

Run "pqcsign-cli <command> -h" for command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "spike":
		err = cmdSpike(os.Args[2:])
	case "genpki":
		err = cmdGenPKI(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "pubkey":
		err = cmdPubkey(os.Args[2:])
	case "csr":
		err = cmdCSR(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "totp":
		err = cmdTOTP(os.Args[2:])
	case "version":
		fmt.Printf("pqcsign-cli spike build\n%s %s/%s\nalgorithm: %s  profile: PAdES_B  digest: SHA-512\n",
			runtime.Version(), runtime.GOOS, runtime.GOARCH, keys.Algorithm)
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

// ---- spike ----

func cmdSpike(args []string) error {
	fs := flag.NewFlagSet("spike", flag.ExitOnError)
	in := fs.String("in", "", "input PDF (default: built-in sample)")
	out := fs.String("out", "spike-out", "output directory for artifacts and report.json")
	signer := fs.String("signer", "Spike Operator", "signer common name / display name")
	device := fs.String("device-label", "Windows Laptop", "device label")
	platform := fs.String("platform", runtime.GOOS, `platform tag ("windows" | "android")`)
	_ = fs.Parse(args)

	var pdf []byte
	var err error
	if *in != "" {
		if pdf, err = os.ReadFile(*in); err != nil {
			return err
		}
	} else {
		pdf = testpdf.Sample()
	}

	rep, err := spike.Run(spike.Config{
		InputPDF:    pdf,
		SignerName:  *signer,
		DeviceLabel: *device,
		Platform:    *platform,
	})
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	a := rep.Artifacts
	files := map[string][]byte{
		"root-ca.crt.pem":         a.RootCertPEM,
		"intermediate-ca.crt.pem": a.IntermediateCertPEM,
		"device.crt.pem":          a.DeviceCertPEM,
		"ca-chain.pem":            a.ChainPEM,
		"device-key.pkcs8.pem":    a.DeviceKeyPKCS8PEM,
		"device.csr.pem":          a.CSRPEM,
		"crl.pem":                 a.CRLPEM,
		"unrelated-root.crt.pem":  a.WrongRootPEM,
		"signed.pdf":              a.SignedPDF,
	}
	for name, b := range files {
		mode := os.FileMode(0o644)
		if strings.Contains(name, "key") {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(*out, name), b, mode); err != nil {
			return err
		}
	}
	reportJSON, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "report.json"), reportJSON, 0o644); err != nil {
		return err
	}

	// Console summary.
	fmt.Printf("PQC PDF Sign V1 — M1 spike (%s)\n", rep.OSArch)
	fmt.Printf("  algorithm        : %s / %s\n", rep.Algorithm, rep.PDFProfile)
	fmt.Printf("  input  PDF bytes : %d\n", rep.InputPDFBytes)
	fmt.Printf("  signed PDF bytes : %d  (signature overhead %d)\n", rep.SignedPDFBytes, rep.SignatureOverhead)
	fmt.Printf("  timings          : keygen %dms | sign %dms | verify %dms\n", rep.KeygenMillis, rep.SignMillis, rep.VerifyMillis)
	fmt.Printf("  peak heap alloc  : %d KiB\n", rep.PeakHeapAllocBytes/1024)
	fmt.Printf("  cert serial      : %s\n", rep.CertificateSerial)
	fmt.Println("  checks:")
	for _, c := range rep.Checks {
		mark := "PASS"
		if !c.Passed {
			mark = "FAIL"
		}
		fmt.Printf("    [%s] %-32s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Printf("\nartifacts written to %s/\n", *out)
	if !rep.Passed {
		return errors.New("spike FAILED (see checks above)")
	}
	fmt.Println("spike PASSED")
	return nil
}

// ---- genpki (lab only) ----

func cmdGenPKI(args []string) error {
	fs := flag.NewFlagSet("genpki", flag.ExitOnError)
	out := fs.String("out", "lab-pki", "output directory")
	cn := fs.String("device-cn", "Lab Device", "device certificate common name")
	platform := fs.String("platform", runtime.GOOS, "platform tag for the device")
	_ = fs.Parse(args)

	root, err := labpki.NewRootCA("PQC PDF Root CA (LAB)", 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	inter, err := labpki.NewIntermediateCA(root, "PQC Device Signing CA (LAB)", 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	devKey, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return err
	}
	devKeyPEM, err := keys.MarshalPKCS8PEM(devKey)
	if err != nil {
		return err
	}
	csrPEM, err := enrollment.CreateDeviceCSR(devKeyPEM, enrollment.Request{CommonName: *cn, Organization: "PQC PDF Sign Lab", Platform: *platform})
	if err != nil {
		return err
	}
	csr, _, err := enrollment.ParseAndValidateCSR(csrPEM)
	if err != nil {
		return err
	}
	devCert, err := inter.IssueDeviceCert(csr, labpki.DeviceCertOptions{
		Subject:  pkix.Name{CommonName: *cn, Organization: []string{"PQC PDF Sign Lab"}},
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	crlPEM, err := inter.NewCRL(nil, 1, 7*24*time.Hour)
	if err != nil {
		return err
	}
	// An unrelated Root CA, for negative "wrong trust anchor" tests.
	unrelated, err := labpki.NewRootCA("Unrelated Root CA (LAB)", 365*24*time.Hour)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	write := func(name string, b []byte, mode os.FileMode) error {
		return os.WriteFile(filepath.Join(*out, name), b, mode)
	}
	if err := errors.Join(
		write("root-ca.crt.pem", labpki.CertPEM(root.Cert), 0o644),
		write("intermediate-ca.crt.pem", labpki.CertPEM(inter.Cert), 0o644),
		write("ca-chain.pem", labpki.ChainPEM(devCert, inter.Cert), 0o644),
		write("device.crt.pem", labpki.CertPEM(devCert), 0o644),
		write("device-key.pkcs8.pem", devKeyPEM, 0o600),
		write("device.csr.pem", csrPEM, 0o644),
		write("crl.pem", crlPEM, 0o644),
		write("unrelated-root.crt.pem", labpki.CertPEM(unrelated.Cert), 0o644),
	); err != nil {
		return err
	}
	fmt.Printf("lab PKI written to %s/\n  root       : %s\n  intermediate: %s\n  device     : %s (serial %x)\n",
		*out, root.Cert.Subject, inter.Cert.Subject, devCert.Subject, devCert.SerialNumber)
	fmt.Println("NOTE: lab only — not a production PKI ceremony (Rencana V1 §13).")
	return nil
}

// ---- keygen / pubkey / csr ----

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "device-key.pkcs8.pem", "output path for the PKCS#8 PEM key")
	_ = fs.Parse(args)
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return err
	}
	pemBytes, err := keys.MarshalPKCS8PEM(sk)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, pemBytes, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%s, PKCS#8, UNENCRYPTED — lab use only)\n", *out, keys.Algorithm)
	return nil
}

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	keyPath := fs.String("key", "", "device key PKCS#8 PEM (required)")
	_ = fs.Parse(args)
	if *keyPath == "" {
		return errors.New("-key is required")
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	sk, err := keys.ParsePKCS8(raw)
	if err != nil {
		return err
	}
	pemBytes, err := keys.ExportPublicKeyPEM(sk)
	if err != nil {
		return err
	}
	fp, _ := keys.PublicKeyFingerprint(sk.Public())
	fmt.Print(string(pemBytes))
	fmt.Fprintf(os.Stderr, "sha256 fingerprint: %s\n", fp)
	return nil
}

func cmdCSR(args []string) error {
	fs := flag.NewFlagSet("csr", flag.ExitOnError)
	keyPath := fs.String("key", "", "device key PKCS#8 PEM (required)")
	out := fs.String("out", "device.csr.pem", "output path for the CSR PEM")
	cn := fs.String("cn", "", "requested common name (advisory; CA assigns identity)")
	org := fs.String("org", "", "organization")
	platform := fs.String("platform", runtime.GOOS, "platform tag")
	_ = fs.Parse(args)
	if *keyPath == "" || *cn == "" {
		return errors.New("-key and -cn are required")
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	csrPEM, err := enrollment.CreateDeviceCSR(raw, enrollment.Request{
		CommonName:   *cn,
		Organization: *org,
		Platform:     *platform,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, csrPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", *out)
	return nil
}

// ---- sign ----

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	in := fs.String("in", "", "input PDF (required)")
	out := fs.String("out", "signed.pdf", "output signed PDF")
	keyPath := fs.String("key", "", "device key PKCS#8 PEM (required)")
	chainPath := fs.String("chain", "", "certificate chain PEM: leaf first, then intermediates (required)")
	reason := fs.String("reason", "", "signing reason")
	location := fs.String("location", "", "signing location")
	signer := fs.String("signer", "", "signer display name (default: cert CN)")
	publicID := fs.String("public-id", "", "reservation / public transaction id")
	verifyURL := fs.String("verify-url", "", "verification URL for the QR code")
	qr := fs.Bool("qr", true, "embed a QR code in the appearance")
	page := fs.Int("page", 1, "page to place the appearance on (1-based)")
	x := fs.Float64("x", 40, "appearance X in PDF points")
	y := fs.Float64("y", 40, "appearance Y in PDF points")
	_ = fs.Parse(args)
	if *in == "" || *keyPath == "" || *chainPath == "" {
		return errors.New("-in, -key and -chain are required")
	}
	pdf, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	chain, err := os.ReadFile(*chainPath)
	if err != nil {
		return err
	}
	res, err := signing.SignPDF(pdf, key, chain, signing.Options{
		Reason:             *reason,
		Location:           *location,
		SignerName:         *signer,
		PublicID:           *publicID,
		VerificationURL:    *verifyURL,
		IncludeQR:          *qr,
		Page:               *page,
		X:                  *x,
		Y:                  *y,
		ClaimedSigningTime: time.Now(),
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, res.SignedPDF, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  algorithm       : %s / %s\n  original sha512 : %s\n  signed   sha512 : %s\n  cert serial     : %s\n",
		*out, res.Algorithm, res.PDFProfile, res.OriginalSHA512, res.SignedSHA512, res.CertificateSerial)
	return nil
}

// ---- verify ----

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	in := fs.String("in", "", "signed PDF (required)")
	rootPath := fs.String("root", "", "explicit Root CA PEM (required)")
	interPath := fs.String("intermediate", "", "extra intermediates PEM (optional)")
	crlPath := fs.String("crl", "", "CRL PEM for offline revocation check (optional)")
	external := fs.Bool("external", false, "allow network OCSP/CRL fetching")
	pqcOnly := fs.Bool("pqc-only", true, "reject non-ML-DSA signatures")
	_ = fs.Parse(args)
	if *in == "" || *rootPath == "" {
		return errors.New("-in and -root are required")
	}
	pdf, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	opts := verification.Options{RequireMLDSAOnly: *pqcOnly, AllowExternalRevocation: *external}
	if opts.RootPEM, err = os.ReadFile(*rootPath); err != nil {
		return err
	}
	if *interPath != "" {
		if opts.IntermediatePEM, err = os.ReadFile(*interPath); err != nil {
			return err
		}
	}
	if *crlPath != "" {
		if opts.CRLPEM, err = os.ReadFile(*crlPath); err != nil {
			return err
		}
	}
	res, err := verification.VerifyPDF(pdf, opts)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
	if !res.Valid {
		return errors.New("verification result: INVALID")
	}
	return nil
}
