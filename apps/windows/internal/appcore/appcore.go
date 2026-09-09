// Package appcore is the GUI-independent logic of the Windows client
// (Rencana V1 §20). Every page in the Wails app is a thin call into one of
// these methods. The private key is generated here, wrapped immediately by
// the keystore, and only unwrapped for the duration of a single operation.
package appcore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/keys"
	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/verification"

	"example.internal/pqc-pdf-sign/apps/windows/internal/apiclient"
	"example.internal/pqc-pdf-sign/apps/windows/internal/keystore"
)

// App bundles the vault + server client. One instance per running client.
type App struct {
	store *keystore.Store
	api   *apiclient.Client
}

// Config wires an App. VaultDir "" -> %LOCALAPPDATA%\PQC-PDF-Sign.
type Config struct {
	VaultDir    string
	ServerURL   string
	InsecureTLS bool // lab only (Caddy internal CA)
}

func New(cfg Config) (*App, error) {
	st, err := keystore.Open(cfg.VaultDir)
	if err != nil {
		return nil, err
	}
	if cfg.ServerURL == "" {
		if s, _ := st.State(); s.ServerBaseURL != "" {
			cfg.ServerURL = s.ServerBaseURL
		}
	}
	return &App{store: st, api: apiclient.New(cfg.ServerURL, cfg.InsecureTLS)}, nil
}

// ---- 1. Login ----

func (a *App) Login(email, password string) error {
	if err := a.api.Login(email, password); err != nil {
		return err
	}
	s, _ := a.store.State()
	s.AccountEmail = email
	return a.store.SaveState(s)
}

// VerifyPublic checks a PDF against a server's public verifier
// (POST /api/v1/verify, no login). Returns the raw JSON result.
func (a *App) VerifyPublic(serverURL, path string) (json.RawMessage, error) {
	pdf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res, err := apiclient.New(serverURL, true).VerifyPublic(pdf)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(res)
	return b, nil
}

func (a *App) SetServerURL(u string, insecure bool) error {
	a.api = apiclient.New(u, insecure)
	s, _ := a.store.State()
	s.ServerBaseURL = u
	return a.store.SaveState(s)
}

// ---- 1b. Self-registration (Rencana RB-1) ----

// RegisterResult mirrors the server's register response.
type RegisterResult struct {
	AccountID string `json:"account_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// Register creates a pending account. An admin approves it before Login works.
func (a *App) Register(fullName, org, email, password string) (RegisterResult, error) {
	r, err := a.api.Register(fullName, org, email, password)
	return RegisterResult(r), err
}

// ---- 2. Device enrolment ----

type EnrollResult struct {
	DeviceID     string `json:"device_id"`
	EnrollmentID string `json:"enrollment_id"`
}

// EnsureEnrolled makes this device ready to sign with no manual step
// (Rencana RB-3): on first run it generates + enrols a key; then it fetches
// the certificate the server auto-issues for an approved account. It also
// re-enrols automatically when the stored device id is unknown to the current
// server (a fresh server / wiped database / switched server URL). Safe to
// call after every Login.
func (a *App) EnsureEnrolled(pin string) (CertStatus, error) {
	if !a.store.HasKey() || a.deviceUnknownToServer() {
		label, _ := os.Hostname()
		if label == "" {
			label = "Windows"
		} else {
			label = "Windows " + label
		}
		a.wipeDeviceState()
		if _, err := a.enrollDevice(label, pin); err != nil {
			return CertStatus{}, err
		}
	}
	return a.CertificateStatus(pin)
}

// deviceUnknownToServer reports true when we hold a key + device id but the
// server has no such device (404 on its certificate endpoint). Any other
// error (network, not-issued-yet) is treated as "known".
func (a *App) deviceUnknownToServer() bool {
	s, _ := a.store.State()
	if s.DeviceID == "" {
		return true
	}
	_, err := a.api.DeviceCertificate(s.DeviceID)
	return errors.Is(err, apiclient.ErrNotYetIssued)
}

// wipeDeviceState removes the stale key blob + cached certificate and clears
// the recorded device id, so the following enrolment starts clean. It keeps
// the vault directory (and the server URL / account email in state) intact so
// SaveKey can write straight away.
func (a *App) wipeDeviceState() {
	_ = a.store.DeleteKey()
	_ = a.store.SaveDeviceCertPEM([]byte{}) // invalidate the cached cert
	s, _ := a.store.State()
	s.DeviceID, s.EnrollmentID, s.CertificateSN = "", "", ""
	_ = a.store.SaveState(s)
}

// RegisterDevice is the explicit enrol entry point kept for tooling/tests. It
// refuses to clobber an existing key; EnsureEnrolled is the app path.
func (a *App) RegisterDevice(label, pin string) (EnrollResult, error) {
	if a.store.HasKey() {
		return EnrollResult{}, errors.New("a device key already exists; use Security settings to reset first")
	}
	return a.enrollDevice(label, pin)
}

// enrollDevice generates the device key, wraps it, and enrols with the server.
// pin may be "" (no PIN).
func (a *App) enrollDevice(label, pin string) (EnrollResult, error) {
	sk, err := keys.GenerateMLDSA65Key()
	if err != nil {
		return EnrollResult{}, err
	}
	pkcs8, err := keys.MarshalPKCS8PEM(sk)
	if err != nil {
		return EnrollResult{}, err
	}
	defer wipe(pkcs8)

	if err := a.store.SaveKey(pkcs8, keystore.Options{PIN: pin}); err != nil {
		return EnrollResult{}, fmt.Errorf("protect key: %w", err)
	}

	deviceID, err := a.api.CreateDevice(label, "windows")
	if err != nil {
		_ = a.store.DeleteKey()
		return EnrollResult{}, err
	}
	csrPEM, err := enrollment.CreateDeviceCSR(pkcs8, enrollment.Request{
		CommonName: label, DeviceLabel: label, Platform: "windows",
	})
	if err != nil {
		return EnrollResult{}, err
	}
	enrID, err := a.api.SubmitCSR(deviceID, csrPEM)
	if err != nil {
		return EnrollResult{}, err
	}

	if root, err := a.api.PublicRootCA(); err == nil {
		_ = a.store.SaveRootPEM(root)
	}
	if chain, err := a.api.PublicChain(); err == nil {
		_ = a.store.SaveChainPEM(chain)
	}

	s, _ := a.store.State()
	s.DeviceID, s.EnrollmentID, s.HasPIN = deviceID, enrID, pin != ""
	if err := a.store.SaveState(s); err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{DeviceID: deviceID, EnrollmentID: enrID}, nil
}

// ---- 3. Certificate status ----

type CertStatus struct {
	State string             `json:"state"` // "none" | "pending" | "active"
	Info  *certutil.CertInfo `json:"info,omitempty"`
}

// CertificateStatus checks locally first, then polls the server; when the CA
// has issued a cert it is verified against the on-device key and cached.
func (a *App) CertificateStatus(pin string) (CertStatus, error) {
	if !a.store.HasKey() {
		return CertStatus{State: "none"}, nil
	}
	if pem, err := a.store.DeviceCertPEM(); err == nil {
		_, info, verr := certutil.ParseAndValidateCertificate(pem, time.Now())
		if verr == nil {
			return CertStatus{State: "active", Info: info}, nil
		}
	}
	s, _ := a.store.State()
	if s.DeviceID == "" {
		return CertStatus{State: "pending"}, nil
	}
	pem, err := a.api.DeviceCertificate(s.DeviceID)
	if errors.Is(err, apiclient.ErrNotYetIssued) {
		return CertStatus{State: "pending"}, nil
	}
	if err != nil {
		return CertStatus{}, err
	}
	cert, info, err := certutil.ParseAndValidateCertificate(pem, time.Now())
	if err != nil {
		return CertStatus{}, fmt.Errorf("server returned an unusable certificate: %w", err)
	}
	// The issued cert MUST match the key held on this device (§14, §25.2).
	keyPEM, err := a.store.LoadKey(keystore.Options{PIN: pin})
	if err != nil {
		return CertStatus{}, err
	}
	defer wipe(keyPEM)
	sk, err := keys.ParsePKCS8(keyPEM)
	if err != nil {
		return CertStatus{}, err
	}
	if !keys.SameKeyPair(sk, cert.PublicKey) {
		return CertStatus{}, errors.New("issued certificate does not match the on-device key — rejecting")
	}
	if err := a.store.SaveDeviceCertPEM(pem); err != nil {
		return CertStatus{}, err
	}
	s.CertificateSN = info.SerialNumber
	_ = a.store.SaveState(s)
	return CertStatus{State: "active", Info: info}, nil
}

// ---- 4. Sign PDF ----

type SignResult struct {
	OutputPath      string `json:"output_path"`
	PublicID        string `json:"public_id"`
	VerificationURL string `json:"verification_url"`
	OriginalSHA512  string `json:"original_sha512"`
	SignedSHA512    string `json:"signed_pdf_sha512"`
	ServerStatus    string `json:"server_status"`
}

// QRPlacement is where the user dropped the QR box in the preview: a
// 1-based page and a page-relative rectangle with the origin at the top-left
// (X,Y = top-left corner, W = width; all fractions in [0,1]).
type QRPlacement struct {
	Page int     `json:"page"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	W    float64 `json:"w"`
}

// PdfBytesB64 returns the raw PDF at path as base64 — the frontend feeds it
// to its PDF preview so the user can position the QR box.
func (a *App) PdfBytesB64(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// SignPDF reserves an id, has the server stamp a QR at the requested spot,
// signs locally, verifies the result against the bundled Root CA, writes it,
// and submits it (§15). It never uploads the original unstamped PDF for
// storage — only to the stamp endpoint, which returns it for signing.
func (a *App) SignPDF(inPath, outPath, reason, signerName, pin string, place QRPlacement) (SignResult, error) {
	pdf, err := os.ReadFile(inPath)
	if err != nil {
		return SignResult{}, err
	}
	// One document, one signature (Rencana V1 §15.3). Re-signing an already
	// signed PDF would break the first signature and the server rejects
	// multi-signature uploads — catch it early with a clear message.
	if sigs, _ := verification.ListPDFSignatures(pdf); len(sigs) > 0 {
		return SignResult{}, fmt.Errorf("dokumen ini sudah memiliki tanda tangan digital — satu dokumen hanya boleh ditandatangani sekali; pilih PDF yang belum ditandatangani")
	}
	chainPEM, err := a.store.ChainPEM()
	if err != nil {
		return SignResult{}, errors.New("no CA chain cached; register the device first")
	}
	devCertPEM, err := a.store.DeviceCertPEM()
	if err != nil {
		return SignResult{}, errors.New("no device certificate yet; check Certificate status")
	}
	rootPEM, err := a.store.RootPEM()
	if err != nil {
		return SignResult{}, errors.New("no Root CA cached")
	}
	fullChain := append(append([]byte(nil), devCertPEM...), chainPEM...)

	s, _ := a.store.State()
	origHash := hashutil.CalculateSHA512(pdf)
	res, err := a.api.Reserve(s.DeviceID, origHash, filepath.Base(inPath))
	if err != nil {
		return SignResult{}, fmt.Errorf("reserve: %w", err)
	}

	// The QR stamp is drawn server-side BEFORE signing so it is inside the
	// signed byte range (Rencana RB-2c). A PDF the server cannot process
	// fails here with a clear message.
	toSign, err := a.api.Stamp(res.PublicID, pdf, apiclient.StampPlacement{
		Page: place.Page, X: place.X, Y: place.Y, W: place.W,
	}, reason)
	if err != nil {
		return SignResult{}, fmt.Errorf("penempelan QR: %w", err)
	}

	keyPEM, err := a.store.LoadKey(keystore.Options{PIN: pin})
	if err != nil {
		return SignResult{}, err
	}
	signed, serr := signing.SignPDF(toSign, keyPEM, fullChain, signing.Options{
		Reason:          reason,
		SignerName:      signerName,
		PublicID:        res.PublicID,
		VerificationURL: res.VerificationURL,
		IncludeQR:       false, // the appended page carries the QR
		Timeout:         20 * time.Second,
	})
	wipe(keyPEM)
	if serr != nil {
		return SignResult{}, fmt.Errorf("sign: %w", serr)
	}

	// Local verification before upload (§15.2 step 10).
	vr, err := verification.VerifyPDF(signed.SignedPDF, verification.Options{
		RootPEM: rootPEM, IntermediatePEM: chainPEM, RequireMLDSAOnly: true, Timeout: 20 * time.Second,
	})
	if err != nil || !vr.Valid {
		return SignResult{}, fmt.Errorf("local verification failed; not uploading: %v", firstErr(vr, err))
	}

	if outPath == "" {
		outPath = strings.TrimSuffix(inPath, ".pdf") + ".signed.pdf"
	}
	if err := os.WriteFile(outPath, signed.SignedPDF, 0o644); err != nil {
		return SignResult{}, err
	}

	sub, err := a.api.SubmitDocument(res.PublicID, signed.SignedPDF)
	status := "submitted"
	if err != nil {
		status = "local-only (upload failed: " + err.Error() + ")"
	} else if v, ok := sub["status"].(string); ok {
		status = v
	}
	return SignResult{
		OutputPath: outPath, PublicID: res.PublicID, VerificationURL: res.VerificationURL,
		OriginalSHA512: origHash, SignedSHA512: signed.SignedSHA512, ServerStatus: status,
	}, nil
}

// ---- 5. Verify PDF (local) ----

func (a *App) VerifyPDF(path string) (json.RawMessage, error) {
	pdf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rootPEM, err := a.store.RootPEM()
	if err != nil {
		return nil, errors.New("no Root CA cached; register the device or import the Root CA first")
	}
	chainPEM, _ := a.store.ChainPEM()
	var crlPEM []byte
	if b, err := a.api.PublicCRL(); err == nil {
		crlPEM = b
	}
	res, err := verification.VerifyPDF(pdf, verification.Options{
		RootPEM: rootPEM, IntermediatePEM: chainPEM, CRLPEM: crlPEM,
		RequireMLDSAOnly: true, Timeout: 20 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	return b, nil
}

// ---- 6. History ----

func (a *App) History() ([]map[string]any, error) { return a.api.MySignatures() }

// ---- 7. Security settings ----

// SetPIN re-wraps the existing key: unwrap with oldPIN, wrap with newPIN.
func (a *App) SetPIN(oldPIN, newPIN string) error {
	keyPEM, err := a.store.LoadKey(keystore.Options{PIN: oldPIN})
	if err != nil {
		return fmt.Errorf("current PIN/DPAPI check failed: %w", err)
	}
	defer wipe(keyPEM)
	if err := a.store.SaveKey(keyPEM, keystore.Options{PIN: newPIN}); err != nil {
		return err
	}
	s, _ := a.store.State()
	s.HasPIN = newPIN != ""
	return a.store.SaveState(s)
}

func (a *App) ReportLost() error {
	s, _ := a.store.State()
	if s.DeviceID == "" {
		return errors.New("no device id on record")
	}
	return a.api.ReportLost(s.DeviceID)
}

// Reset wipes the local vault (uninstall / lost-key recovery, §12.3, M4 gate).
func (a *App) Reset() error { return a.store.Reset() }

// ---- helpers ----

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func firstErr(vr *verification.Result, err error) any {
	if err != nil {
		return err
	}
	if vr != nil && len(vr.Signatures) > 0 && len(vr.Signatures[0].Errors) > 0 {
		return vr.Signatures[0].Errors[0]
	}
	return "invalid"
}
