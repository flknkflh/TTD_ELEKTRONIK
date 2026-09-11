//go:build windows

package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	wails "github.com/wailsapp/wails/v2/pkg/runtime"

	"example.internal/pqc-pdf-sign/apps/windows/internal/appcore"
)

// The types below are the ONLY shapes crossing the Wails bridge. They are
// flat, primitive-only and defined in this package on purpose: the Wails
// binding generator silently produces no window.go bindings at all if any
// bound method's signature references a type it cannot traverse (a map, or a
// struct reachable from another package that contains time.Time, etc.).
type certView struct {
	State         string `json:"state"`
	Serial        string `json:"serial"`
	Subject       string `json:"subject"`
	HasDocSigning bool   `json:"has_doc_signing"`
	NotAfter      string `json:"not_after"`
}
type registerView struct {
	AccountID string `json:"account_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}
type signView struct {
	OutputPath      string `json:"output_path"`
	PublicID        string `json:"public_id"`
	VerificationURL string `json:"verification_url"`
	OriginalSHA512  string `json:"original_sha512"`
	SignedSHA512    string `json:"signed_pdf_sha512"`
	ServerStatus    string `json:"server_status"`
	Submitted       bool   `json:"submitted"`
	SubmitError     string `json:"submit_error"`
}

// App is the Wails-bound facade. Every method here is one call into appcore
// (the GUI-independent logic, Rencana V1 §20). Wails marshals args/returns to
// and from the JavaScript frontend.
type App struct {
	ctx  context.Context
	core *appcore.App
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// A GUI app has no console: keep a log beside the vault so a failed
	// upload can be diagnosed after the fact.
	if dir, err := os.UserCacheDir(); err == nil { // %LOCALAPPDATA%
		dir = filepath.Join(dir, "PQC-PDF-Sign")
		_ = os.MkdirAll(dir, 0o700)
		if f, err := os.OpenFile(filepath.Join(dir, "pqcsign.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(f)
		}
	}
	core, err := appcore.New(appcore.Config{}) // vault: %LOCALAPPDATA%\PQC-PDF-Sign
	if err == nil {
		a.core = core
		a.hookProgress()
	}
}

// hookProgress forwards signing steps to the frontend as "sign-progress"
// events ({step,total,label,pct}).
func (a *App) hookProgress() {
	a.core.SetProgress(func(step, total int, label string, pct int) {
		wails.EventsEmit(a.ctx, "sign-progress", map[string]any{
			"step": step, "total": total, "label": label, "pct": pct,
		})
	})
}

// Connect (re)points the client at a server URL. insecureTLS is lab-only.
func (a *App) Connect(serverURL string, insecureTLS bool) error {
	if a.core == nil {
		c, err := appcore.New(appcore.Config{ServerURL: serverURL, InsecureTLS: insecureTLS})
		if err != nil {
			return err
		}
		a.core = c
		a.hookProgress()
		return nil
	}
	return a.core.SetServerURL(serverURL, insecureTLS)
}

func (a *App) Register(fullName, org, email, password, position, nip string) (registerView, error) {
	r, err := a.core.Register(fullName, org, email, password, position, nip)
	return registerView{AccountID: r.AccountID, Status: r.Status, Message: r.Message}, err
}

func (a *App) Login(email, password string) error {
	return a.core.Login(email, password)
}

// VerifyPublic runs a PDF through a server's public verifier — no login.
func (a *App) VerifyPublic(serverURL, path string) (string, error) {
	b, err := a.core.VerifyPublic(serverURL, path)
	return string(b), err
}

// Prepare runs the silent device enrolment after login (Rencana RB-3).
func (a *App) Prepare(pin string) (certView, error) {
	cs, err := a.core.EnsureEnrolled(pin)
	return toCertView(cs), err
}

func (a *App) CertificateStatus(pin string) (certView, error) {
	cs, err := a.core.CertificateStatus(pin)
	return toCertView(cs), err
}

func toCertView(cs appcore.CertStatus) certView {
	v := certView{State: cs.State}
	if cs.Info != nil {
		v.Serial = cs.Info.SerialNumber
		v.Subject = cs.Info.Subject
		v.HasDocSigning = cs.Info.HasDocumentSigning
		v.NotAfter = cs.Info.NotAfter.Format("2006-01-02")
	}
	return v
}

// SignPDF takes the QR placements as a JSON array string
// ([{page,x,y,w},...], page-relative top-left fractions) so only a string
// crosses the bridge.
func (a *App) SignPDF(inPath, outPath, reason, signerName, pin, placementsJSON, issuedPlace string) (signView, error) {
	r, err := a.core.SignPDF(inPath, outPath, reason, signerName, pin, placementsJSON, issuedPlace)
	return signView{
		OutputPath: r.OutputPath, PublicID: r.PublicID, VerificationURL: r.VerificationURL,
		OriginalSHA512: r.OriginalSHA512, SignedSHA512: r.SignedSHA512, ServerStatus: r.ServerStatus,
		Submitted: r.Submitted, SubmitError: r.SubmitError,
	}, err
}

// RetrySubmit re-sends a locally saved signed PDF whose submit failed.
func (a *App) RetrySubmit(publicID, signedPath string) (string, error) {
	return a.core.RetrySubmit(publicID, signedPath)
}

// FileSize returns the size in bytes of the file at path.
func (a *App) FileSize(path string) (int64, error) { return a.core.FileSize(path) }

// MaxSignMB is the largest PDF (in MB) the app will sign.
func (a *App) MaxSignMB() int { return appcore.MaxSignBytes >> 20 }

// LoadPdfB64 returns the PDF at path as base64 for the placement preview.
func (a *App) LoadPdfB64(path string) (string, error) { return a.core.PdfBytesB64(path) }

func (a *App) VerifyPDF(path string) (string, error) {
	b, err := a.core.VerifyPDF(path)
	return string(b), err
}

// History returns the signature list as a JSON string (no map/slice-of-map on
// the bridge).
func (a *App) History() (string, error) {
	h, err := a.core.History()
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(h)
	return string(b), nil
}

// PickPDF / SaveSignedPDF open native file dialogs so the user never types a
// path (Rencana RB-3). An empty return means the user cancelled.
func (a *App) PickPDF() (string, error) {
	return wails.OpenFileDialog(a.ctx, wails.OpenDialogOptions{
		Title:   "Pilih PDF",
		Filters: []wails.FileFilter{{DisplayName: "Berkas PDF (*.pdf)", Pattern: "*.pdf"}},
	})
}

func (a *App) SaveSignedPDF(suggested string) (string, error) {
	if suggested == "" {
		suggested = "dokumen-bertandatangan.pdf"
	}
	return wails.SaveFileDialog(a.ctx, wails.SaveDialogOptions{
		Title:           "Simpan PDF bertanda tangan",
		DefaultFilename: suggested,
		Filters:         []wails.FileFilter{{DisplayName: "Berkas PDF (*.pdf)", Pattern: "*.pdf"}},
	})
}

func (a *App) ReportLost() error { return a.core.ReportLost() }
func (a *App) Reset() error      { return a.core.Reset() }

// VerifyByHash checks a local PDF against the server record for publicID by
// sending only its SHA-512. The file itself is never uploaded.
func (a *App) VerifyByHash(serverURL, publicID, path string) (string, error) {
	b, err := a.core.VerifyByHash(serverURL, publicID, path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
