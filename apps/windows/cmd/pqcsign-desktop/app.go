//go:build windows

package main

import (
	"context"

	"example.internal/pqc-pdf-sign/apps/windows/internal/appcore"
)

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
	core, err := appcore.New(appcore.Config{}) // vault: %LOCALAPPDATA%\PQC-PDF-Sign
	if err == nil {
		a.core = core
	}
}

// Connect (re)points the client at a server URL. insecureTLS is lab-only.
func (a *App) Connect(serverURL string, insecureTLS bool) error {
	if a.core == nil {
		c, err := appcore.New(appcore.Config{ServerURL: serverURL, InsecureTLS: insecureTLS})
		if err != nil {
			return err
		}
		a.core = c
		return nil
	}
	return a.core.SetServerURL(serverURL, insecureTLS)
}

func (a *App) Login(email, password, totpCode string) error {
	return a.core.Login(email, password, totpCode)
}

func (a *App) RegisterDevice(label, pin string) (appcore.EnrollResult, error) {
	return a.core.RegisterDevice(label, pin)
}

func (a *App) CertificateStatus(pin string) (appcore.CertStatus, error) {
	return a.core.CertificateStatus(pin)
}

func (a *App) SignPDF(inPath, outPath, reason, signerName, pin string) (appcore.SignResult, error) {
	return a.core.SignPDF(inPath, outPath, reason, signerName, pin)
}

func (a *App) VerifyPDF(path string) (string, error) {
	b, err := a.core.VerifyPDF(path)
	return string(b), err
}

func (a *App) History() ([]map[string]any, error) { return a.core.History() }

func (a *App) StartMFASetup() (appcore.MFASetup, error) { return a.core.StartMFASetup() }
func (a *App) ConfirmMFA(code string) error             { return a.core.ConfirmMFA(code) }
func (a *App) SetPIN(oldPIN, newPIN string) error       { return a.core.SetPIN(oldPIN, newPIN) }
func (a *App) ReportLost() error                        { return a.core.ReportLost() }
func (a *App) Reset() error                             { return a.core.Reset() }
