package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Online CA issuer (split CA, production). The Root CA key never exists on the
// server. On first start the server has ca-admin create the Intermediate key
// (sealed under the Intermediate passphrase) and its CSR; a super admin carries
// the CSR to the offline Root, which signs it, and installs the certificate
// here. From then on device certificates are issued on enrolment and the CRL
// is republished daily. Until then the server runs, but issues nothing.

func (li *LabIssuer) file(parts ...string) string {
	return filepath.Join(append([]string{li.Dir}, parts...)...)
}

func (li *LabIssuer) installed() bool {
	_, err := os.Stat(li.file("intermediate", "cert.pem"))
	return err == nil
}

func (li *LabIssuer) pendingCSR() ([]byte, error) {
	return os.ReadFile(li.file("intermediate", "request.csr.pem"))
}

func (li *LabIssuer) hasRootKey() bool {
	for _, name := range []string{"key.pem", "key.pem.enc"} {
		if _, err := os.Stat(li.file("root", name)); err == nil {
			return true
		}
	}
	return false
}

// issuerReady reports an issuer that can sign device certificates and CRLs.
func (s *Server) issuerReady() bool {
	li := s.cfg.LabIssuer
	return li != nil && li.installed()
}

// caChain is the active Root+Intermediate chain: Config.CAChainPEM, or the
// issuer's once its Intermediate is installed.
func (s *Server) caChain() []byte {
	s.caMu.RLock()
	defer s.caMu.RUnlock()
	return s.chain
}

// useIssuerChain checks the issuer's published chain against the configured
// Root CA and makes it the active chain.
func (s *Server) useIssuerChain() error {
	chain, err := os.ReadFile(s.cfg.LabIssuer.file("public", "ca-chain.pem"))
	if err != nil {
		return err
	}
	certs, err := certutil.ParseChainPEM(chain)
	if err != nil || len(certs) < 2 {
		return errors.New("ca-chain.pem must hold the Intermediate and the Root")
	}
	root, err := certutil.ParseCertificatePEM(s.cfg.RootCAPEM)
	if err != nil {
		return err
	}
	if !certs[len(certs)-1].Equal(root) {
		return errors.New("the issuer's Root is not the configured Root CA")
	}
	if err := certs[0].CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("the Intermediate is not signed by the configured Root CA: %w", err)
	}
	s.caMu.Lock()
	s.chain = chain
	s.caMu.Unlock()
	return nil
}

// prepareIssuer runs at startup. An online issuer must hold no Root key and
// have its passphrase; without an Intermediate it gets a key + CSR created.
// An installed issuer's chain is verified and activated.
func (s *Server) prepareIssuer() error {
	li := s.cfg.LabIssuer
	if li == nil {
		return nil
	}
	if li.Online {
		if li.hasRootKey() {
			return fmt.Errorf("api: %s holds a Root CA private key — refusing to start (the Root stays offline)", li.Dir)
		}
		if len(li.Passphrase) < 16 {
			return errors.New("api: the online CA issuer needs the Intermediate passphrase (PQC_CA_INTERMEDIATE_PASSPHRASE_FILE, 16+ characters)")
		}
		if !li.installed() {
			if _, err := li.pendingCSR(); err != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				out, err := li.run(ctx, "intermediate-csr", "--dir", li.Dir, "--inter-cn", firstNonEmpty(li.InterCN, "PQC Device Signing CA"))
				if err != nil {
					return fmt.Errorf("api: create the Intermediate key + CSR: %s", clip(out, 400))
				}
				log.Printf("api: Intermediate key + CSR created in %s — have the offline Root sign it, then install it", li.Dir)
			} else {
				log.Printf("api: CA issuer waiting for the Intermediate certificate (CSR in %s)", li.file("intermediate"))
			}
			return nil
		}
	}
	if !li.installed() {
		return nil
	}
	if err := s.useIssuerChain(); err != nil {
		return fmt.Errorf("api: CA issuer %s: %w", li.Dir, err)
	}
	return nil
}

func (s *Server) issuerStatus() map[string]any {
	li := s.cfg.LabIssuer
	if li == nil {
		return map[string]any{"mode": "offline"}
	}
	out := map[string]any{"mode": "lab"}
	if li.Online {
		out["mode"] = "online"
	}
	if !li.installed() {
		_, err := li.pendingCSR()
		out["state"] = "pending"
		out["csr_available"] = err == nil
		return out
	}
	out["state"] = "active"
	if certs, err := certutil.ParseChainPEM(s.caChain()); err == nil && len(certs) > 0 {
		c := certs[0]
		out["intermediate"] = map[string]any{
			"subject":     c.Subject.CommonName,
			"fingerprint": certutil.FingerprintSHA256(c),
			"not_after":   fmtTime(c.NotAfter),
		}
	}
	return out
}

// hIssuerStatus (super admin): GET /api/v1/admin/ca/issuer.
func (s *Server) hIssuerStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.issuerStatus())
}

// hIntermediateCSR (super admin): GET /api/v1/admin/ca/intermediate.csr — the
// pending request to carry to the offline Root.
func (s *Server) hIntermediateCSR(w http.ResponseWriter, r *http.Request) {
	li := s.cfg.LabIssuer
	if li == nil || !li.Online {
		writeErr(w, http.StatusNotFound, "tidak ada CA penerbit online")
		return
	}
	csr, err := li.pendingCSR()
	if err != nil {
		writeErr(w, http.StatusNotFound, "tidak ada permintaan Intermediate yang menunggu")
		return
	}
	w.Header().Set("Content-Type", "application/pkcs10")
	w.Header().Set("Content-Disposition", `attachment; filename="intermediate.csr.pem"`)
	_, _ = w.Write(csr)
}

// hInstallIntermediate (super admin): POST /api/v1/admin/ca/intermediate with
// the Root-signed certificate PEM. ca-admin checks it is a pathlen:0 CA from
// the configured Root for the key generated here; the first CRL follows.
func (s *Server) hInstallIntermediate(w http.ResponseWriter, r *http.Request) {
	li := s.cfg.LabIssuer
	if li == nil || !li.Online {
		writeErr(w, http.StatusNotFound, "tidak ada CA penerbit online")
		return
	}
	if li.installed() {
		writeErr(w, http.StatusConflict, "sertifikat Intermediate sudah terpasang")
		return
	}
	body, err := readBody(r, 64<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	tmp, err := os.MkdirTemp("", "pqc-inter-")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tmp")
		return
	}
	defer os.RemoveAll(tmp)
	certPath, rootPath := filepath.Join(tmp, "intermediate.crt.pem"), filepath.Join(tmp, "root.crt.pem")
	if os.WriteFile(certPath, body, 0o600) != nil || os.WriteFile(rootPath, s.cfg.RootCAPEM, 0o600) != nil {
		writeErr(w, http.StatusInternalServerError, "tmp")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	c := claims(r)
	if out, err := li.run(ctx, "install-intermediate", "--dir", li.Dir, "--cert", certPath, "--root-cert", rootPath); err != nil {
		s.st.Append(store.AuditEvent{Type: "ca.intermediate.install", AccountID: c.Sub, Result: "fail", Detail: clip(out, 300)})
		writeErr(w, http.StatusBadRequest, "sertifikat Intermediate ditolak: "+clip(out, 400))
		return
	}
	if err := s.useIssuerChain(); err != nil {
		writeErr(w, http.StatusInternalServerError, "rantai CA tidak valid setelah pemasangan: "+err.Error())
		return
	}
	st := s.issuerStatus()
	fp := ""
	if i, ok := st["intermediate"].(map[string]any); ok {
		fp, _ = i["fingerprint"].(string)
	}
	s.st.Append(store.AuditEvent{Type: "ca.intermediate.install", AccountID: c.Sub, Result: "ok", Detail: fp})
	out := map[string]any{"issuer": st, "crl_published": true}
	if err := s.refreshCRL(r.Context(), c.Sub, ""); err != nil {
		out["crl_published"] = false
		out["crl_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// StartBackground runs periodic jobs until ctx ends. With a ready issuer the
// CRL is republished when there is none or it is over a day old (checked
// hourly), so its 7-day nextUpdate never lapses.
func (s *Server) StartBackground(ctx context.Context) {
	if s.cfg.LabIssuer == nil {
		return
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if s.issuerReady() && s.crlDue() {
				if err := s.refreshCRL(ctx, "system", ""); err != nil {
					log.Printf("api: scheduled CRL publication failed: %v", err)
					s.st.Append(store.AuditEvent{Type: "crl.publish", Result: "fail", Detail: err.Error()})
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (s *Server) crlDue() bool {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return len(s.crl) == 0 || time.Since(s.crlRec.ThisUpdate) > 24*time.Hour
}
