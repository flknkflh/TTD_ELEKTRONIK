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
// here. From then on device certificates are issued on enrolment, renewed
// before expiry, and the CRL is republished daily.
//
// Rotation: when the Intermediate has less than LabIssuer.RotateDays left (or
// a super admin starts it), the server prepares the next Intermediate key +
// CSR. After the Root signs it and it is installed, the old Intermediate
// retires — it stays in the chain and signs its own CRL while valid — and
// every device certificate it issued is re-issued from the new one.

func (li *LabIssuer) file(parts ...string) string {
	return filepath.Join(append([]string{li.Dir}, parts...)...)
}

func (li *LabIssuer) installed() bool {
	_, err := os.Stat(li.file("intermediate", "cert.pem"))
	return err == nil
}

// nextPending reports a prepared rotation waiting for the Root's signature.
func (li *LabIssuer) nextPending() bool {
	_, err := os.Stat(li.file("next", "request.csr.pem"))
	return err == nil
}

// pendingCSR is the request waiting for the Root: the first Intermediate's,
// or the next one's during a rotation.
func (li *LabIssuer) pendingCSR() ([]byte, error) {
	if b, err := os.ReadFile(li.file("intermediate", "request.csr.pem")); err == nil {
		return b, nil
	}
	return os.ReadFile(li.file("next", "request.csr.pem"))
}

func (li *LabIssuer) hasRootKey() bool {
	for _, name := range []string{"key.pem", "key.pem.enc"} {
		if _, err := os.Stat(li.file("root", name)); err == nil {
			return true
		}
	}
	return false
}

func (li *LabIssuer) rotateWindow() time.Duration {
	days := li.RotateDays
	if days <= 0 {
		days = 730
	}
	return time.Duration(days) * 24 * time.Hour
}

// issuerReady reports an issuer that can sign device certificates and CRLs.
func (s *Server) issuerReady() bool {
	li := s.cfg.LabIssuer
	return li != nil && li.installed()
}

// caChain is the active chain: the Intermediate, retired Intermediates still
// valid, then the Root — Config.CAChainPEM, or the issuer's once installed.
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
	for _, c := range certs[:len(certs)-1] {
		if err := c.CheckSignatureFrom(root); err != nil {
			return fmt.Errorf("Intermediate %s is not signed by the configured Root CA: %w", c.Subject.CommonName, err)
		}
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

// currentIntermediate is the active Intermediate certificate, nil when none.
func (s *Server) currentIntermediate() []any {
	certs, err := certutil.ParseChainPEM(s.caChain())
	if err != nil || len(certs) < 2 {
		return nil
	}
	out := make([]any, 0, len(certs)-1)
	for _, c := range certs[:len(certs)-1] {
		out = append(out, map[string]any{
			"subject":     c.Subject.CommonName,
			"fingerprint": certutil.FingerprintSHA256(c),
			"not_after":   fmtTime(c.NotAfter),
		})
	}
	return out
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
	out["next_pending"] = li.nextPending()
	if inters := s.currentIntermediate(); len(inters) > 0 {
		out["intermediate"] = inters[0]
		out["retired"] = inters[1:]
	}
	return out
}

// startRotation has ca-admin prepare the next Intermediate key + CSR.
func (s *Server) startRotation(ctx context.Context, actor, why string) error {
	li := s.cfg.LabIssuer
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := li.run(ctx, "intermediate-csr", "--dir", li.Dir, "--next", "--inter-cn", firstNonEmpty(li.InterCN, "PQC Device Signing CA"))
	if err != nil {
		s.st.Append(store.AuditEvent{Type: "ca.rotation.start", AccountID: actor, Result: "fail", Detail: clip(out, 300)})
		return fmt.Errorf("ca-admin intermediate-csr --next: %s", clip(out, 400))
	}
	s.st.Append(store.AuditEvent{Type: "ca.rotation.start", AccountID: actor, Result: "ok", Detail: why})
	log.Printf("api: Intermediate rotation prepared (%s) — have the offline Root sign the CSR in %s", why, li.file("next"))
	return nil
}

// CheckIntermediateRotation prepares the next Intermediate when the active one
// has less than the rotation window left and no rotation is pending. It
// reports whether it started one; StartBackground calls it hourly.
func (s *Server) CheckIntermediateRotation(ctx context.Context) bool {
	li := s.cfg.LabIssuer
	if !s.issuerReady() || !li.Online || li.nextPending() {
		return false
	}
	certs, err := certutil.ParseChainPEM(s.caChain())
	if err != nil || len(certs) < 2 || time.Until(certs[0].NotAfter) > li.rotateWindow() {
		return false
	}
	return s.startRotation(ctx, "system", "Intermediate expires "+fmtTime(certs[0].NotAfter)) == nil
}

// hIssuerStatus (super admin): GET /api/v1/admin/ca/issuer.
func (s *Server) hIssuerStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.issuerStatus())
}

// hStartRotation (super admin): POST /api/v1/admin/ca/rotate — prepare the
// next Intermediate now (before the automatic window, e.g. after an incident).
func (s *Server) hStartRotation(w http.ResponseWriter, r *http.Request) {
	li := s.cfg.LabIssuer
	if li == nil || !li.Online {
		writeErr(w, http.StatusNotFound, "tidak ada CA penerbit online")
		return
	}
	if !li.installed() {
		writeErr(w, http.StatusConflict, "belum ada Intermediate terpasang")
		return
	}
	if li.nextPending() {
		writeErr(w, http.StatusConflict, "rotasi sudah menunggu tanda tangan Root")
		return
	}
	if err := s.startRotation(r.Context(), claims(r).Sub, "started by the super admin"); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.issuerStatus())
}

// hIntermediateCSR (super admin): GET /api/v1/admin/ca/intermediate.csr — the
// pending request (first Intermediate or rotation) to carry to the Root.
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
	name := "intermediate.csr.pem"
	if li.installed() {
		name = "intermediate-next.csr.pem"
	}
	w.Header().Set("Content-Type", "application/pkcs10")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(csr)
}

// hInstallIntermediate (super admin): POST /api/v1/admin/ca/intermediate with
// the Root-signed certificate PEM. ca-admin checks it is a pathlen:0 CA from
// the configured Root for the key generated here. During a rotation it
// replaces the active Intermediate and retires the old one; device
// certificates are then re-issued by the hourly renewal. A CRL follows.
func (s *Server) hInstallIntermediate(w http.ResponseWriter, r *http.Request) {
	li := s.cfg.LabIssuer
	if li == nil || !li.Online {
		writeErr(w, http.StatusNotFound, "tidak ada CA penerbit online")
		return
	}
	rotate := li.installed()
	if rotate && !li.nextPending() {
		writeErr(w, http.StatusConflict, "sertifikat Intermediate sudah terpasang; mulai rotasi dulu untuk menggantinya")
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
	args := []string{"install-intermediate", "--dir", li.Dir, "--cert", certPath, "--root-cert", rootPath}
	event := "ca.intermediate.install"
	if rotate {
		args = append(args, "--rotate")
		event = "ca.intermediate.rotate"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	c := claims(r)
	if out, err := li.run(ctx, args...); err != nil {
		s.st.Append(store.AuditEvent{Type: event, AccountID: c.Sub, Result: "fail", Detail: clip(out, 300)})
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
	s.st.Append(store.AuditEvent{Type: event, AccountID: c.Sub, Result: "ok", Detail: fp})
	out := map[string]any{"issuer": st, "rotated": rotate, "crl_published": true}
	if err := s.refreshCRL(r.Context(), c.Sub, ""); err != nil {
		out["crl_published"] = false
		out["crl_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// StartBackground runs periodic jobs until ctx ends. With a ready issuer,
// checked hourly: the CRL is republished when there is none or it is over a
// day old, so its 7-day nextUpdate never lapses; a rotation is prepared when
// the Intermediate nears its end; and device certificates near expiry or from
// a retired Intermediate are re-issued (renew.go).
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
			s.CheckIntermediateRotation(ctx)
			if n := s.RenewDueCertificates(ctx); n > 0 {
				log.Printf("api: renewed %d device certificate(s)", n)
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
