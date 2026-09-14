package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// The active CRL. It used to live only in memory, so a restart dropped every
// imported revocation from the upload verifier, /public/ca/crl.pem and the
// apps that download it. It is now kept in the database (migration 0009), and
// only a CRL signed by this server's CA and newer than the active one can
// replace it — an old CRL can never quietly un-revoke a certificate.

func (s *Server) currentCRL() []byte {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return s.crl
}

// checkCRL parses a PEM or DER CRL — or a PEM bundle, whose first CRL is the
// active Intermediate's and the rest are retired Intermediates' — and requires
// a CRL number and a signature by a certificate of this server's CA on every
// CRL. It returns the first CRL and the bundle re-encoded as PEM.
func (s *Server) checkCRL(b []byte) (*x509.RevocationList, []byte, error) {
	crls, err := certutil.ParseCRLs(b)
	if err != nil {
		return nil, nil, fmt.Errorf("bukan CRL yang valid: %w", err)
	}
	chain, _ := certutil.ParseChainPEM(append(append([]byte{}, s.caChain()...), s.cfg.RootCAPEM...))
	var out []byte
	for _, rl := range crls {
		if rl.Number == nil {
			return nil, nil, errors.New("CRL tidak memiliki nomor (CRLNumber)")
		}
		signed := false
		for _, c := range chain {
			if rl.CheckSignatureFrom(c) == nil {
				signed = true
				break
			}
		}
		if !signed {
			return nil, nil, errors.New("CRL tidak ditandatangani oleh CA server ini")
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rl.Raw})...)
	}
	return crls[0], out, nil
}

func crlRecord(rl *x509.RevocationList, pemBytes []byte, source, actor string) store.CRL {
	return store.CRL{
		Number: rl.Number.String(), ThisUpdate: rl.ThisUpdate, NextUpdate: rl.NextUpdate,
		Entries: len(rl.RevokedCertificateEntries), PEM: pemBytes, Source: source, ImportedBy: actor,
	}
}

func crlDetail(c store.CRL) string {
	return fmt.Sprintf("CRL #%s, %d entries", c.Number, c.Entries)
}

// activeCRLNumber is the active CRL's number, nil when there is none. Callers
// hold crlMu, or run before the server handles requests.
func (s *Server) activeCRLNumber() *big.Int {
	if len(s.crl) == 0 {
		return nil
	}
	n, ok := new(big.Int).SetString(s.crlRec.Number, 10)
	if !ok {
		return nil
	}
	return n
}

// loadCRL activates the newest stored CRL at startup. A CRL from
// Config.CRLPEM (PQC_CRL_PEM) must be valid; when it is newer than the stored
// one it becomes active and is recorded. A stale CRL is still served — better
// than none — and the admin console flags it.
func (s *Server) loadCRL() error {
	if rec, err := s.st.LatestCRL(); err == nil {
		if _, _, cerr := s.checkCRL(rec.PEM); cerr != nil {
			log.Printf("api: stored CRL #%s ignored: %v", rec.Number, cerr)
		} else {
			s.crl, s.crlRec = rec.PEM, rec
		}
	}
	if len(s.cfg.CRLPEM) == 0 {
		return nil
	}
	rl, pemBytes, err := s.checkCRL(s.cfg.CRLPEM)
	if err != nil {
		return fmt.Errorf("api: CRLPEM: %w", err)
	}
	if cur := s.activeCRLNumber(); cur != nil && rl.Number.Cmp(cur) <= 0 {
		return nil
	}
	rec := crlRecord(rl, pemBytes, "config", "")
	if err := s.st.SaveCRL(rec); err != nil {
		return fmt.Errorf("api: save CRL: %w", err)
	}
	s.crl, s.crlRec = pemBytes, rec
	return nil
}

// replaceCRL validates b, requires it to be unexpired and newer than the
// active CRL, stores it, and makes it active.
func (s *Server) replaceCRL(b []byte, source, actor string) (store.CRL, error) {
	rl, pemBytes, err := s.checkCRL(b)
	if err != nil {
		return store.CRL{}, err
	}
	if !rl.NextUpdate.IsZero() && time.Now().After(rl.NextUpdate) {
		return store.CRL{}, fmt.Errorf("CRL #%s sudah kedaluwarsa (nextUpdate %s) — terbitkan CRL baru",
			rl.Number, rl.NextUpdate.UTC().Format(time.RFC3339))
	}
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	if cur := s.activeCRLNumber(); cur != nil && rl.Number.Cmp(cur) <= 0 {
		return store.CRL{}, fmt.Errorf("CRL #%s tidak lebih baru dari CRL aktif #%s", rl.Number, cur)
	}
	rec := crlRecord(rl, pemBytes, source, actor)
	if err := s.st.SaveCRL(rec); err != nil {
		return store.CRL{}, fmt.Errorf("simpan CRL: %w", err)
	}
	s.crl, s.crlRec = pemBytes, rec
	return rec, nil
}

// crlStatus describes the active CRL for the admin console; nil when none.
func (s *Server) crlStatus() map[string]any {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	if len(s.crl) == 0 {
		return nil
	}
	c := s.crlRec
	out := map[string]any{
		"number":      c.Number,
		"this_update": fmtTime(c.ThisUpdate),
		"entries":     c.Entries,
		"source":      c.Source,
		"stale":       false,
	}
	if !c.NextUpdate.IsZero() {
		out["next_update"] = fmtTime(c.NextUpdate)
		out["stale"] = time.Now().After(c.NextUpdate)
	}
	return out
}

// refreshCRL publishes a fresh CRL through the issuer and makes it active.
// Without a ready issuer it does nothing: an offline CA operator issues the
// CRL with ca-admin and imports it.
func (s *Server) refreshCRL(ctx context.Context, actor, accountID string) error {
	if !s.issuerReady() {
		return nil
	}
	pemBytes, err := s.publishCRLViaCA(ctx)
	if err != nil || len(pemBytes) == 0 {
		return err
	}
	rec, err := s.replaceCRL(pemBytes, "ca", actor)
	if err != nil {
		return err
	}
	s.st.Append(store.AuditEvent{Type: "crl.publish", AccountID: accountID, Result: "ok", Detail: crlDetail(rec)})
	return nil
}

// caReason maps a free-text revoke reason onto an RFC 5280 name ca-admin accepts.
func caReason(reason string) string {
	switch reason = strings.TrimSpace(reason); reason {
	case "keyCompromise", "cACompromise", "affiliationChanged", "superseded",
		"cessationOfOperation", "certificateHold", "privilegeWithdrawn":
		return reason
	}
	return "unspecified"
}
