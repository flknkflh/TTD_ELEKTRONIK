package api

import (
	"context"
	"crypto/x509"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

func (li *LabIssuer) renewWindow() time.Duration {
	days := li.RenewDays
	if days <= 0 {
		days = 30
	}
	return time.Duration(days) * 24 * time.Hour
}

// RenewDueCertificates re-issues device certificates from the CSR stored at
// enrolment — same device key, identity from the account, nothing to do on
// the device — when they expire within the renewal window (and a new one
// would last meaningfully longer), or when they were issued by an Intermediate
// that has since been rotated out. The old certificate is not revoked:
// documents and apps still using it keep working until it expires, and apps
// fetch the new one on their next certificate check. Inactive accounts and
// devices are skipped, as is a certificate with a newer one for its device.
// It returns how many certificates were renewed; StartBackground calls it
// hourly.
func (s *Server) RenewDueCertificates(ctx context.Context) int {
	if !s.issuerReady() {
		return 0
	}
	li := s.cfg.LabIssuer
	chain, err := certutil.ParseChainPEM(s.caChain())
	if err != nil || len(chain) == 0 {
		return 0
	}
	current := chain[0]
	now := time.Now()
	nextNotAfter := now.Add(time.Duration(li.certDays()) * 24 * time.Hour)
	if nextNotAfter.After(current.NotAfter) {
		nextNotAfter = current.NotAfter
	}

	renewed := 0
	for _, c := range s.st.CertificatesExpiringBefore(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)) {
		if ctx.Err() != nil {
			break
		}
		expiring := c.NotAfter.Before(now.Add(li.renewWindow())) && nextNotAfter.After(c.NotAfter.Add(24*time.Hour))
		if !expiring && issuedBy(c, current) {
			continue
		}
		if latest, err := s.st.CertificateByDevice(c.DeviceID); err != nil || latest.ID != c.ID {
			continue
		}
		if acc, err := s.st.Account(c.AccountID); err != nil || acc.Status != store.AccountActive {
			continue
		}
		if dev, err := s.st.Device(c.DeviceID); err != nil || dev.Status != store.DeviceActive {
			continue
		}
		e, err := s.st.Enrollment(c.EnrollmentID)
		if err != nil {
			continue
		}
		leaf, err := s.issueViaCA(ctx, e)
		var stored store.Certificate
		if err == nil {
			stored, err = s.bindIssuedCert(e, leaf)
		}
		if err != nil {
			s.st.Append(store.AuditEvent{Type: "certificate.renew", AccountID: c.AccountID, DeviceID: c.DeviceID,
				Result: "fail", Detail: c.Serial + ": " + err.Error()})
			continue
		}
		s.st.Append(store.AuditEvent{Type: "certificate.renew", AccountID: c.AccountID, DeviceID: c.DeviceID,
			Result: "ok", Detail: c.Serial + " -> " + stored.Serial})
		renewed++
	}
	return renewed
}

// issuedBy reports whether c was signed by ca. An unparseable certificate
// counts as issued by it, so it is never re-issued in a loop.
func issuedBy(c store.Certificate, ca *x509.Certificate) bool {
	cert, err := certutil.ParseCertificatePEM(c.PEM)
	if err != nil {
		return true
	}
	return cert.CheckSignatureFrom(ca) == nil
}
