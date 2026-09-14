package api

import (
	"context"
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

// RenewDueCertificates re-issues device certificates that expire within the
// issuer's renewal window, from the CSR stored at enrolment: same device key,
// identity from the account, nothing to do on the device. The old certificate
// is not revoked — documents and apps still using it keep working until it
// expires — and apps fetch the new one on their next certificate check. A
// certificate is skipped when its account or device is not active, when a
// newer certificate already exists for the device, or when a new one would
// not last meaningfully longer (the Intermediate itself is near its end).
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
	now := time.Now()
	nextNotAfter := now.Add(time.Duration(li.certDays()) * 24 * time.Hour)
	if nextNotAfter.After(chain[0].NotAfter) {
		nextNotAfter = chain[0].NotAfter
	}

	renewed := 0
	for _, c := range s.st.CertificatesExpiringBefore(now.Add(li.renewWindow())) {
		if ctx.Err() != nil {
			break
		}
		if !nextNotAfter.After(c.NotAfter.Add(24 * time.Hour)) {
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
