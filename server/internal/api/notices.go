package api

import (
	"fmt"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
)

// caNotice is a reminder for the admin console about the CA: every admin and
// the super admin see the list (GET /api/v1/admin/capabilities → notices).
type caNotice struct {
	Level   string `json:"level"` // info | warn | critical
	Code    string `json:"code"`
	Message string `json:"message"`
}

const day = 24 * time.Hour

// caNotices derives reminders from the CA material the server holds: the Root
// nearing its end (its rotation is a manual plan, RUNBOOK §8.9), the
// Intermediate nearing its end or waiting for the Root's signature, and a
// stale CRL.
func (s *Server) caNotices() []caNotice {
	out := []caNotice{}
	now := time.Now()
	daysLeft := func(t time.Time) int { return int(t.Sub(now) / day) }

	if root, err := certutil.ParseCertificatePEM(s.cfg.RootCAPEM); err == nil {
		left := root.NotAfter.Sub(now)
		msg := fmt.Sprintf("Root CA berakhir %s (%d hari lagi). ", root.NotAfter.Format("2 Jan 2006"), daysLeft(root.NotAfter))
		switch {
		case left < 365*day:
			out = append(out, caNotice{"critical", "root_expiring", msg + "Rotasi Root harus sudah berjalan: ceremony Root baru dan rilis aplikasi dengan dua Root (RUNBOOK §8.9)."})
		case left < 2*365*day:
			out = append(out, caNotice{"warn", "root_expiring", msg + "Jalankan rencana rotasi Root sekarang (RUNBOOK §8.9)."})
		case left < 5*365*day:
			out = append(out, caNotice{"info", "root_expiring", msg + "Mulai rencanakan rotasi Root (RUNBOOK §8.9)."})
		}
	}

	li := s.cfg.LabIssuer
	if li != nil && li.Online && !li.installed() {
		out = append(out, caNotice{"warn", "issuer_pending",
			"CA penerbit menunggu sertifikat Intermediate: super admin memasangnya di menu Admin. Sertifikat perangkat belum bisa terbit."})
	}
	if certs, err := certutil.ParseChainPEM(s.caChain()); err == nil && len(certs) > 1 {
		inter := certs[0]
		left := inter.NotAfter.Sub(now)
		msg := fmt.Sprintf("Intermediate CA berakhir %s (%d hari lagi). ", inter.NotAfter.Format("2 Jan 2006"), daysLeft(inter.NotAfter))
		window := 730 * day
		if li != nil {
			window = li.rotateWindow()
		}
		switch {
		case li != nil && li.Online && li.nextPending():
			out = append(out, caNotice{"warn", "intermediate_rotation_pending", msg +
				"Rotasi disiapkan: super admin mengunduh CSR Intermediate berikutnya di menu Admin, Root menandatanganinya (RUNBOOK §8.6), lalu sertifikatnya dipasang."})
		case left < 90*day:
			out = append(out, caNotice{"critical", "intermediate_expiring", msg + "Rotasi Intermediate harus segera diselesaikan."})
		case left < window:
			out = append(out, caNotice{"warn", "intermediate_expiring", msg + "Rotasi Intermediate perlu dimulai."})
		}
	}

	if st := s.crlStatus(); st != nil && st["stale"] == true {
		out = append(out, caNotice{"critical", "crl_stale",
			"CRL sudah basi: aplikasi dan verifikator luar tidak mendapat daftar pencabutan terbaru."})
	}
	return out
}
