package api

import (
	"html"
	"net/http"
	"net/url"
)

// hVerifyPage is the human-facing landing page the QR code points at
// (Rencana V1 §16.3): GET /v/{public_id}. It renders the display-safe server
// record. Cryptographic integrity is still checked from the PDF file itself
// via POST /api/v1/verify — this page only confirms the record matches.
func (s *Server) hVerifyPage(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("public_id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	sig, err := s.st.Signature(pid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(verifyPageShell("Tidak ditemukan", `
			<p class="bad">Tidak ada catatan tanda tangan dengan ID <code>`+html.EscapeString(pid)+`</code>.</p>
			<p class="muted">Pastikan QR dipindai dari dokumen yang benar, atau dokumen ini belum pernah diserahkan ke server.</p>`)))
		return
	}
	a, _ := s.st.Account(sig.AccountID)
	d, _ := s.st.Device(sig.DeviceID)
	rec := s.publicRecord(sig, a, d)

	_, objErr := s.st.GetObject(sig.StorageObjectKey)
	docURL := "/v/" + url.PathEscape(pid) + "/document"

	status := str(rec["certificate_status"])
	badge := `<span class="badge ok">TERVERIFIKASI</span>`
	statusNote := "Sertifikat penanda tangan aktif saat halaman ini dibuka."
	switch status {
	case "revoked":
		badge = `<span class="badge bad">DICABUT</span>`
		statusNote = "Sertifikat penanda tangan telah DICABUT. Tanda tangan ini tidak lagi sah."
	case "device_reported_lost":
		badge = `<span class="badge warn">PERANGKAT DILAPORKAN HILANG</span>`
		statusNote = "Perangkat penanda tangan dilaporkan hilang. Perlakukan tanda tangan ini dengan hati-hati."
	}

	rows := ""
	add := func(k, v string) {
		if v == "" {
			return
		}
		rows += "<tr><th>" + html.EscapeString(k) + "</th><td>" + html.EscapeString(v) + "</td></tr>"
	}
	add("Penanda tangan", str(rec["signer_name"]))
	add("Perangkat", str(rec["device_label"]))
	add("No. sertifikat", str(rec["certificate_serial"]))
	add("Sidik jari sertifikat", str(rec["certificate_fingerprint"]))
	add("Waktu tanda tangan (klaim perangkat)", str(rec["client_claimed_signing_time"]))
	add("Diterima server", str(rec["server_received_at"]))
	add("SHA-512 dokumen bertanda tangan", str(rec["signed_pdf_sha512"]))
	add("ID verifikasi", str(rec["public_id"]))

	doc := ""
	if objErr == nil {
		doc = `
		<div class="doc">
		  <h2>Dokumen asli yang ditandatangani</h2>
		  <p class="muted">Bandingkan berkas di bawah ini dengan dokumen yang Anda terima.
		  Jika isinya berbeda, berarti QR ini ditempelkan pada dokumen lain — dokumen yang
		  Anda pegang tidak asli.</p>
		  <iframe src="` + docURL + `" title="Dokumen bertanda tangan"></iframe>
		  <p><a class="btn" href="` + docURL + `" target="_blank" rel="noopener">Buka / unduh dokumen asli</a></p>
		</div>`
	}

	body := `
		<div class="status">` + badge + `<p>` + html.EscapeString(statusNote) + `</p></div>
		<table>` + rows + `</table>
		<p class="muted">` + html.EscapeString(str(rec["note"])) + `</p>` + doc + `
		<p class="muted">Untuk memeriksa keutuhan isi dokumen secara kriptografis, unggah berkas PDF ke
		<code>/api/v1/verify</code> atau lewat aplikasi. Halaman ini mencocokkan catatan server
		dan menampilkan berkas asli dari server.</p>`
	_, _ = w.Write([]byte(verifyPageShell("Verifikasi Tanda Tangan", body)))
}

// hPublicDocument serves the authoritative signed PDF behind a QR code:
// GET /v/{public_id}/document, no account required. The public_id is a
// 96-bit random token printed on the document itself, so only someone who
// already holds the document can resolve it. Serving the real file lets a
// verifier without the app compare it against the paper in hand: a QR
// lifted onto a different document shows a different file here.
func (s *Server) hPublicDocument(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("public_id")
	sig, err := s.st.Signature(pid)
	if err != nil {
		http.Error(w, "tidak ada dokumen dengan ID itu", http.StatusNotFound)
		return
	}
	b, err := s.st.GetObject(sig.StorageObjectKey)
	if err != nil {
		http.Error(w, "berkas dokumen tidak tersedia di server", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `inline; filename="`+pid+`.pdf"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func verifyPageShell(title, inner string) string {
	return `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + ` — PQC PDF Sign</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         background:#f4f5f7; color:#16181d; }
  @media (prefers-color-scheme:dark){ body{ background:#14161a; color:#e6e8ec; } }
  .wrap { max-width:640px; margin:0 auto; padding:22px 16px; }
  h1 { font-size:18px; margin:0 0 4px; }
  .sub { opacity:.65; font-size:13px; margin:0 0 18px; }
  .card { background:#fff; border:1px solid #e2e4e8; border-radius:12px; padding:18px; }
  @media (prefers-color-scheme:dark){ .card{ background:#1c1f25; border-color:#2c2f36; } }
  .status { text-align:center; margin-bottom:16px; }
  .status p { margin:10px 0 0; font-size:14px; }
  .badge { display:inline-block; padding:6px 16px; border-radius:999px; font-weight:700;
           letter-spacing:.05em; font-size:14px; }
  .badge.ok  { background:#dcfce7; color:#166534; }
  .badge.bad { background:#fee2e2; color:#991b1b; }
  .badge.warn{ background:#fef3c7; color:#92400e; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin:6px 0 14px; }
  th,td { text-align:left; padding:8px 6px; border-bottom:1px solid #e2e4e8; vertical-align:top; }
  @media (prefers-color-scheme:dark){ th,td{ border-color:#2c2f36; } }
  th { opacity:.6; font-weight:600; white-space:nowrap; width:42%; }
  td { word-break:break-all; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .muted { opacity:.6; font-size:12px; }
  .bad { color:#991b1b; font-weight:600; }
  h2 { font-size:15px; margin:20px 0 6px; }
  .doc iframe { width:100%; height:440px; border:1px solid #e2e4e8; border-radius:8px;
                background:#fff; margin-top:8px; }
  @media (prefers-color-scheme:dark){ .doc iframe{ border-color:#2c2f36; } }
  .btn { display:inline-block; margin-top:10px; padding:9px 16px; border-radius:8px;
         background:#4f46e5; color:#fff; text-decoration:none; font-weight:600; font-size:13px; }
  .btn:hover { background:#4338ca; }
</style></head><body><div class="wrap">
<h1>Verifikasi Tanda Tangan Digital</h1>
<p class="sub">PQC PDF Sign · ML-DSA-65 (FIPS 204)</p>
<div class="card">` + inner + `</div></div></body></html>`
}
