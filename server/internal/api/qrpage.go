package api

import (
	"encoding/json"
	"html"
	"net/http"
	"strings"
)

// reqBase returns scheme://host for the incoming request — the natural
// default for the "server address" the verification pages talk to.
func reqBase(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// serverBar is the "Alamat server" control shared by every public page. The
// person scanning a QR often lands on a host their phone cannot reach (a
// local deployment bakes in localhost / a dev IP), so they can correct it
// here; the choice is remembered and every document link + API call on the
// page is rebased onto it via window.SRV.
func serverBar(defaultBase string) string {
	return `
<div class="srvbar">
  <label for="srv">Alamat server verifikasi</label>
  <div class="srvrow">
    <input id="srv" type="text" spellcheck="false" placeholder="http://192.168.x.x:8098" />
    <button id="srvApply" type="button">Terapkan</button>
  </div>
  <p class="srvhint" id="srvHint"></p>
</div>
<script>
(function(){
  var DEF = ` + jsString(defaultBase) + `;
  function clean(u){ return String(u||"").trim().replace(/\/+$/,""); }
  window.SRV = clean(localStorage.getItem("pqc_srv") || DEF);
  var box = document.getElementById("srv");
  box.value = window.SRV;
  var host = location.hostname;
  if ((host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0") &&
      !localStorage.getItem("pqc_srv")) {
    document.getElementById("srvHint").textContent =
      "Alamat ini localhost — ganti ke IP/alamat server Anda (mis. http://172.16.23.177:8098) lalu Terapkan.";
    document.querySelector(".srvbar").classList.add("warn");
  }
  document.getElementById("srvApply").addEventListener("click", function(){
    var v = clean(box.value);
    if (!/^https?:\/\//.test(v)) { v = "http://" + v; }
    localStorage.setItem("pqc_srv", v);
    location.reload();
  });
  box.addEventListener("keydown", function(e){ if (e.key === "Enter") document.getElementById("srvApply").click(); });
})();
</script>`
}

// jsString renders s as a safe JavaScript string literal (JSON encoding also
// escapes <, >, & so it is safe inside a <script> block).
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// hScanResolver is what a QR code opens: GET /s/{public_id}. It does NOT look
// anything up — it just lets the person confirm the server address and then
// sends them to that server's /v/{public_id}. This works even when the host
// baked into the QR is only reachable from the signing machine.
func (s *Server) hScanResolver(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("public_id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	body := serverBar(reqBase(r)) + `
<p class="muted">ID verifikasi: <code>` + html.EscapeString(pid) + `</code></p>
<p class="muted">Pastikan alamat server di atas benar, lalu buka hasil verifikasinya.</p>
<p><button class="btn" id="go" type="button">Lihat hasil verifikasi →</button></p>
<script>
document.getElementById("go").addEventListener("click", function(){
  location.href = window.SRV + "/v/" + ` + jsString(pid) + `;
});
</script>`
	_, _ = w.Write([]byte(verifyPageShell("Buka Verifikasi", body)))
}

// hVerifyPage is the human-facing landing page (GET /v/{public_id}). It
// renders the display-safe server record and embeds the authoritative signed
// PDF. Cryptographic integrity is still checked from the PDF file itself via
// POST /api/v1/verify.
func (s *Server) hVerifyPage(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("public_id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	sig, err := s.st.Signature(pid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(verifyPageShell("Tidak ditemukan", serverBar(reqBase(r))+`
			<p class="bad">Tidak ada catatan tanda tangan dengan ID <code>`+html.EscapeString(pid)+`</code> di server ini.</p>
			<p class="muted">Jika alamat server di atas salah, perbaiki lalu Terapkan. Atau dokumen ini belum pernah diserahkan ke server.</p>`)))
		return
	}
	a, _ := s.st.Account(sig.AccountID)
	d, _ := s.st.Device(sig.DeviceID)
	rec := s.publicRecord(sig, a, d)

	_, objErr := s.st.GetObject(sig.StorageObjectKey)
	docPath := "/v/" + pid + "/document"

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
		  <h2>Dokumen yang ditandatangani</h2>
		  <p class="muted">Ini berkas asli yang tersimpan di server. Bandingkan dengan dokumen
		  yang Anda terima — jika berbeda, dokumen yang Anda pegang tidak asli.</p>
		  <iframe id="docFrame" title="Dokumen bertanda tangan"></iframe>
		  <div class="docbtns">
		    <a class="btn" id="docLink" target="_blank" rel="noopener">Buka layar penuh / unduh (PDF)</a>
		  </div>
		</div>`
	}

	body := serverBar(reqBase(r)) + `
		<div class="status">` + badge + `<p>` + html.EscapeString(statusNote) + `</p></div>
		<table>` + rows + `</table>
		<p class="muted">` + html.EscapeString(str(rec["note"])) + `</p>` + doc + `
		<p class="muted">Untuk memeriksa keutuhan isi dokumen secara kriptografis, unggah berkas PDF di
		<a id="homeLink" href="/">halaman verifikasi</a>. Halaman ini mencocokkan catatan server
		dan menampilkan berkas asli dari server.</p>
<script>
(function(){
  var p = ` + jsString(docPath) + `;
  var f = document.getElementById("docFrame"), l = document.getElementById("docLink");
  if (f) f.src = window.SRV + p;
  if (l) l.href = window.SRV + p;
  var h = document.getElementById("homeLink"); if (h) h.href = window.SRV + "/";
})();
</script>`
	_, _ = w.Write([]byte(verifyPageShell("Verifikasi Tanda Tangan", body)))
}

// hPublicDocument serves the authoritative signed PDF behind a QR code:
// GET /v/{public_id}/document, no account required.
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
  .wrap { max-width:1040px; margin:0 auto; padding:30px 22px 60px; }
  h1 { font-size:22px; margin:0 0 4px; letter-spacing:-.01em; }
  .sub { opacity:.6; font-size:13px; margin:0 0 22px; }
  .card { background:#fff; border:1px solid #e2e4e8; border-radius:16px; padding:26px 28px;
          box-shadow:0 1px 2px rgba(20,22,25,.04), 0 10px 30px rgba(20,22,25,.05); }
  @media (prefers-color-scheme:dark){ .card{ background:#1c1f25; border-color:#2c2f36;
          box-shadow:0 1px 2px rgba(0,0,0,.3), 0 14px 36px rgba(0,0,0,.35); } }
  @media (max-width:560px){ .wrap{ padding:20px 14px 44px; } .card{ padding:18px; } }
  .srvbar { margin:0 0 16px; padding:12px; border:1px solid #e2e4e8; border-radius:10px; background:#fafbfc; }
  @media (prefers-color-scheme:dark){ .srvbar{ background:#181b20; border-color:#2c2f36; } }
  .srvbar.warn { border-color:#f59e0b; background:#fffbeb; }
  @media (prefers-color-scheme:dark){ .srvbar.warn{ background:#2a2210; } }
  .srvbar label { display:block; font-size:12px; opacity:.7; margin-bottom:6px; }
  .srvrow { display:flex; gap:8px; }
  .srvrow input { flex:1; min-width:0; padding:8px 10px; border:1px solid #cfd3da; border-radius:8px;
                  font:inherit; background:#fff; color:inherit; }
  @media (prefers-color-scheme:dark){ .srvrow input{ background:#0f1114; border-color:#3a3e46; } }
  .srvrow button { padding:8px 14px; border:0; border-radius:8px; background:#4f46e5; color:#fff;
                   font:inherit; font-weight:600; cursor:pointer; }
  .srvhint { margin:8px 0 0; font-size:12px; color:#92400e; }
  @media (prefers-color-scheme:dark){ .srvhint{ color:#fbbf24; } }
  .idbox { margin:14px 0 0; padding:14px; border:1px solid #e2e4e8; border-radius:10px; background:#fafbfc; }
  @media (prefers-color-scheme:dark){ .idbox{ background:#181b20; border-color:#2c2f36; } }
  .idbox label { display:block; font-size:12px; opacity:.7; margin-bottom:6px; }
  .status { text-align:center; margin-bottom:16px; }
  .status p { margin:10px 0 0; font-size:14px; }
  .badge { display:inline-block; padding:6px 16px; border-radius:999px; font-weight:700;
           letter-spacing:.05em; font-size:14px; }
  .badge.ok  { background:#dcfce7; color:#166534; }
  .badge.bad { background:#fee2e2; color:#991b1b; }
  .badge.warn{ background:#fef3c7; color:#92400e; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; margin:6px 0 14px; }
  th,td { text-align:left; padding:10px 8px; border-bottom:1px solid #e8eaee; vertical-align:top; }
  @media (prefers-color-scheme:dark){ th,td{ border-color:#2a2d33; } }
  th { opacity:.55; font-weight:600; white-space:nowrap; width:230px; }
  td { word-break:break-word; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .muted { opacity:.6; font-size:12.5px; }
  .bad { color:#991b1b; font-weight:600; }
  h2 { font-size:16px; margin:24px 0 6px; }
  .doc { margin:18px -28px 4px; padding:18px 28px 0; border-top:1px solid #e8eaee; }
  @media (prefers-color-scheme:dark){ .doc{ border-color:#2a2d33; } }
  @media (max-width:560px){ .doc{ margin-left:-18px; margin-right:-18px; padding-left:18px; padding-right:18px; } }
  .doc iframe { width:100%; height:min(86vh, 1200px); min-height:560px;
                border:1px solid #d7dade; border-radius:10px; background:#fff; margin-top:10px; }
  @media (prefers-color-scheme:dark){ .doc iframe{ border-color:#2c2f36; } }
  .docbtns { display:flex; flex-wrap:wrap; gap:10px; margin-top:12px; }
  .btn { display:inline-flex; align-items:center; gap:7px; padding:11px 20px; border-radius:9px; border:0;
         background:#4f46e5; color:#fff; text-decoration:none; font-weight:600; font-size:13.5px; cursor:pointer; }
  .btn:hover { background:#4338ca; }
  .btn.alt { background:#0e7490; }
  .btn.alt:hover { background:#0c6579; }
  #drop { transition:border-color .15s; }
  #drop:hover { border-color:#4f46e5; }
</style></head><body><div class="wrap">
<h1>Verifikasi Tanda Tangan Digital</h1>
<p class="sub">PQC PDF Sign · ML-DSA-65 (FIPS 204)</p>
<div class="card">` + inner + `</div></div></body></html>`
}
