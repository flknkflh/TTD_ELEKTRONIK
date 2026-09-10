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
    <button id="srvApply" type="button" class="btn btn-primary">Terapkan</button>
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
<p><button class="btn btn-primary" id="go" type="button">Lihat hasil verifikasi →</button></p>
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
	case "not_server_verified":
		badge = `<span class="badge warn">TIDAK DIVERIFIKASI SERVER</span>`
		statusNote = "Berkas terlalu besar untuk diverifikasi otomatis di server — hanya SHA-512 yang dicatat. " +
			"Unggah PDF di halaman verifikasi untuk memeriksa tanda tangannya."
	}

	rows := ""
	add := func(k, v string) {
		if v == "" {
			return
		}
		rows += "<tr><th>" + html.EscapeString(k) + "</th><td>" + html.EscapeString(v) + "</td></tr>"
	}
	add("Penanda tangan", str(rec["signer_name"]))
	add("Jabatan", str(rec["position"]))
	add("NIP", str(rec["nip"]))
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

	// Hash-only check: the browser hashes the chosen file locally and sends
	// only the 64-byte digest. Nothing of the document itself is transmitted,
	// so a confidential file can be checked here.
	hashCheck := `
		<div class="hashcheck" id="hashcheck" hidden>
		  <h2>Verifikasi tanpa mengunggah berkas</h2>
		  <p class="muted">Untuk dokumen rahasia. Berkas tidak dikirim ke mana pun — hanya sidik jari
		  SHA-512 (64 byte) yang dihitung di perangkat Anda lalu dicocokkan dengan catatan server.</p>
		  <label class="hpick" for="hf">
		    <input type="file" id="hf" accept="application/pdf" style="display:none">
		    <b>📄 Pilih berkas PDF</b>
		    <span>Berkas hanya dibaca &amp; di-hash di browser Anda</span>
		  </label>
		  <div id="hres" class="muted"></div>
		</div>
		<div class="hashcheck" id="hashcheck-off" hidden>
		  <h2>Verifikasi tanpa mengunggah berkas</h2>
		  <p class="muted">Pemeriksaan sidik jari di browser memerlukan koneksi aman (HTTPS).
		  Halaman ini dibuka lewat HTTP biasa, sehingga fitur ini dimatikan browser.
		  Gunakan aplikasi desktop atau Android untuk mencocokkan sidik jari tanpa mengunggah berkas.</p>
		</div>`

	body := serverBar(reqBase(r)) + `
		<div class="status">` + badge + `<p>` + html.EscapeString(statusNote) + `</p></div>
		<table>` + rows + `</table>
		<p class="muted">` + html.EscapeString(str(rec["note"])) + `</p>` + doc + hashCheck + `
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

  // crypto.subtle exists only in a secure context (HTTPS, or localhost). On a
  // plain-HTTP LAN/VPS address it is undefined, so offer the block only where
  // it can actually work and point elsewhere when it cannot.
  var PID  = ` + jsString(pid) + `;
  var secure = (window.isSecureContext === true) && window.crypto && window.crypto.subtle;
  var on = document.getElementById("hashcheck"), off = document.getElementById("hashcheck-off");
  if (!secure) { if (off) off.hidden = false; return; }
  if (on) on.hidden = false;

  var hf = document.getElementById("hf"), o = document.getElementById("hres");
  hf.addEventListener("change", function(){
    var file = hf.files && hf.files[0];
    if (!file) return;
    o.className = "muted";
    o.textContent = "Menghitung sidik jari…";
    file.arrayBuffer().then(function(buf){
      return crypto.subtle.digest("SHA-512", buf);
    }).then(function(d){
      var hex = Array.prototype.map.call(new Uint8Array(d), function(b){
        return ("0" + b.toString(16)).slice(-2); }).join("");
      return fetch(window.SRV + "/api/v1/public/verify-hash", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ public_id: PID, sha512: hex })
      }).then(function(r){ return r.json().then(function(j){ return { ok: r.ok, j: j, hex: hex }; }); });
    }).then(function(v){
      if (!v.ok) {
        o.className = "bad";
        o.textContent = "Gagal memeriksa: " + ((v.j && v.j.error) || "server menolak permintaan");
        return;
      }
      o.className = "";
      o.innerHTML = v.j.match
        ? '<span class="badge ok">COCOK</span> <span class="muted">Berkas ini byte-identik dengan yang diterbitkan server untuk ID ini.</span>'
        : '<span class="badge bad">TIDAK COCOK</span> <span class="muted">Berkas ini berbeda dari yang diterbitkan server untuk ID ini.</span>';
      o.innerHTML += '<p class="muted" style="margin:8px 0 0">SHA-512 berkas Anda:<br><code>' + v.hex + '</code></p>';
    }).catch(function(e){
      o.className = "bad";
      o.textContent = "Gagal memeriksa: " + e;
    });
  });
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
` + lgHead + `
<style>
  .v-wrap { max-width:1080px; margin:0 auto; padding:0 20px 90px; position:relative; z-index:1; }
  .v-nav { display:flex; align-items:center; gap:14px; padding:20px 0 8px; }
  .v-nav .spacer { flex:1; }
  .v-nav .navlink { position:relative; color:var(--text-secondary); text-decoration:none; font-weight:600;
                    font-size:13px; padding:7px 12px; border-radius:8px;
                    transition:color .25s var(--ease-glass), background .25s, transform .45s var(--ease-spring); }
  .v-nav .navlink:hover { color:var(--text-primary); background:var(--glass-bg-soft); transform:translateY(-2px); }
  /* underline wipes in from the centre */
  .v-nav .navlink::after { content:""; position:absolute; left:50%; right:50%; bottom:2px; height:2px;
                    border-radius:2px; background:var(--grad-primary);
                    transition:left .35s var(--ease-spring), right .35s var(--ease-spring); }
  .v-nav .navlink:hover::after { left:12px; right:12px; }
  .brand .mark { transition:transform .6s var(--ease-spring), filter .4s; }
  .brand:hover .mark { transform:scale(1.08) rotate(-3deg); filter:drop-shadow(0 10px 28px var(--glow-cyan)); }
  .v-feat .f { transition:transform .45s var(--ease-spring); }
  .v-feat .f:hover { transform:translateY(-4px); }
  .v-feat .f svg { transition:transform .5s var(--ease-spring); }
  .v-feat .f:hover svg { transform:scale(1.2) rotate(-8deg); }
  #drop .dz-ic { transition:transform .55s var(--ease-spring); }
  #drop:hover .dz-ic { transform:translateY(-6px) scale(1.12); }
  @media (max-width:640px){ .v-nav .navlink{ display:none; } }
  .v-hero { text-align:center; padding:22px 0 26px; }
  .v-hero h1 { font-size:clamp(26px,4.4vw,42px); line-height:1.14; margin:0 0 12px; letter-spacing:-.02em; }
  .v-hero .sub { color:var(--text-secondary); font-weight:600; letter-spacing:.03em; font-size:13px; margin:0; }
  .v-card { padding:30px 34px; }
  @media (max-width:620px){ .v-card{ padding:20px; } }

  .srvbar, .idbox { margin:0 0 18px; padding:16px 18px; border-radius:var(--radius-md);
    background:var(--glass-bg-soft); border:1px solid var(--glass-border);
    -webkit-backdrop-filter:blur(10px); backdrop-filter:blur(10px); }
  .srvbar.warn { border-color:var(--warning); background:var(--warning-soft); }
  .srvbar label, .idbox label { margin-top:0; }
  .srvrow { display:flex; gap:10px; }
  .srvrow input { flex:1; min-width:0; }
  .srvhint { margin:8px 0 0; font-size:12px; color:var(--warning); }

  .status { text-align:center; margin:4px 0 18px; }
  .status p { margin:12px 0 0; font-size:14px; color:var(--text-secondary); }

  #drop { display:block; border:1.6px dashed var(--border-active); border-radius:var(--radius-md);
    padding:34px 18px; text-align:center; cursor:pointer; font-size:14px; color:var(--text-secondary);
    background:var(--glass-bg-soft); transition:border-color .25s var(--ease-glass), background .25s, transform .25s, box-shadow .25s; }
  #drop:hover { border-color:var(--cyan-400); background:var(--glass-bg); transform:translateY(-2px); }
  #drop.drag { border-color:var(--cyan-400); background:var(--glass-bg-strong); box-shadow:0 0 34px var(--glow-cyan); }
  #drop .dz-ic { display:block; width:40px; height:40px; margin:0 auto 10px; color:var(--blue-500); }

  h2 { font-size:16px; margin:22px 0 6px; }
  .v-card table { margin:8px 0 14px; }
  .v-card th { text-transform:none; letter-spacing:0; font-size:12px; color:var(--text-muted);
               font-weight:600; white-space:nowrap; width:228px; }
  .v-card td { word-break:break-word; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }

  .doc { margin:20px 0 4px; padding:20px 0 0; border-top:1px solid var(--glass-border); }
  .doc iframe { width:100%; height:min(84vh,1100px); min-height:520px; border:1px solid var(--glass-border);
    border-radius:var(--radius-md); background:#fff; margin-top:12px; }
  .docbtns { display:flex; flex-wrap:wrap; gap:10px; margin-top:12px; }
  .btn.alt { background:linear-gradient(135deg,var(--cyan-500),var(--blue-600)); color:#fff; border-color:transparent; }

  /* ---- hash-only checker: verify a confidential file without uploading it ---- */
  .hashcheck { margin:20px 0 4px; padding:20px 0 0; border-top:1px solid var(--glass-border); }
  .hashcheck h2 { margin:0 0 6px; }
  .hashcheck .hpick { display:block; border:1.5px dashed var(--border-active); border-radius:var(--radius-md);
           padding:18px; text-align:center; cursor:pointer; margin-top:12px;
           transition:border-color .3s, background .3s, transform .3s var(--ease-spring); }
  .hashcheck .hpick:hover { border-color:var(--cyan-400); background:var(--glass-bg); transform:translateY(-2px); }
  .hashcheck .hpick b { display:block; font-size:13px; }
  .hashcheck .hpick span { font-size:12px; color:var(--text-muted); }
  #hres { margin-top:12px; font-size:13px; }
  #hres code { word-break:break-all; font-size:11.5px; }

  .v-feat { display:flex; flex-wrap:wrap; gap:16px; margin-top:24px; padding-top:20px; border-top:1px solid var(--glass-border); }
  .v-feat .f { flex:1 1 170px; display:flex; gap:11px; align-items:flex-start; }
  .v-feat .f svg { width:22px; height:22px; color:var(--blue-500); flex:0 0 22px; margin-top:1px; }
  .v-feat .f b { display:block; font-size:13px; }
  .v-feat .f span { font-size:11.5px; color:var(--text-muted); }

  .v-foot { text-align:center; color:var(--text-muted); font-size:12px; padding:34px 0 0; }

  /* ---- progress panel while a document is being checked ---- */
  .vprog { display:flex; gap:24px; align-items:center; padding:22px 24px; margin-top:4px;
           border-radius:var(--radius-md); border:1px solid var(--glass-border);
           background:var(--glass-bg-soft); position:relative; overflow:hidden;
           animation:popIn .5s var(--ease-spring) both; }
  /* a light sweeps across the panel while work is in flight */
  .vprog::after { content:""; position:absolute; inset:0; pointer-events:none;
           background:linear-gradient(100deg,transparent 20%,var(--glass-highlight) 50%,transparent 80%);
           opacity:.5; transform:translateX(-100%); animation:vsweep 2.1s ease-in-out infinite; }
  .vprog.done::after { animation:none; opacity:0; }
  @keyframes vsweep { to { transform:translateX(100%); } }

  .vprog .ringwrap { position:relative; width:104px; height:104px; flex:0 0 104px; }
  .vprog svg.ring { width:100%; height:100%; transform:rotate(-90deg); display:block; }
  .vprog .track { fill:none; stroke:var(--glass-border); stroke-width:9; }
  .vprog .bar { fill:none; stroke:url(#vgrad); stroke-width:9; stroke-linecap:round;
           stroke-dasharray:314; stroke-dashoffset:314;
           transition:stroke-dashoffset .45s var(--ease-glass);
           filter:drop-shadow(0 0 7px var(--glow-cyan)); }
  .vprog .pct { position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
           line-height:1; font-size:23px; font-weight:800; font-variant-numeric:tabular-nums;
           letter-spacing:-.02em; }
  .vprog .pct span { font-size:12px; opacity:.55; margin-left:2px; font-weight:700;
           position:relative; top:-5px; }
  .vprog .steps { flex:1; min-width:0; }
  .vprog .fname { font-size:13px; font-weight:700; margin:0 0 10px;
           overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .vprog .fname em { font-style:normal; font-weight:500; color:var(--text-muted); }
  @media (max-width:560px){ .vprog{ flex-direction:column; text-align:center; } }

  .vstep { display:flex; align-items:center; gap:10px; padding:4px 0; font-size:13px;
           color:var(--text-muted); transition:color .35s var(--ease-glass), transform .5s var(--ease-spring); }
  .vstep .dot { width:19px; height:19px; border-radius:50%; flex:0 0 19px;
           border:2px solid var(--glass-border); display:grid; place-items:center;
           font-size:11px; font-weight:900; color:transparent;
           transition:border-color .4s, background .4s, box-shadow .4s, color .3s, transform .5s var(--ease-spring); }
  .vstep.doing { color:var(--text-primary); transform:translateX(4px); }
  .vstep.doing .dot { border-color:var(--blue-500); box-shadow:0 0 0 4px var(--glow-blue);
           animation:vpulse 1.3s ease-in-out infinite; }
  .vstep.done { color:var(--text-secondary); }
  .vstep.done .dot { border-color:var(--success); background:var(--success); color:#fff; transform:scale(1.06); }
  @keyframes vpulse { 0%,100%{transform:scale(1)} 50%{transform:scale(1.18)} }

  /* ---- inline warning (file too big / wrong type / server error) ---- */
  .vwarn { display:flex; gap:13px; align-items:flex-start; padding:16px 18px; margin-top:4px;
           border-radius:var(--radius-md); border:1px solid var(--danger);
           background:var(--danger-soft); animation:popIn .45s var(--ease-spring) both; }
  .vwarn svg { width:22px; height:22px; flex:0 0 22px; color:var(--danger); margin-top:1px;
           animation:vshake .5s var(--ease-glass) both; }
  /* only the heading is a block; <b> used for emphasis inside the text stays inline */
  .vwarn > div > b { display:block; font-size:14px; margin-bottom:3px; color:var(--danger); }
  .vwarn p { margin:0; font-size:12.5px; color:var(--text-secondary); }
  .vwarn p b { color:var(--text-primary); font-weight:700; }
  .vwarn .meter { margin-top:9px; height:6px; border-radius:6px; background:var(--glass-border); overflow:hidden; }
  .vwarn .meter i { display:block; height:100%; border-radius:6px; width:0;
           background:linear-gradient(90deg,var(--warning),var(--danger));
           animation:vfill .8s var(--ease-glass) forwards; }
  @keyframes vfill  { to { width:100%; } }
  @keyframes vshake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-4px)} 75%{transform:translateX(4px)} }
  #drop.too-big { border-color:var(--danger); background:var(--danger-soft); }
  .v-hero { position:relative; }
  .v-qr { position:absolute; right:-1vw; top:-6px; width:min(12vw,120px); opacity:.72;
          filter:drop-shadow(0 14px 40px var(--glow-cyan)); pointer-events:none; }
  @media (max-width:1000px){ .v-qr{ display:none; } }
</style></head><body>
` + lgBackground + `
<div class="v-wrap">
  <nav class="v-nav anim-fade-down">
    <a class="brand" href="/">` + lgMark + `</a>
    <span class="spacer"></span>
    <a class="navlink" href="/">Beranda</a>
    <a class="navlink" href="/">Verifikasi</a>
    <a class="navlink" href="/api/v1/public/ca/chain.pem">Sertifikat CA</a>
    ` + lgThemeToggle + `
  </nav>
  <header class="v-hero">
    <img class="v-qr float lt" src="/assets/img/qr-light.png" alt="" aria-hidden="true">
    <img class="v-qr float dk" src="/assets/img/qr-dark.png" alt="" aria-hidden="true">
    <h1 class="anim-fade-up">Verifikasi <span class="grad-text">Tanda Tangan Digital</span></h1>
    <p class="sub anim-fade-up stg-1">PQC PDF Sign · ML-DSA-65 (FIPS 204)</p>
  </header>
  <div class="glass glow-border spotlight v-card anim-fade-up stg-2">
` + inner + `
  </div>
  <p class="v-foot">PQC PDF Sign · Keamanan Post-Quantum untuk Dokumen Tepercaya</p>
</div>
` + lgScripts + `
</body></html>`
}
