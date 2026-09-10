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

	// Hash-only check. This is now the page's only interactive step: the
	// browser reads the chosen file, digests it locally and sends just the
	// 64-byte hash. The document itself is never transmitted, and the server's
	// copy is never shown or offered for download.
	hashCheck := `
		<div class="hashcheck">
		  <h2>Cocokkan berkas Anda</h2>
		  <p class="muted">Pilih berkas PDF yang Anda terima. Sidik jari SHA-512-nya dihitung
		  di perangkat Anda lalu dibandingkan dengan yang tercatat di server. Berkas tidak
		  diunggah ke mana pun, jadi aman untuk dokumen rahasia.</p>
		  <label class="hpick" for="hf">
		    <input type="file" id="hf" accept="application/pdf" style="display:none">
		    <b>📄 Pilih berkas PDF</b>
		    <span>Berkas hanya dibaca &amp; di-hash di browser Anda</span>
		  </label>
		  <div id="hres" class="muted"></div>
		</div>`

	body := serverBar(reqBase(r)) + `
		<div class="status">` + badge + `<p>` + html.EscapeString(statusNote) + `</p></div>
		<table>` + rows + `</table>
		<p class="muted">` + html.EscapeString(str(rec["note"])) + `</p>` + hashCheck + `
		<p class="muted">Halaman ini mencocokkan catatan server dengan berkas yang Anda pegang.
		Untuk pemeriksaan tanda tangan kriptografis yang lengkap, unggah berkas PDF di
		<a id="homeLink" href="/">halaman verifikasi</a>.</p>
<script>
(function(){
  var h = document.getElementById("homeLink"); if (h) h.href = window.SRV + "/";

  var PID = ` + jsString(pid) + `;
  var hf = document.getElementById("hf"), o = document.getElementById("hres");

  function say(cls, html){ o.className = cls; o.innerHTML = html; }

  hf.addEventListener("change", function(){
    var file = hf.files && hf.files[0];
    if (!file) return;
    say("muted", "Membaca berkas…");
    var reader = new FileReader();
    reader.onerror = function(){ say("bad", "Gagal membaca berkas."); };
    reader.onload = function(){
      var bytes = new Uint8Array(reader.result);
      say("muted", "Menghitung sidik jari…");
      digest(bytes, function(hex){ send(hex); }, function(pct){
        say("muted", "Menghitung sidik jari… " + pct + "%");
      });
    };
    reader.readAsArrayBuffer(file);
  });

  // crypto.subtle is only defined in a secure context (HTTPS or localhost).
  // This site is commonly served over plain HTTP on a LAN or VPS address, so
  // fall back to the bundled SHA-512 rather than disabling the feature.
  function digest(bytes, done, progress){
    if (window.crypto && window.crypto.subtle && window.isSecureContext) {
      crypto.subtle.digest("SHA-512", bytes).then(function(d){
        done(Array.prototype.map.call(new Uint8Array(d), function(b){
          return ("0" + b.toString(16)).slice(-2); }).join(""));
      }).catch(function(){ jsDigest(bytes, done, progress); });
      return;
    }
    jsDigest(bytes, done, progress);
  }

  // Chunked so a large file does not freeze the tab: hash ~4 MB per tick and
  // yield to the event loop in between.
  function jsDigest(bytes, done, progress){
    var H = sha512New(), fullEnd = bytes.length - (bytes.length % 128), off = 0, CH = 4 << 20;
    (function step(){
      var to = Math.min(off + CH, fullEnd);
      sha512Blocks(H, bytes, off, to);
      off = to;
      if (off < fullEnd) {
        progress(Math.floor((off / bytes.length) * 100));
        setTimeout(step, 0);
      } else {
        done(sha512Final(H, bytes, fullEnd));
      }
    })();
  }

  function send(hex){
    fetch(window.SRV + "/api/v1/public/verify-hash", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ public_id: PID, sha512: hex })
    }).then(function(r){
      return r.json().then(function(j){ return { ok: r.ok, j: j }; });
    }).then(function(v){
      if (!v.ok) {
        say("bad", "Gagal memeriksa: " + ((v.j && v.j.error) || "server menolak permintaan"));
        return;
      }
      say("", (v.j.match
        ? '<span class="badge ok">COCOK</span> <span class="muted">Berkas ini byte-identik dengan yang diterbitkan server untuk ID ini.</span>'
        : '<span class="badge bad">TIDAK COCOK</span> <span class="muted">Berkas ini berbeda dari yang diterbitkan server untuk ID ini.</span>')
        + '<p class="muted" style="margin:8px 0 0">SHA-512 berkas Anda:<br><code>' + hex + '</code></p>');
    }).catch(function(e){
      say("bad", "Gagal menghubungi server: " + e);
    });
  }
})();
</script>` + sha512JS
	_, _ = w.Write([]byte(verifyPageShell("Verifikasi Tanda Tangan", body)))
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

// sha512JS is a self-contained SHA-512 for the QR landing page. The page
// prefers crypto.subtle, but that is defined only in a secure context and this
// site is routinely served over plain HTTP on a LAN or VPS address -- without
// this fallback the "cocokkan berkas" step would silently not exist for most
// visitors. Implemented over 32-bit hi/lo pairs (not BigInt) for speed, and
// exposed as an incremental API so the page can hash in chunks and keep the
// tab responsive. Verified against the NIST vectors and Node's crypto.
const sha512JS = `
<script>
// SHA-512 over 32-bit hi/lo pairs. Needed because crypto.subtle exists only in
// a secure context (HTTPS/localhost) and this site is often served over plain
// HTTP on a LAN or VPS address.
var K512 = [
  0x428a2f98,0xd728ae22,0x71374491,0x23ef65cd,0xb5c0fbcf,0xec4d3b2f,0xe9b5dba5,0x8189dbbc,
  0x3956c25b,0xf348b538,0x59f111f1,0xb605d019,0x923f82a4,0xaf194f9b,0xab1c5ed5,0xda6d8118,
  0xd807aa98,0xa3030242,0x12835b01,0x45706fbe,0x243185be,0x4ee4b28c,0x550c7dc3,0xd5ffb4e2,
  0x72be5d74,0xf27b896f,0x80deb1fe,0x3b1696b1,0x9bdc06a7,0x25c71235,0xc19bf174,0xcf692694,
  0xe49b69c1,0x9ef14ad2,0xefbe4786,0x384f25e3,0x0fc19dc6,0x8b8cd5b5,0x240ca1cc,0x77ac9c65,
  0x2de92c6f,0x592b0275,0x4a7484aa,0x6ea6e483,0x5cb0a9dc,0xbd41fbd4,0x76f988da,0x831153b5,
  0x983e5152,0xee66dfab,0xa831c66d,0x2db43210,0xb00327c8,0x98fb213f,0xbf597fc7,0xbeef0ee4,
  0xc6e00bf3,0x3da88fc2,0xd5a79147,0x930aa725,0x06ca6351,0xe003826f,0x14292967,0x0a0e6e70,
  0x27b70a85,0x46d22ffc,0x2e1b2138,0x5c26c926,0x4d2c6dfc,0x5ac42aed,0x53380d13,0x9d95b3df,
  0x650a7354,0x8baf63de,0x766a0abb,0x3c77b2a8,0x81c2c92e,0x47edaee6,0x92722c85,0x1482353b,
  0xa2bfe8a1,0x4cf10364,0xa81a664b,0xbc423001,0xc24b8b70,0xd0f89791,0xc76c51a3,0x0654be30,
  0xd192e819,0xd6ef5218,0xd6990624,0x5565a910,0xf40e3585,0x5771202a,0x106aa070,0x32bbd1b8,
  0x19a4c116,0xb8d2d0c8,0x1e376c08,0x5141ab53,0x2748774c,0xdf8eeb99,0x34b0bcb5,0xe19b48a8,
  0x391c0cb3,0xc5c95a63,0x4ed8aa4a,0xe3418acb,0x5b9cca4f,0x7763e373,0x682e6ff3,0xd6b2b8a3,
  0x748f82ee,0x5defb2fc,0x78a5636f,0x43172f60,0x84c87814,0xa1f0ab72,0x8cc70208,0x1a6439ec,
  0x90befffa,0x23631e28,0xa4506ceb,0xde82bde9,0xbef9a3f7,0xb2c67915,0xc67178f2,0xe372532b,
  0xca273ece,0xea26619c,0xd186b8c7,0x21c0c207,0xeada7dd6,0xcde0eb1e,0xf57d4f7f,0xee6ed178,
  0x06f067aa,0x72176fba,0x0a637dc5,0xa2c898a6,0x113f9804,0xbef90dae,0x1b710b35,0x131c471b,
  0x28db77f5,0x23047d84,0x32caab7b,0x40c72493,0x3c9ebe0a,0x15c9bebc,0x431d67c4,0x9c100d4c,
  0x4cc5d4be,0xcb3e42b6,0x597f299c,0xfc657e2a,0x5fcb6fab,0x3ad6faec,0x6c44198c,0x4a475817
];

// --- incremental core -------------------------------------------------
// blockRange compresses bytes[from..to) (a whole number of 128-byte blocks)
// into H. Hashing the caller's buffer directly avoids copying the whole file
// just to append padding, which matters for a 100 MB+ document.
function sha512New() {
  return [
    0x6a09e667,0xf3bcc908, 0xbb67ae85,0x84caa73b, 0x3c6ef372,0xfe94f82b, 0xa54ff53a,0x5f1d36f1,
    0x510e527f,0xade682d1, 0x9b05688c,0x2b3e6c1f, 0x1f83d9ab,0xfb41bd6b, 0x5be0cd19,0x137e2179
  ];
}

var _W = new Array(160);

function sha512Blocks(H, p, from, to) {
  var W = _W;
  for (var off = from; off < to; off += 128) {
    for (var i = 0; i < 32; i++) {
      var j = off + i * 4;
      W[i] = ((p[j] << 24) | (p[j+1] << 16) | (p[j+2] << 8) | p[j+3]) >>> 0;
    }
    for (var t = 16; t < 80; t++) {
      var i2 = t * 2;
      var xh = W[i2-30], xl = W[i2-29];
      var s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
      var s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
      var yh = W[i2-4], yl = W[i2-3];
      var s1h = ((yh >>> 19) | (yl << 13)) ^ ((yl >>> 29) | (yh << 3)) ^ (yh >>> 6);
      var s1l = ((yl >>> 19) | (yh << 13)) ^ ((yh >>> 29) | (yl << 3)) ^ ((yl >>> 6) | (yh << 26));
      var ah = W[i2-32], al = W[i2-31], bh = W[i2-14], bl = W[i2-13];
      var lo = (s0l + al) | 0; var hi = (s0h + ah + (((lo >>> 0) < (s0l >>> 0)) ? 1 : 0)) | 0;
      var lo2 = (lo + s1l) | 0; hi = (hi + s1h + (((lo2 >>> 0) < (lo >>> 0)) ? 1 : 0)) | 0;
      var lo3 = (lo2 + bl) | 0; hi = (hi + bh + (((lo3 >>> 0) < (lo2 >>> 0)) ? 1 : 0)) | 0;
      W[i2] = hi >>> 0; W[i2+1] = lo3 >>> 0;
    }
    var ah0=H[0],al0=H[1],bh0=H[2],bl0=H[3],ch0=H[4],cl0=H[5],dh0=H[6],dl0=H[7],
        eh0=H[8],el0=H[9],fh0=H[10],fl0=H[11],gh0=H[12],gl0=H[13],hh0=H[14],hl0=H[15];
    for (var t2 = 0; t2 < 80; t2++) {
      var k2 = t2 * 2;
      var S1h = ((eh0 >>> 14) | (el0 << 18)) ^ ((eh0 >>> 18) | (el0 << 14)) ^ ((el0 >>> 9) | (eh0 << 23));
      var S1l = ((el0 >>> 14) | (eh0 << 18)) ^ ((el0 >>> 18) | (eh0 << 14)) ^ ((eh0 >>> 9) | (el0 << 23));
      var chh = (eh0 & fh0) ^ (~eh0 & gh0);
      var chl = (el0 & fl0) ^ (~el0 & gl0);
      var S0h = ((ah0 >>> 28) | (al0 << 4)) ^ ((al0 >>> 2) | (ah0 << 30)) ^ ((al0 >>> 7) | (ah0 << 25));
      var S0l = ((al0 >>> 28) | (ah0 << 4)) ^ ((ah0 >>> 2) | (al0 << 30)) ^ ((ah0 >>> 7) | (al0 << 25));
      var majh = (ah0 & bh0) ^ (ah0 & ch0) ^ (bh0 & ch0);
      var majl = (al0 & bl0) ^ (al0 & cl0) ^ (bl0 & cl0);
      var t1l = (hl0 + S1l) | 0; var t1h = (hh0 + S1h + (((t1l >>> 0) < (hl0 >>> 0)) ? 1 : 0)) | 0;
      var pl = t1l; t1l = (t1l + chl) | 0; t1h = (t1h + chh + (((t1l >>> 0) < (pl >>> 0)) ? 1 : 0)) | 0;
      pl = t1l; t1l = (t1l + K512[k2+1]) | 0; t1h = (t1h + K512[k2] + (((t1l >>> 0) < (pl >>> 0)) ? 1 : 0)) | 0;
      pl = t1l; t1l = (t1l + W[k2+1]) | 0; t1h = (t1h + W[k2] + (((t1l >>> 0) < (pl >>> 0)) ? 1 : 0)) | 0;
      var t2l = (S0l + majl) | 0; var t2h = (S0h + majh + (((t2l >>> 0) < (S0l >>> 0)) ? 1 : 0)) | 0;
      hh0=gh0; hl0=gl0; gh0=fh0; gl0=fl0; fh0=eh0; fl0=el0;
      var el1 = (dl0 + t1l) | 0; var eh1 = (dh0 + t1h + (((el1 >>> 0) < (dl0 >>> 0)) ? 1 : 0)) | 0;
      eh0 = eh1 >>> 0; el0 = el1 >>> 0;
      dh0=ch0; dl0=cl0; ch0=bh0; cl0=bl0; bh0=ah0; bl0=al0;
      var al1 = (t1l + t2l) | 0; var ah1 = (t1h + t2h + (((al1 >>> 0) < (t1l >>> 0)) ? 1 : 0)) | 0;
      ah0 = ah1 >>> 0; al0 = al1 >>> 0;
    }
    var st = [ah0,al0,bh0,bl0,ch0,cl0,dh0,dl0,eh0,el0,fh0,fl0,gh0,gl0,hh0,hl0];
    for (var q = 0; q < 16; q += 2) {
      var nl = (H[q+1] + st[q+1]) | 0;
      var nh = (H[q] + st[q] + (((nl >>> 0) < (H[q+1] >>> 0)) ? 1 : 0)) | 0;
      H[q] = nh >>> 0; H[q+1] = nl >>> 0;
    }
  }
}

// sha512Final compresses the trailing partial block plus the padding.
function sha512Final(H, bytes, fullEnd) {
  var ml = bytes.length, rem = ml - fullEnd;
  var tail = new Uint8Array(rem + 17 > 128 ? 256 : 128);
  tail.set(bytes.subarray(fullEnd));
  tail[rem] = 0x80;
  var bitsHi = Math.floor(ml / 536870912), bitsLo = (ml * 8) >>> 0, n = tail.length;
  tail[n-8] = (bitsHi >>> 24) & 0xff; tail[n-7] = (bitsHi >>> 16) & 0xff;
  tail[n-6] = (bitsHi >>> 8) & 0xff;  tail[n-5] = bitsHi & 0xff;
  tail[n-4] = (bitsLo >>> 24) & 0xff; tail[n-3] = (bitsLo >>> 16) & 0xff;
  tail[n-2] = (bitsLo >>> 8) & 0xff;  tail[n-1] = bitsLo & 0xff;
  sha512Blocks(H, tail, 0, n);
  var out = "";
  for (var z = 0; z < 16; z++) out += ("00000000" + H[z].toString(16)).slice(-8);
  return out;
}
</script>`
