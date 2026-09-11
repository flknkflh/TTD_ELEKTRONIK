package api

import (
	"net/http"
	"strconv"
)

// verifyLimitBytes is the byte ceiling POST /api/v1/verify enforces on an
// uploaded PDF. It mirrors hPublicVerify so the browser-side warning and the
// server-side rejection can never disagree.
func (s *Server) verifyLimitBytes() int64 { return s.cfg.MaxUploadBytes }

// VerifyRoutes is a stripped-down handler that exposes ONLY public
// verification: a browser upload page, the verify API, the QR landing page,
// and the public CA material. No auth, no registration, no signing, no admin.
// Run it on its own port (PQC_VERIFY_ADDR) so a verification-only service can
// be published separately from the signing API.
func (s *Server) VerifyRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.hVerifyHome)
	mux.HandleFunc("POST /api/v1/verify", s.limit(s.rlVerify, s.byIP, s.hPublicVerify))
	mux.HandleFunc("POST /api/v1/public/verify-hash", s.limit(s.rlVerify, s.byIP, s.hVerifyHash))
	mux.HandleFunc("GET /s/{public_id}", s.hScanResolver)
	mux.HandleFunc("GET /v/{public_id}", s.hVerifyPage)
	mux.HandleFunc("GET /api/v1/public/signatures/{public_id}", s.hPublicRecord)
	mux.HandleFunc("GET /api/v1/public/ca/root.crt", s.pem(func() []byte { return s.cfg.RootCAPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/chain.pem", s.pem(func() []byte { return s.cfg.CAChainPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/crl.pem", s.pem(func() []byte { return s.crl }))

	s.mountUIKit(mux)

	// The verify page may be opened at one address (localhost) while pointed
	// at the server on another (the LAN IP typed into the "Alamat server"
	// box). This service is public and read-only, so allow any origin.
	return securityHeaders(corsAny(mux))
}

func corsAny(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hVerifyHome serves the upload page for the standalone verification service.
// After a successful check it also shows the "scan" view: the server record
// and the authoritative signed PDF, exactly like opening the QR link.
func (s *Server) hVerifyHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Hand the page the ceiling this endpoint actually enforces, so the
	// "file too large" warning can be raised before anything is uploaded.
	limit := `<script>window.PQC_VERIFY_MAX_BYTES=` +
		strconv.FormatInt(s.verifyLimitBytes(), 10) + `;</script>`
	body := serverBar(reqBase(r)) + limit + verifyHomeBody
	_, _ = w.Write([]byte(verifyPageShell("Verifikasi Dokumen", body)))
}

const verifyHomeBody = `
<p class="muted" style="margin-top:0">Unggah berkas PDF bertanda tangan untuk memeriksa keaslian &amp;
keutuhannya. Tidak perlu akun. Berkas Anda diperiksa di server lalu dibuang — tidak disimpan.</p>

<h2>Unggah berkas PDF</h2>
<label id="drop" for="file">
  <input id="file" type="file" accept="application/pdf" style="display:none">
  <svg class="dz-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4m0 0 4 4m-4-4-4 4"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/></svg>
  <span id="dz">Seret &amp; lepas berkas PDF di sini</span>
  <span class="muted" style="display:block;margin-top:8px">atau</span>
  <span class="btn btn-primary" style="margin-top:10px" data-no-ripple>Pilih Berkas PDF</span>
  <span class="muted" style="display:block;margin-top:10px" id="dzLimit">Hanya berkas PDF</span>
</label>

<div id="out" style="margin-top:16px"></div>

<div class="v-feat">
  <div class="f"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg><div><b>Aman &amp; Privat</b><span>Berkas tidak disimpan di server</span></div></div>
  <div class="f"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/></svg><div><b>Standar Post-Quantum</b><span>ML-DSA-65 (FIPS 204)</span></div></div>
  <div class="f"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m9 11 3 3 8-8"/><path d="M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h11"/></svg><div><b>Mudah Digunakan</b><span>Tanpa akun, langsung verifikasi</span></div></div>
</div>

<script>
(function(){
  var file = document.getElementById('file'),
      drop = document.getElementById('drop'),
      dz   = document.getElementById('dz'),
      out  = document.getElementById('out');

  ['dragenter','dragover'].forEach(function(ev){
    drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.add('drag'); });
  });
  ['dragleave','drop'].forEach(function(ev){
    drop.addEventListener(ev, function(e){ e.preventDefault(); drop.classList.remove('drag'); });
  });
  drop.addEventListener('drop', function(e){
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) run(e.dataTransfer.files[0]);
  });
  file.addEventListener('change', function(){ if (file.files[0]) run(file.files[0]); });

  function esc(s){ return String(s == null ? '' : s).replace(/[&<>]/g, function(c){
    return ({'&':'&amp;','<':'&lt;','>':'&gt;'})[c]; }); }
  function row(k,v){ return v ? '<tr><th>'+esc(k)+'</th><td>'+esc(v)+'</td></tr>' : ''; }

  // ---- size limit -------------------------------------------------
  // The server tells the page its own ceiling, so the warning can never
  // drift away from what the API actually accepts.
  var MAX = Number(window.PQC_VERIFY_MAX_BYTES) || 0;
  function human(b){
    if (!(b > 0)) return '-';
    var u = ['B','KB','MB','GB'], i = 0, n = b;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (n >= 10 || i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i];
  }
  var limitEl = document.getElementById('dzLimit');
  if (limitEl && MAX) limitEl.textContent = 'Hanya berkas PDF · ukuran maksimal ' + human(MAX);

  function warn(title, msg, meter){
    drop.classList.add('too-big');
    setTimeout(function(){ drop.classList.remove('too-big'); }, 2500);
    out.innerHTML =
      '<div class="vwarn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/>' +
      '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>' +
      '<div style="flex:1"><b>' + esc(title) + '</b><p>' + msg + '</p>' +
      (meter ? '<div class="meter"><i></i></div>' : '') + '</div></div>';
  }

  // accept() runs before a single byte leaves the browser
  function accept(f){
    var isPdf = f.type === 'application/pdf' || /\.pdf$/i.test(f.name);
    if (!isPdf) {
      warn('Bukan berkas PDF',
        'Berkas <b>' + esc(f.name) + '</b> bukan PDF. Verifikasi tanda tangan hanya bisa dilakukan pada berkas PDF.');
      return false;
    }
    if (f.size === 0) {
      warn('Berkas kosong', 'Berkas <b>' + esc(f.name) + '</b> berukuran 0 byte, tidak ada yang bisa diperiksa.');
      return false;
    }
    if (MAX && f.size > MAX) {
      warn('Ukuran berkas terlalu besar',
        'Berkas <b>' + esc(f.name) + '</b> berukuran <b>' + human(f.size) + '</b>, melebihi batas ' +
        '<b>' + human(MAX) + '</b> yang diterima server verifikasi. Kecilkan berkasnya (mis. kompres PDF) lalu coba lagi.',
        true);
      return false;
    }
    return true;
  }

  // ---- progress panel --------------------------------------------
  var STEPS = ['Mengunggah berkas', 'Memeriksa tanda tangan', 'Menyusun hasil'];
  var CIRC = 314, pct = 0, creep = null;

  function progressUI(f){
    out.innerHTML =
      '<div class="vprog" id="vprog">' +
        '<div class="ringwrap">' +
          '<svg class="ring" viewBox="0 0 120 120" aria-hidden="true"><defs>' +
            '<linearGradient id="vgrad" x1="0" y1="0" x2="1" y2="1">' +
              '<stop offset="0%" stop-color="var(--cyan-400)"/>' +
              '<stop offset="55%" stop-color="var(--blue-500)"/>' +
              '<stop offset="100%" stop-color="var(--violet-400)"/>' +
            '</linearGradient></defs>' +
            '<circle class="track" cx="60" cy="60" r="50"/>' +
            '<circle class="bar" id="vbar" cx="60" cy="60" r="50"/>' +
          '</svg>' +
          '<div class="pct" id="vpct" role="status" aria-live="polite">0<span>%</span></div>' +
        '</div>' +
        '<div class="steps">' +
          '<p class="fname">' + esc(f.name) + ' <em>· ' + human(f.size) + '</em></p>' +
          STEPS.map(function(s, i){
            return '<div class="vstep" id="vstep' + i + '"><span class="dot">&#10003;</span>' + esc(s) + '</div>';
          }).join('') +
        '</div>' +
      '</div>';
    step(0);
    setPct(0, true);
  }
  function setPct(p, immediate){
    pct = Math.max(pct, Math.min(100, p));
    var bar = document.getElementById('vbar'), lbl = document.getElementById('vpct');
    if (!bar) return;
    if (immediate) { pct = p; }
    bar.style.strokeDashoffset = String(CIRC - (CIRC * pct) / 100);
    lbl.innerHTML = Math.round(pct) + '<span>%</span>';
  }
  function step(i){
    for (var n = 0; n < STEPS.length; n++) {
      var el = document.getElementById('vstep' + n);
      if (!el) continue;
      el.className = 'vstep' + (n < i ? ' done' : n === i ? ' doing' : '');
    }
  }
  // while the server is verifying there is nothing to measure, so ease
  // asymptotically toward 99% instead of freezing the ring
  function startCreep(){
    stopCreep();
    creep = setInterval(function(){ setPct(pct + (99 - pct) * 0.06); }, 180);
  }
  function stopCreep(){ if (creep) { clearInterval(creep); creep = null; } }
  function finish(){
    stopCreep(); step(STEPS.length); setPct(100);
    var p = document.getElementById('vprog'); if (p) p.classList.add('done');
  }

  function run(f){
    if (!accept(f)) return;
    dz.textContent = f.name;
    pct = 0;
    progressUI(f);

    var fd = new FormData(); fd.append('file', f);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', window.SRV + '/api/v1/verify');
    xhr.responseType = 'text';

    // real upload percentage, mapped onto the first 85% of the ring
    xhr.upload.onprogress = function(e){
      if (e.lengthComputable) setPct((e.loaded / e.total) * 85);
    };
    xhr.upload.onload = function(){ setPct(86); step(1); startCreep(); };

    xhr.onload = function(){
      stopCreep();
      var j = null;
      try { j = JSON.parse(xhr.responseText); } catch (_) {}
      if (xhr.status === 413) {
        warn('Ukuran berkas terlalu besar',
          'Server verifikasi menolak berkas ini karena melebihi batas' + (MAX ? ' ' + human(MAX) : '') +
          '. Kecilkan berkasnya lalu coba lagi.', true);
        return;
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        warn('Gagal memeriksa berkas', esc((j && j.error) || ('Server menjawab HTTP ' + xhr.status)) + '.');
        return;
      }
      step(2); setPct(96);
      // let the last step be visible for a beat before swapping in the verdict
      setTimeout(function(){ finish(); setTimeout(function(){ render(j); }, 320); }, 220);
    };
    xhr.onerror = function(){
      stopCreep();
      warn('Tidak bisa menghubungi server',
        'Gagal menghubungi server verifikasi di <b>' + esc(window.SRV) + '</b>. Periksa "Alamat server" di atas.');
    };
    xhr.onabort = function(){ stopCreep(); };
    xhr.send(fd);
  }

  // The underlying libraries report failures in English, and the CMS digest
  // mismatch arrives as a two-line hex dump. Neither belongs in front of a
  // member of the public, so translate the ones we recognise and drop the
  // lines that merely restate a consequence.
  function humanErrs(errs){
    var out = [], seen = {};
    (errs || []).forEach(function(raw){
      var e = String(raw), low = e.toLowerCase(), msg;
      if (low.indexOf('message digest mismatch') >= 0 || low.indexOf('signature verification failed') >= 0) {
        msg = 'Isi dokumen tidak cocok dengan tanda tangannya — berkas sudah diubah setelah ditandatangani.';
      } else if (low.indexOf('byterange') >= 0 || low.indexOf('unexpected eof') >= 0) {
        msg = 'Struktur tanda tangan tidak utuh — berkas kemungkinan disimpan ulang atau dipotong oleh aplikasi lain.';
      } else if (low.indexOf('no signer certificate') >= 0) {
        return; // a consequence of the failure above, not a separate cause
      } else if (low.indexOf('x509') >= 0 || low.indexOf('certificate signed by unknown authority') >= 0) {
        msg = 'Sertifikat penanda tangan tidak berasal dari CA yang dipercaya server ini.';
      } else if (low.indexOf('no processable signatures') >= 0) {
        msg = 'Dokumen ini tidak memuat tanda tangan elektronik.';
      } else {
        msg = e.split('\n')[0]; // already Indonesian, or unknown: first line only
      }
      if (!seen[msg]) { seen[msg] = 1; out.push(msg); }
    });
    return out;
  }

  // A DN escapes a comma inside a value as "\,", so splitting on the
  // first comma truncates any name carrying a degree ("Gita Aurora\, S.Ap."
  // came out as "Gita Aurora\"). Consume escaped characters, then unescape.
  function dn(subject, key){
    var m = new RegExp(key + "=((?:\\\\.|[^,])*)").exec(subject || "");
    return m ? m[1].replace(/\\(.)/g, "$1") : "";
  }

  function humanCert(s){
    return ({revoked:'DICABUT', device_reported_lost:'perangkat dilaporkan hilang',
             not_server_verified:'tidak diverifikasi otomatis oleh server', active:'aktif'})[s] || s; }

  function render(top){
    var o = top.verification || top;
    var sigs = o.signatures || [];
    var rec = top.record || {};
    var storedOnly = rec.verification_status === 'stored_unverified' || rec.certificate_status === 'not_server_verified';
    var storedNote = storedOnly
      ? '<p class="muted">⚠ Berkas ini terlalu besar untuk diverifikasi otomatis oleh server saat diunggah — server hanya menyimpan salinan &amp; mencatat SHA-512-nya. Kecocokan kriptografis di atas dihitung sekarang dari berkas yang Anda unggah.</p>'
      : '';
    if (o.valid && sigs.length){
      var s = sigs[0];
      var subj = s.subject || '';
      var name = dn(subj, 'CN') || '-';
      var org  = dn(subj, 'O')  || '-';
      var pid  = rec.public_id || String(s.contact || '').replace('pqc-public-id:', '');
      // The stored document is never shown or offered for download; the
      // verdict plus the SHA-512 comparison below is the whole answer.
      var docv = '';
      if (top.registered === true && pid){
        var pageURL = window.SRV + '/v/' + encodeURIComponent(pid);
        docv =
          '<div class="docbtns" style="margin-top:14px">' +
          '<a class="btn alt" href="'+esc(pageURL)+'" target="_blank" rel="noopener">Halaman catatan server</a>' +
          '</div>';
      }
      out.innerHTML =
        '<div class="status"><span class="badge ok">TANDA TANGAN SAH</span></div>' +
        '<table>' +
          row('Penanda tangan', name) +
          row('Instansi', org) +
          row('Algoritma', s.algorithm) +
          row('Alasan', s.reason) +
          row('Waktu (klaim perangkat)', s.client_claimed_signing_time) +
          row('No. sertifikat', s.certificate_serial) +
          row('Sidik jari sertifikat', rec.certificate_fingerprint) +
          row('Perangkat', rec.device_label) +
          row('Status sertifikat', rec.certificate_status ? humanCert(rec.certificate_status) : '') +
          row('Rantai tepercaya', s.trusted_chain ? 'ya' : 'TIDAK') +
          row('Sertifikat dicabut', s.revoked ? 'YA' : 'tidak') +
          row('Terdaftar di server', top.registered === true ? (storedOnly ? 'ya (disimpan, tidak diverifikasi otomatis)' : 'ya') : 'tidak') +
          row('Sidik jari cocok dengan catatan server',
              top.hash_match === true ? 'ya' : (top.hash_match === false ? 'TIDAK — berkas berbeda' : '')) +
          row('ID verifikasi', pid) +
        '</table>' + docv + storedNote +
        '<p class="muted">Waktu di atas berasal dari jam perangkat penandatangan, bukan stempel waktu tepercaya.</p>';
    } else {
      var errs = o.errors || (sigs[0] && sigs[0].errors) || [];
      var hashNote = top.hash_match === false
        ? '<p class="bad"><b>Sidik jari SHA-512 berkas ini tidak cocok dengan catatan server.</b> ' +
          'Server menerbitkan satu urutan byte untuk ID tersebut, dan berkas ini bukan itu.</p>'
        : '';
      var shown = humanErrs(errs);
      out.innerHTML =
        '<div class="status"><span class="badge bad">TIDAK SAH</span></div>' + hashNote +
        (shown.length ? '<ul class="muted">' + shown.map(function(x){ return '<li>'+esc(x)+'</li>'; }).join('') + '</ul>'
                      : '<p class="muted">Dokumen tidak memuat tanda tangan ML-DSA-65 yang valid.</p>');
    }
  }
})();
</script>`
