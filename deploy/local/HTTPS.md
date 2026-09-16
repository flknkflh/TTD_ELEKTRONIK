# HTTPS melalui Caddy bersama

Update 14 September 2026: HTTPS IP aktif di https://136.244.116.132 dengan
sertifikat publik Let's Encrypt profil shortlived, dikelola otomatis oleh Caddy.
Admin: https://136.244.116.132/admin. Konfigurasi live berada di
/opt/wgshield/caddy/Caddyfile; snapshot sebelum perubahan ada di
Caddyfile.shared.before-https dan konfigurasi yang diterapkan ada di
Caddyfile.shared.pending. Default SNI sekarang IP publik untuk browser tanpa SNI.
Compose utama menggunakan URL HTTPS dan port API loopback. Jalankan deployment
biasa dengan docker compose up -d --no-deps api. Jangan gunakan override domain
di bawah sampai DNS tersedia. Port publik 8098/8099 ditutup; gunakan HTTPS tanpa
port. QR lama dengan IP:8099 masih membutuhkan migrasi/redirect tersendiri.

Rencana opsional migrasi ke domain (belum diterapkan):
Caddy WG-SHIELD aktif pada 80/443;
API terhubung ke shared_edge dengan alias pqsign-api. DNS publik
pqsign.idk-shield.web.id mengembalikan NXDOMAIN, sehingga cutover belum dilakukan.

1. Tambahkan record DNS A: pqsign -> 136.244.116.132 pada zona idk-shield.web.id.
   Jangan tambahkan AAAA kecuali IPv6 VPS dan firewall sudah dikonfigurasi.
2. Backup konfigurasi Caddy dan konfigurasi deployment yang ada. Pastikan backup
   database, cadata, dan objdata tersedia. Jangan hapus atau mengganti volume.
3. Tambahkan isi Caddyfile.https ke /opt/wgshield/caddy/Caddyfile tanpa mengganti
   situs WG-SHIELD. Validasi lalu reload hanya Caddy:

   ```sh
   docker exec wgshield-caddy-1 caddy validate --config /etc/caddy/Caddyfile
   docker exec wgshield-caddy-1 caddy reload --config /etc/caddy/Caddyfile
   curl -I https://pqsign.idk-shield.web.id/
   curl -I https://pqsign.idk-shield.web.id/admin
   curl -I http://pqsign.idk-shield.web.id/
   ```

4. Setelah HTTPS valid, jalankan dari deploy/local (Compose >= 2.24.4 diperlukan
   untuk !override):

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.https.yml config --quiet
   docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --no-deps api
   ```

   Gunakan kedua file tersebut pada deployment berikutnya agar binding publik
   tidak aktif kembali. Override menetapkan URL HTTPS dan kepercayaan header
   proxy sekaligus membatasi port API ke loopback.
5. Uji halaman utama, admin/login, upload/download, /s dan /v dengan ID valid,
   serta klien desktop/Android. QR baru harus memakai HTTPS. Perbarui alamat server
   pada klien lama. QR lama yang memakai IP:8099 tidak berubah: setelah port
   publik ditutup, QR tersebut memerlukan layanan redirect terpisah jika ingin
   tetap dapat dibuka langsung. Jangan mengedit PDF yang sudah ditandatangani.

Batas proxy 1032 MB mengikuti batas upload stack lokal 1024 MB ditambah overhead.
HSTS awal satu hari, tanpa includeSubDomains; perpanjang setelah HTTPS stabil.
TLS situs web tidak memerlukan perubahan pada CA penandatanganan PDF.

Rollback cutover: jalankan docker compose -f docker-compose.yml up -d --no-deps api
dari deploy/local untuk kembali ke konfigurasi awal. Ini membuka HTTP publik lagi;
gunakan hanya bila diperlukan untuk pemulihan. Jangan jalankan down -v.
