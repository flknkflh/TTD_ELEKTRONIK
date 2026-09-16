# Redirect sementara untuk QR HTTP lama

Layanan terpisah `pqsign-qr-demo` mendengarkan hanya pada IP publik
136.244.116.132 port TCP 8098 dan 8099. API tetap pada loopback 127.0.0.1 di
port yang sama, jadi tidak berebut binding. Caddy HTTPS tetap pada 443.

GET/HEAD `/`, `/v/*`, dan `/s/*` diarahkan dengan HTTP 302 ke
`https://136.244.116.132` dengan path/query yang sama. Header Cache-Control
no-store mencegah caching redirect demo. Tidak ada reverse proxy ke API;
path/metode lain dijawab 404, termasuk login, upload, dan admin.

Mengaktifkan dari VPS:

```sh
docker compose -f /opt/pqc/deploy/local/docker-compose.qr-demo.yml up -d
```

Menghentikan setelah demo (tidak menyentuh API, DB, CA, atau dokumen):

```sh
docker compose -f /opt/pqc/deploy/local/docker-compose.qr-demo.yml down
```

Pemeriksaan contoh (gunakan ID dokumen sebenarnya untuk hasil verifikasi):

```sh
curl -I http://136.244.116.132:8099/v/ID-DOKUMEN
curl -I http://136.244.116.132:8098/s/ID-DOKUMEN
```

UFW sudah mengizinkan 8098/8099 saat aktivasi, sehingga tidak diubah. Firewall
provider juga harus mengizinkan TCP 8098/8099 untuk akses dari luar VPS.
Redirect tidak memperbaiki dokumen/record yang hilang dan tidak mengedit PDF.
QR lama dengan skema `https://IP:8099` tidak didukung: port demo ini HTTP saja.
Untuk verifikasi baru gunakan HTTPS tanpa port tambahan.
