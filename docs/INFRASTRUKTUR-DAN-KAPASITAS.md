# Laporan Infrastruktur dan Perkiraan Kapasitas

## PQC PDF Sign - Versi Saat Ini

Tanggal penyusunan: 14 September 2026

## Ringkasan Eksekutif

PQC PDF Sign melakukan penandatanganan PDF sepenuhnya pada perangkat pengguna. Server menerima PDF yang telah ditandatangani, memverifikasi tanda tangan terhadap Root CA, menyimpan dokumen dan metadata, serta menyediakan halaman verifikasi publik.

Akses publik direncanakan hanya melalui HTTPS port 443. Listener aplikasi pada port 8098 dan 8099 serta PostgreSQL pada port 5432 harus tetap berada di jaringan internal. Trafik terbesar berasal dari upload/download PDF dan unduhan pembaruan aplikasi.

## 1. Inventaris Port

| Port | Cakupan | Fungsi |
|---|---|---|
| 443 | Publik | HTTPS utama: verifier, API, admin, QR, dan update |
| 443/UDP | Publik, opsional | HTTP/3 melalui QUIC bila diaktifkan pada reverse proxy |
| 80 | Publik | Redirect HTTP menuju HTTPS |
| 8099 | Internal/localhost | Receiver API lengkap, autentikasi, admin, upload, dan update |
| 8098 | Internal/localhost | Situs verifikasi publik dengan rute terbatas |
| 5432 | Internal Docker | PostgreSQL untuk akun, sertifikat, metadata, dan audit |
| 22 | Infrastruktur | Administrasi VPS dan SSH tunnel |
| 53 | Infrastruktur eksternal | Resolusi DNS melalui UDP/TCP |

Port 8098 dan 8099 pada konfigurasi terbaru di-bind ke 127.0.0.1 untuk diagnostik lokal. PostgreSQL tidak dipublikasikan ke host atau internet. Seluruh trafik pengguna masuk melalui reverse proxy HTTPS.

## 2. Protokol Komunikasi

| Jalur komunikasi | Transport | Protokol aplikasi | Enkripsi |
|---|---|---|---|
| Pengguna ke reverse proxy | TCP 443 | HTTPS, HTTP/1.1 atau HTTP/2 | TLS |
| Pengguna ke HTTP/3, bila aktif | UDP 443 | HTTPS melalui QUIC/HTTP/3 | TLS 1.3 |
| HTTP redirect | TCP 80 | HTTP | Tidak; hanya redirect |
| Reverse proxy ke API | TCP 8098/8099 | HTTP | Jaringan internal Docker |
| API ke PostgreSQL | TCP 5432 | PostgreSQL wire protocol | Jaringan internal Docker |
| Operator ke VPS | TCP 22 | SSH | SSH |
| Resolusi domain | UDP/TCP 53 | DNS | Bergantung penyedia DNS |

Tidak terdapat WebSocket, RTSP, RTP, WebRTC, MQTT, atau gRPC streaming pada versi saat ini.

## 3. Perkiraan Bandwidth

Bandwidth utama mengikuti ukuran PDF. Login, sertifikat, QR, record verifikasi, dan audit biasanya hanya membutuhkan puluhan sampai ratusan kilobyte per proses.

Per transaksi dokumen:

- Metadata, login, reservasi, dan sertifikat: sekitar 50-500 KB.
- Upload PDF bertanda tangan: sebesar ukuran PDF.
- Download kembali: tambahan sebesar ukuran PDF.
- Overhead HTTPS dan HTTP: sekitar 2-10 persen.

| Ukuran PDF | Target selesai 1 menit | Target selesai 5 menit |
|---:|---:|---:|
| 10 MB | sekitar 1,4 Mbps | sekitar 0,3 Mbps |
| 100 MB | sekitar 14 Mbps | sekitar 2,8 Mbps |
| 350 MB | sekitar 49 Mbps | sekitar 9,8 Mbps |
| 1 GB | sekitar 143 Mbps | sekitar 29 Mbps |

Contoh: satu PDF 10 MB membutuhkan sekitar 10-11 MB untuk upload saja atau 20-22 MB bila diunggah dan diunduh kembali. Seratus dokumen 10 MB per hari membutuhkan sekitar 1-2,2 GB per hari.

Koneksi server simetris 100 Mbps cukup untuk pilot dan beberapa pengguna bersamaan. Untuk banyak upload ratusan MB secara paralel, disarankan 500 Mbps sampai 1 Gbps.

File update saat ini berukuran sekitar 16,3 MB untuk Windows dan 31,5 MB untuk Android per instalasi. Keseluruhan artefak update yang tersimpan saat laporan dibuat sekitar 154 MB.

## 4. Streaming atau Bukan

Aplikasi bukan layanan streaming realtime. Transfer dokumen menggunakan request-response HTTPS.

- File kecil dikirim sebagai body HTTP biasa.
- Klien Android membagi PDF di atas 2 MB menjadi chunk 2 MB.
- Upload besar mendukung mekanisme resumable menggunakan POST, PATCH, dan GET.
- Server dapat menulis file ke storage sambil menghitung SHA-512.
- Proses stamp dan verifikasi PDF tidak bersifat streaming karena library memproses dokumen secara utuh di memori.

Istilah yang tepat adalah chunked/resumable file transfer, bukan media streaming. Upload sementara kedaluwarsa setelah dua jam. Batas konfigurasi lokal adalah upload 1.024 MB, stamp 150 MB, dan verifikasi ketat 350 MB. Dokumen di atas batas verifikasi dapat disimpan sebagai store-only tanpa verifikasi otomatis server.

## 5. Rencana Domain dan Subdomain

Disarankan memakai domain resmi yang singkat dan mudah dikenali, misalnya pqsign.id. Nama tersebut adalah contoh dan harus diperiksa ketersediaan serta kepemilikannya sebelum digunakan.

| Domain atau subdomain | Fungsi |
|---|---|
| verify.pqsign.id | Halaman verifikasi publik dan tujuan QR pada PDF |
| api.pqsign.id | API untuk aplikasi Windows dan Android |
| admin.pqsign.id | Portal administrasi dan pengelolaan pengguna |
| download.pqsign.id | Installer, APK, EXE, dan manifest pembaruan |
| pki.pqsign.id | Root CA, certificate chain, dan CRL publik |
| status.pqsign.id | Status layanan dan informasi gangguan |
| docs.pqsign.id | Dokumentasi pengguna dan panduan aplikasi |

Alur akses yang direncanakan:

- Windows/Android menuju api.pqsign.id melalui HTTPS.
- QR PDF menuju verify.pqsign.id/v/{document_id}.
- Administrator menuju admin.pqsign.id melalui HTTPS dan jaringan terbatas.
- Updater menuju download.pqsign.id.
- Klien sertifikat mengambil material publik dari pki.pqsign.id.

Ketentuan penerapan:

1. Semua domain hanya melayani HTTPS melalui port 443.
2. Port internal 8098, 8099, dan 5432 tidak dibuka ke internet.
3. admin.pqsign.id dibatasi menggunakan VPN atau allowlist alamat IP.
4. api.pqsign.id menerapkan rate limiting dan pembatasan ukuran upload.
5. QR baru diarahkan permanen ke verify.pqsign.id.
6. Domain verifikasi dipertahankan jangka panjang karena alamat tertanam dalam PDF.
7. Distribusi update dipisahkan agar dapat dipindahkan ke CDN atau object storage.
8. Material PKI dipisahkan agar URL CRL dan certificate chain tetap stabil.

Tahapan migrasi:

1. Daftarkan dan verifikasi kepemilikan domain.
2. Buat DNS record menuju reverse proxy.
3. Aktifkan sertifikat TLS dan perpanjangan otomatis.
4. Ubah public base URL menjadi https://verify.pqsign.id.
5. Ubah alamat API aplikasi menjadi https://api.pqsign.id.
6. Ubah origin updater menjadi https://download.pqsign.id.
7. Uji login, upload, verifikasi, QR, admin, PKI, dan update aplikasi.
8. Pertahankan alamat IP lama sebagai redirect selama masa transisi.
9. Setelah semua klien bermigrasi, tutup akses publik lewat IP dan port lama.

QR lama di dalam PDF tidak boleh diedit karena perubahan akan merusak tanda tangan. Kompatibilitas atau redirect alamat lama perlu dipertahankan selama masa migrasi.

## 6. Perkiraan Penyimpanan

Penyimpanan server mencakup PDF bertanda tangan, upload sementara, PostgreSQL, data CA, installer aplikasi, log, dan backup.

Rumus dasar:

    Storage PDF per bulan = jumlah pengguna x dokumen per pengguna per bulan x rata-rata ukuran PDF

| Skenario | Dokumen per bulan | Data PDF per bulan |
|---|---:|---:|
| 100 pengguna x 10 PDF x 5 MB | 1.000 | sekitar 5 GB |
| 500 pengguna x 20 PDF x 10 MB | 10.000 | sekitar 100 GB |
| 1.000 pengguna x 30 PDF x 10 MB | 30.000 | sekitar 300 GB |

Tambahan kapasitas yang perlu diperhitungkan:

- Database dan metadata: sekitar 1-5 persen dari ukuran PDF.
- Temporary upload: cadangan 10-30 persen untuk upload bersamaan.
- Log: sekitar 1-10 GB, bergantung trafik dan retensi.
- File update: sediakan 2-5 GB untuk riwayat versi.
- Satu backup penuh membuat kebutuhan mendekati dua kali data aktif.
- Beberapa generasi backup memerlukan sekitar 2,5-3 kali data aktif.

Rekomendasi kapasitas:

| Tahap penggunaan | Kapasitas awal yang disarankan |
|---|---:|
| Pilot kecil | 100-150 GB |
| Produksi menengah | 500 GB |
| Volume tinggi atau retensi panjang | Mulai 1 TB dan gunakan S3/MinIO |

Pertahankan ruang kosong minimal 20-25 persen. Disk workspace saat laporan dibuat berkapasitas 150 GB, sekitar 69 GB terpakai dan 75 GB tersedia. Kapasitas ini cukup untuk pilot, tetapi perlu ditingkatkan apabila PDF disimpan permanen bersama beberapa generasi backup.

## Kesimpulan

Arsitektur saat ini dapat dijalankan dengan satu pintu publik HTTPS pada port 443. Port API dan database harus tetap internal. Kapasitas jaringan 100 Mbps dan storage 100-150 GB memadai untuk pilot. Untuk produksi, pemisahan subdomain, pembatasan akses admin, monitoring kapasitas, backup, dan object storage perlu disiapkan sejak awal.

