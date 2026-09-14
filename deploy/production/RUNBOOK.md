# Runbook: PQ PDF Sign ke server produksi

Dokumen ini dipakai **saat server produksi sudah tersedia**. Ikuti bagian
berurutan dari 0 sampai 9. File pendukung ada di folder ini:

| File | Isi |
|---|---|
| `docker-compose.yml` | Caddy (satu-satunya port publik), API, PostgreSQL |
| `Dockerfile` | Image API non-root, tanpa alat CA |
| `Caddyfile` | HTTPS domain, TLS 1.3 hybrid ML-KEM, HSTS, batas body |
| `.env.example` | Semua variabel yang wajib diisi |
| `backup.sh` | Backup harian terenkripsi (database + PDF) |

## Aturan untuk yang menjalankan (manusia atau AI agent)

1. Kerjakan **berurutan**. Jangan lanjut ke langkah berikut sebelum bagian
   **Cek** di langkah itu lulus.
2. Titik bertanda **⛔ STOP** butuh keputusan atau tindakan manusia. Berhenti,
   laporkan, dan tunggu.
3. **Jangan pernah** menampilkan, menyalin ke chat, atau menulis ke log: isi
   `.env`, password superadmin, passphrase CA, kode MFA, private key age.
4. Semua perintah dijalankan sebagai user admin dengan `sudo`, dari
   `/opt/pqsign/deploy/production` kecuali disebut lain.
5. Kalau ada yang tidak sesuai dokumen ini, **berhenti dan laporkan**. Jangan
   mengarang jalan pintas (terutama yang mematikan MFA, rate limit, atau
   pemeriksaan TLS).

---

## 0. Keputusan yang harus sudah ada ⛔ STOP

Tanyakan dan catat sebelum mulai:

| Keputusan | Contoh | Catatan |
|---|---|---|
| Domain produksi | `pqsign.instansi.go.id` | Tercetak di QR bertahun-tahun. **Final sebelum dokumen pertama.** |
| E-mail ACME | `it@instansi.go.id` | Notifikasi Let's Encrypt |
| Mode CA | **A: Root + Intermediate offline** | Satu-satunya mode yang didukung kode saat ini (lihat §9) |
| Batas ukuran PDF | 64 MB | Library PDF menolak > 64 MB |
| IP kantor untuk konsol admin | opsional | Membatasi `/admin` (§5.4) |
| Lokasi backup di luar server | object storage / server lain | Wajib |
| Pemegang passphrase CA & saksi ceremony | 2–3 orang | §3 |

---

## 1. Syarat kode yang di-deploy

Deploy **hanya dari commit yang sudah di-review dan di-tag** (mis. `v1.0.0`),
bukan dari working tree yang belum di-commit.

**Cek** di clone repo:

```sh
ls server/internal/store/migrations/ | grep -E '0008_admin_mfa.up|0009_crls.up'   # dua-duanya harus ada
grep -q 'hChangeOwnPassword' server/internal/api/accounts.go && echo ok-password
grep -q 'loginAdminMFA' server/internal/api/mfa.go && echo ok-mfa
grep -q 'replaceCRL' server/internal/api/crl.go && echo ok-crl
```

Jalankan test sebelum deploy (butuh Docker):

```sh
docker run --rm -v "$PWD":/src -w /src/server golang:1.27 go test ./... 2>&1 | tail -20
```

**Cek:** semua paket `ok`. Kalau ada `FAIL` → ⛔ STOP.

---

## 2. Siapkan server

Target: Ubuntu 24.04 LTS, ≥ 4 vCPU, ≥ 8 GB RAM, disk terpisah atau cukup untuk
PDF, **dipakai khusus PQ PDF Sign**.

### 2.1 User admin dan SSH

```sh
adduser pqadmin && usermod -aG sudo pqadmin
install -d -m 700 -o pqadmin -g pqadmin /home/pqadmin/.ssh
# tempel public key admin ke /home/pqadmin/.ssh/authorized_keys (chmod 600)
```

**Cek dulu** login `ssh pqadmin@SERVER` dengan key berhasil dari sesi lain,
**baru** kunci SSH:

```sh
cat > /etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
EOF
sshd -t && systemctl reload ssh
```

**Cek:** `sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication)'` →
`permitrootlogin no`, `passwordauthentication no`.

### 2.2 Paket, update otomatis, jam

```sh
apt-get update && apt-get -y upgrade
apt-get install -y ca-certificates curl git ufw chrony unattended-upgrades age dnsutils
dpkg-reconfigure -f noninteractive unattended-upgrades
systemctl enable --now chrony
```

**Cek:** `timedatectl | grep synchronized` → `yes`. Jam yang meleset membuat
kode MFA admin selalu ditolak.

### 2.3 Firewall

```sh
ufw default deny incoming && ufw default allow outgoing
ufw allow OpenSSH          # atau: ufw allow from <IP-kantor> to any port 22
ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp
ufw --force enable
```

Catatan: port yang di-publish Docker **melewati ufw**. Karena itu hanya Caddy
yang boleh punya `ports:` di compose (sudah demikian). Jangan tambahkan
`ports:` ke `api` atau `postgres`.

### 2.4 Docker

```sh
curl -fsSL https://get.docker.com | sh
cat > /etc/docker/daemon.json <<'EOF'
{ "log-driver": "json-file", "log-opts": { "max-size": "50m", "max-file": "5" }, "live-restore": true }
EOF
systemctl restart docker
```

**Cek:** `docker compose version` berjalan.

---

## 3. PKI ceremony (di laptop offline, BUKAN di server) ⛔ STOP

Dikerjakan manusia dengan saksi, mengikuti `docs/pki-ceremony.md` §0–§3.
Ringkasnya:

1. Laptop khusus, boot dari live USB, **tanpa jaringan**.
2. Binary `ca-admin` dibuild di mesin lain
   (`cd tools/ca-admin && go build -o ca-admin .`), SHA-256 dicocokkan dua orang.
3. `PQC_CA_PASSPHRASE` diketik pemegang passphrase (tidak disimpan di file).
4. `ca-admin init --dir /mnt/ca/pqc-ca --root-cn "<Instansi> PQC Root CA" --inter-cn "<Instansi> PQC Device Signing CA"`
5. `ca-admin status` → catat dua fingerprint di run sheet.
6. `ca-admin crl --dir /mnt/ca/pqc-ca --days 7` → CRL kosong pertama.
7. `ca-admin backup` ke dua USB terenkripsi, uji `restore`, simpan di dua brankas.
8. Salin **hanya** isi `public/` ke USB polos: `root-ca.crt.pem`,
   `ca-chain.pem`, `crl.pem`.

**Yang dibawa ke server hanya 3 file publik itu.** Tidak boleh ada
`key.pem`, `key.pem.enc`, `ledger.json`, `ceremony.jsonl`, atau arsip backup CA.

**Jangan pakai CA lab** (`/opt/pqc` di server lab) untuk produksi.

---

## 4. DNS ⛔ STOP

Minta pemilik domain membuat record:

```
A     <domain-produksi>   <IP-publik-server>   TTL 300
AAAA  (hanya jika server punya IPv6 publik yang benar)
```

**Cek** dari server (ulangi sampai benar, jangan lanjut sebelumnya):

```sh
dig +short <domain-produksi> A @1.1.1.1
dig +short <domain-produksi> A @8.8.8.8
curl -s -4 ifconfig.me
```

Ketiga nilai harus sama. Alasan menunggu: Caddy langsung meminta sertifikat
saat start; Let's Encrypt membatasi 5 kegagalan validasi per jam per nama.

---

## 5. Deploy

### 5.1 Kode dan konfigurasi

```sh
sudo install -d -o pqadmin -g pqadmin /opt/pqsign
git clone https://github.com/flknkflh/TTD_ELEKTRONIK.git /opt/pqsign
cd /opt/pqsign && git checkout <tag-rilis>
cd deploy/production

cp .env.example .env && chmod 600 .env
sed -i "s|^PQC_JWT_SECRET=.*|PQC_JWT_SECRET=$(openssl rand -hex 32)|" .env
sed -i "s|^PQC_DB_PASSWORD=.*|PQC_DB_PASSWORD=$(openssl rand -hex 24)|" .env
# lalu edit PQC_DOMAIN dan ACME_EMAIL sesuai §0 (nano .env)
```

### 5.2 Materi CA publik

```sh
install -d -m 755 pki
cp /media/usb/root-ca.crt.pem /media/usb/ca-chain.pem pki/
chmod 644 pki/*.pem
sha256sum pki/root-ca.crt.pem
grep -l "PRIVATE KEY" pki/* && echo "BAHAYA: ada private key" || echo "ok: tidak ada private key"
```

**Cek:** SHA-256 `root-ca.crt.pem` **sama dengan run sheet ceremony** dan
keluar `ok: tidak ada private key`. Beda → ⛔ STOP.

### 5.3 Validasi lalu jalankan

```sh
docker compose config -q && echo compose-ok
docker run --rm --env-file .env -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:2.11-alpine \
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker compose up -d --build
docker compose ps
```

**Cek:**

- `docker compose ps` → `postgres` dan `api` **healthy**, `caddy` running.
- `docker compose logs api | grep -E 'listening|MFA DISABLED|lab issuer'` →
  dua baris `listening`, **tidak ada** `MFA DISABLED` dan **tidak ada** `lab issuer`.
- `docker compose logs caddy | grep -i 'certificate obtained'` → muncul untuk domain.
- `docker compose exec postgres psql -U pqc -d pqc -Atc "select version from schema_migrations order by 1 desc limit 1"` → `0009_crls` (atau lebih baru).

### 5.4 (Opsional) Batasi konsol admin ke IP kantor

Di `Caddyfile`, buka komentar blok `@adminOutside`, isi IP kantor, lalu
`docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`.
**Cek:** `/admin` dari IP lain → 403, dari kantor → halaman login.

---

## 6. Setup pertama di konsol admin

### 6.1 Superadmin

```sh
docker compose logs api | grep 'SUPER ADMIN created'
```

Password acak tercetak **satu kali**. Manusia yang menyalinnya ⛔ STOP (agent
tidak menampilkan nilainya di chat).

Di `https://<domain>/admin`:

1. Login `superadmin` + password dari log → langsung diminta **aktifkan MFA**:
   pindai QR dengan Google Authenticator, masukkan kode, **simpan 10 kode
   pemulihan** di tempat aman terpisah dari HP.
2. Menu Admin → **Ganti kata sandi saya** → password baru yang kuat.
3. Buat akun admin operasional (satu per orang, bukan akun bersama). Setiap
   admin wajib memasang MFA saat login pertama.

### 6.2 CRL pertama

Admin (bukan superadmin) → **Utilitas** → **Impor CRL** → `crl.pem` dari
ceremony.

**Cek:** status berbunyi `CRL aktif #1 · 0 sertifikat tercantum · berlaku`, dan
`curl -sI https://<domain>/api/v1/public/ca/crl.pem` → `200`.

---

## 7. Verifikasi sebelum go-live

Semua harus lulus. Satu gagal → ⛔ STOP.

### 7.1 Jaringan dan TLS

```sh
ss -tlnp | grep docker-proxy | grep -vE ':(80|443) ' || echo ok-hanya-80-443   # docker hanya boleh membuka 80/443
curl -sI http://<domain>/ | head -3        # 308 ke https
curl -sI https://<domain>/ | grep -i strict-transport-security
curl -s https://<domain>/api/v1/public/ca/root.crt | sha256sum   # sama dengan run sheet
```

Dari komputer **lain** (bukan server): `nmap -Pn -p 1-10000 <IP-server>` →
hanya 22, 80, 443 terbuka.

Uji TLS 1.3 hybrid pasca-kuantum (butuh Docker):

```sh
mkdir -p /tmp/tlsprobe && cat > /tmp/tlsprobe/main.go <<'EOF'
package main

import ("crypto/tls"; "fmt"; "os")

func main() {
	c, err := tls.Dial("tcp", os.Args[1]+":443", &tls.Config{ServerName: os.Args[1]})
	if err != nil { fmt.Println("error:", err); os.Exit(1) }
	st := c.ConnectionState()
	fmt.Println(tls.VersionName(st.Version), st.CurveID)
}
EOF
docker run --rm -v /tmp/tlsprobe:/w -w /w golang:1.27 go run main.go <domain>
```

**Cek:** keluar `TLS 1.3 X25519MLKEM768`.

### 7.2 Keamanan aplikasi

```sh
docker compose exec api id                                   # uid=10001(pqc), bukan root
docker inspect pqsign-api-1 --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}'   # tidak 0
docker compose exec api printenv | grep -E 'MFA_DISABLED|RATE_LIMIT_DISABLED|DEV_LAB' || echo ok-tidak-ada
```

Rate limit login (proxy dipercaya dengan benar):

```sh
for i in $(seq 1 12); do curl -s -o /dev/null -w "%{http_code} " -X POST https://<domain>/api/v1/auth/login -d '{"email":"x","password":"y"}'; done; echo
```

**Cek:** beberapa pertama `401`, lalu `429`. Tunggu 1 menit sesudahnya.

### 7.3 Uji end-to-end dengan akun uji

1. App (build rilis, §9) → daftar akun uji → admin menyetujui.
2. App mendaftarkan perangkat → di konsol **Perangkat** status `submitted`.
3. Terbitkan sertifikat offline (§8.2) → **Unggah sertifikat…** → status `issued`.
4. Tanda tangani PDF uji → pindai QR dengan HP biasa → terbuka
   `https://<domain>/v/...` tanpa peringatan browser, status valid.
5. Unggah PDF di halaman verifikasi → valid.
6. Cabut sertifikat uji (Utilitas) → terbitkan CRL baru offline → impor →
   verifikasi ulang PDF → **tidak valid, dicabut**.
7. `docker compose restart api` → status CRL tetap nomor yang sama, PDF uji
   tetap tidak valid.
8. Nonaktifkan / hapus akun uji.

### 7.4 Backup dan restore drill

Jalankan §8.1 sekali, lalu **restore ke server/VM terpisah** (bukan produksi):

```sh
age -d -i key.txt db-*.dump.age > db.dump
docker run -d --name pgdrill -e POSTGRES_PASSWORD=x postgres:17-alpine
docker cp db.dump pgdrill:/db.dump
docker exec pgdrill sh -c 'until pg_isready -U postgres; do sleep 1; done; createdb -U postgres pqc && pg_restore -U postgres -d pqc --no-owner /db.dump'
docker exec pgdrill psql -U postgres -d pqc -Atc "select count(*) from accounts"
```

**Cek:** jumlah akun sesuai. Hapus `db.dump`, `key.txt`, dan container drill
setelahnya.

---

## 8. Operasional rutin

### 8.1 Backup harian

Private key age dibuat **di luar server** (`age-keygen -o key.txt`); hanya
public key (`age1...`) yang dipakai di server.

```sh
chmod 700 backup.sh
echo '15 2 * * * root AGE_RECIPIENT=age1PUBLICKEY /opt/pqsign/deploy/production/backup.sh >> /var/log/pqsign-backup.log 2>&1' > /etc/cron.d/pqsign-backup
```

Salin `/var/backups/pqsign` ke lokasi di luar server setiap hari (rsync/rclone
ke storage terpisah). Backup berisi hash password, secret TOTP admin, dan
riwayat CRL — karena itu wajib terenkripsi.

### 8.2 Terbitkan sertifikat perangkat (CA offline)

1. Konsol → **Perangkat** → **Unduh CSR** tiap pendaftaran `submitted`.
2. Untuk tiap CSR buat `<id>.meta.json`:
   `{"account":"email@instansi","device":"label perangkat","cn":"Nama Lengkap"}`
   (identitas dari akun yang sudah diverifikasi, **bukan** dari isi CSR).
3. Di laptop CA:
   ```sh
   ca-admin batch-issue --dir /mnt/ca/pqc-ca --in /media/in --out /media/out \
     --org "<Instansi>" --days 365 --crl-url https://<domain>/api/v1/public/ca/crl.pem
   ```
   Beda instansi → jalankan per kelompok `--org`.
4. Konsol → **Unggah sertifikat…** untuk masing-masing.

### 8.3 CRL mingguan (wajib)

CRL berlaku 7 hari. Setiap minggu, dan segera setelah ada pencabutan:

```sh
ca-admin revoke --dir /mnt/ca/pqc-ca --serial <hex> --reason keyCompromise   # bila ada
ca-admin crl --dir /mnt/ca/pqc-ca --days 7
```

Impor `public/crl.pem` di konsol → Utilitas. Kalau lewat, konsol menampilkan
**BASI**. Server tetap menolak sertifikat yang dicabut di database, tetapi app
di HP/laptop hanya tahu lewat CRL.

### 8.4 Pemantauan

- Uptime `https://<domain>/api/v1/public/ca/root.crt` (200).
- Masa berlaku sertifikat TLS (Caddy memperbarui otomatis; alert < 14 hari).
- Disk volume `pgdata` dan `objdata`, CPU container `api` (SF-1).
- Status CRL: `GET /api/v1/admin/capabilities` → `crl.stale` harus `false`.
- Audit log: lonjakan `auth.login` gagal / `mfa code` gagal.
- Log backup `/var/log/pqsign-backup.log` harian.

### 8.5 Update aplikasi

```sh
./backup.sh                                  # dengan AGE_RECIPIENT
cd /opt/pqsign && git fetch --tags && git checkout <tag-baru>
cd deploy/production && docker compose up -d --build api
docker compose logs --tail=50 api
```

Migrasi database berjalan otomatis saat start. Ulangi §7.1–7.2.

### 8.6 Insiden

| Kejadian | Tindakan |
|---|---|
| Admin kehilangan HP | Pakai kode pemulihan; atau superadmin → Reset MFA |
| Superadmin kehilangan HP + semua kode pemulihan | Di server: `docker compose exec postgres psql -U pqc -d pqc -c "DELETE FROM admin_mfa WHERE account_id=(SELECT id FROM accounts WHERE role='superadmin')"` → login ulang, pasang MFA baru |
| Kunci perangkat pengguna bocor / HP hilang | Cabut sertifikat → CRL baru → impor |
| Intermediate CA bocor | `docs/pki-ceremony.md` §6 |
| Database rusak | Restore dari backup terbaru (§7.4, ke produksi) |
| Versi baru bermasalah | `git checkout <tag-sebelumnya>` → `docker compose up -d --build api` (migrasi tidak di-rollback otomatis; restore DB bila skema baru bermasalah) |

---

## 9. Yang BELUM selesai di kode (cek sebelum go-live) ⛔ STOP

| Item | Wajib sebelum | Keterangan |
|---|---|---|
| **App Android: `insecure_tls` default `true`** (menerima sertifikat apa saja) | Rilis app | Ubah default `false`, hapus opsi dari build rilis |
| **App Windows: opsi `InsecureSkipVerify`** | Rilis app | Hapus dari build rilis |
| Alamat server default di app masih `http://136.244.116.132:8099` | Rilis app | Ganti ke `https://<domain>` |
| Build rilis Android bertanda tangan keystore rilis, EXE bertanda tangan | Rilis app | `docs/release-checklist.md` |
| Mode CA B (Intermediate online) | Hanya jika dipilih | Butuh passphrase terpisah Root/Intermediate + perintah rotasi Intermediate |
| Rate limit `auth/register` | Disarankan | Belum ada |
| Pencabutan token sesi | Disarankan | Token berlaku 15 menit |
| Reset / ganti password user biasa | Disarankan | Belum ada |
| SF-1 parser PDF (loop CPU) | Diterima dengan mitigasi | Batas memori/CPU + timeout sudah dipasang |

## Dilarang di produksi

- Menyetel `PQC_DEV_LAB_CA_ADMIN`, `PQC_DEV_LAB_CA_DIR`, `PQC_ADMIN_MFA_DISABLED`,
  atau `PQC_RATE_LIMIT_DISABLED`.
- Menjalankan `deploy/local/seed.sh` atau `tools/dev-admin.sh`.
- Menambahkan `ports:` ke `api` atau `postgres`.
- Menaruh private key CA apa pun di server, termasuk di backup server.
- Memakai CA, database, JWT secret, atau password dari server lab.
- `docker compose down -v`.
- Mengganti `PQC_DOMAIN` setelah dokumen pertama ditandatangani (QR lama rusak).
