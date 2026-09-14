# Runbook: PQ PDF Sign ke server produksi

Dokumen ini dipakai **saat server produksi sudah tersedia**. Ikuti bagian
berurutan dari 0 sampai 9. File pendukung ada di folder ini:

| File | Isi |
|---|---|
| `docker-compose.yml` | Caddy (satu-satunya port publik), API + penerbit CA online, PostgreSQL |
| `Dockerfile` | Image API non-root, berisi `ca-admin` (tanpa kunci CA apa pun) |
| `Caddyfile` | HTTPS domain, TLS 1.3 hybrid ML-KEM, HSTS, batas body |
| `.env.example` | Semua variabel yang wajib diisi |
| `../../tools/backup/` | Backup harian lokal terenkripsi (restic) + laporan untuk super admin (§8.1) |

**Model CA: split CA.** Kunci **Root** hanya pernah ada di container sementara
tanpa jaringan di RAM, lalu disimpan terenkripsi di USB — **tidak pernah** di
disk server. Kunci **Intermediate** dibuat di server, tidak pernah keluar, dan
dipakai API untuk menerbitkan sertifikat perangkat dan CRL secara otomatis.
Kedua kunci dienkripsi dengan passphrase yang **berbeda**.

**Siklus hidup sertifikat:** sertifikat perangkat diperpanjang otomatis
(§8.2); Intermediate dirotasi semi-otomatis — hanya tanda tangan Root yang
dilakukan manusia (§8.8); Root dirotasi manual menurut rencana (§8.9).
Pengingat tampil sebagai banner di konsol admin dan super admin.

## Aturan untuk yang menjalankan (manusia atau AI agent)

1. Kerjakan **berurutan**. Jangan lanjut sebelum bagian **Cek** di langkah
   itu lulus.
2. Titik bertanda **⛔ STOP** butuh keputusan atau tindakan manusia. Berhenti,
   laporkan, dan tunggu.
3. **Jangan pernah** menampilkan, menyalin ke chat, atau menulis ke log/file:
   isi `.env`, isi `secrets/`, password superadmin, passphrase Root atau
   Intermediate, kode MFA, private key age.
4. Semua perintah dijalankan sebagai user admin dengan `sudo`, dari
   `/opt/pqsign/deploy/production` kecuali disebut lain.
5. Kalau ada yang tidak sesuai dokumen ini, **berhenti dan laporkan**. Jangan
   mengarang jalan pintas (terutama yang mematikan MFA, rate limit,
   pemeriksaan TLS, atau pengaman kunci Root).

---

## 0. Keputusan yang harus sudah ada ⛔ STOP

| Keputusan | Contoh | Catatan |
|---|---|---|
| Domain produksi | `pqsign.instansi.go.id` | Tercetak di QR bertahun-tahun. **Final sebelum dokumen pertama.** |
| E-mail ACME | `it@instansi.go.id` | Notifikasi Let's Encrypt |
| Nama CA | `Instansi PQC Root CA`, `Instansi PQC Device Signing CA`, organisasi `Instansi` | Tercetak di sertifikat |
| Pemegang passphrase Root + saksi | 2–3 orang | §3 |
| Dua USB untuk arsip Root | USB-A, USB-B | Disimpan di dua brankas terpisah |
| Penanggung jawab penerimaan risiko | pimpinan / pejabat keamanan | §3.1 |
| Batas ukuran PDF | 64 MB | Library PDF menolak > 64 MB |
| IP kantor untuk konsol admin | opsional | §5.5 |
| Lokasi backup di luar server | object storage / server lain | Wajib |

---

## 1. Syarat kode yang di-deploy

Deploy **hanya dari commit yang sudah di-review dan di-tag** (mis. `v1.0.0`).

**Cek** di clone repo:

```sh
ls server/internal/store/migrations/ | grep -E '0008_admin_mfa.up|0009_crls.up'
grep -q 'loginAdminMFA' server/internal/api/mfa.go && echo ok-mfa
grep -q 'replaceCRL' server/internal/api/crl.go && echo ok-crl
grep -q 'prepareIssuer' server/internal/api/issuer.go && echo ok-issuer
grep -q 'cmdSignIntermediate' tools/ca-admin/split.go && echo ok-split-ca
grep -q 'RenewDueCertificates' server/internal/api/renew.go && echo ok-renew
grep -q 'CheckIntermediateRotation' server/internal/api/issuer.go && echo ok-rotation
```

Jalankan test (butuh Docker):

```sh
docker run --rm -v "$PWD":/src golang:1.27 sh -c '
  cd /src/tools/ca-admin && go test ./... && go build -o /tmp/ca-admin . &&
  cd /src/server && PQC_TEST_CA_ADMIN=/tmp/ca-admin go test ./...' 2>&1 | tail -20
```

**Cek:** semua paket `ok`, termasuk `TestOnlineIssuerLifecycle`,
`TestDeviceCertificateRenewal`, `TestOnlineIssuerRotation` dan
`TestIntermediateRotation` (tidak `skipped`). Ada `FAIL` → ⛔ STOP.

---

## 2. Siapkan server

Target: Ubuntu 24.04 LTS, ≥ 4 vCPU, ≥ 8 GB RAM, **server milik sendiri di
bawah kendali instansi**, dipakai khusus PQ PDF Sign.

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
keduanya `no`.

### 2.2 Paket, update otomatis, jam

```sh
apt-get update && apt-get -y upgrade
apt-get install -y ca-certificates curl git ufw chrony unattended-upgrades restic python3 dnsutils
dpkg-reconfigure -f noninteractive unattended-upgrades
systemctl enable --now chrony
```

**Cek:** `timedatectl | grep synchronized` → `yes` (MFA admin gagal kalau jam
meleset).

### 2.3 Firewall

```sh
ufw default deny incoming && ufw default allow outgoing
ufw allow OpenSSH          # atau: ufw allow from <IP-kantor> to any port 22
ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp
ufw --force enable
```

Port yang di-publish Docker **melewati ufw**; hanya Caddy yang boleh punya
`ports:` (sudah demikian di compose).

### 2.4 Docker

```sh
curl -fsSL https://get.docker.com | sh
cat > /etc/docker/daemon.json <<'EOF'
{ "log-driver": "json-file", "log-opts": { "max-size": "50m", "max-file": "5" }, "live-restore": true }
EOF
systemctl restart docker
```

### 2.5 Kode dan image

```sh
sudo install -d -o pqadmin -g pqadmin /opt/pqsign
git clone https://github.com/flknkflh/TTD_ELEKTRONIK.git /opt/pqsign
cd /opt/pqsign && git checkout <tag-rilis>
cd deploy/production

cp .env.example .env && chmod 600 .env
sed -i "s|^PQC_JWT_SECRET=.*|PQC_JWT_SECRET=$(openssl rand -hex 32)|" .env
sed -i "s|^PQC_DB_PASSWORD=.*|PQC_DB_PASSWORD=$(openssl rand -hex 24)|" .env
# edit PQC_DOMAIN, ACME_EMAIL, PQC_CA_INTERMEDIATE_CN, PQC_CA_ORG sesuai §0 (nano .env)

install -d -m 700 secrets
openssl rand -base64 33 > secrets/ca_intermediate_passphrase
chown 10001:10001 secrets/ca_intermediate_passphrase && chmod 400 secrets/ca_intermediate_passphrase
install -d -m 755 pki && chown 10001:10001 pki

docker compose build api
```

**Cek:** `docker compose config -q && echo ok` dan `docker images | grep pqsign-api`.

Passphrase Intermediate hanya ada di `secrets/` dan di backup volume CA
yang terenkripsi. **Tidak** perlu dicatat manusia: kalau hilang, cukup
ceremony Intermediate baru (§8.6).

---

## 3. Ceremony CA di server (container sementara, tanpa jaringan)

### 3.1 Penerimaan risiko ⛔ STOP

Kunci Root dibuat di **server produksi**, bukan di komputer terpisah yang
tidak pernah terhubung jaringan. Pengamannya: container tanpa jaringan,
filesystem read-only, kunci hanya di RAM (tmpfs), swap dimatikan, langsung
dienkripsi dan dipindah ke USB. **Risiko yang tersisa:** bila server sudah
disusupi sebelum atau saat ceremony (atau ada akses ke RAM/hypervisor),
kunci Root bisa tersalin tanpa jejak. Dampaknya: ceremony ulang, build ulang
app, semua pengguna mendaftar ulang perangkat.

Minta penanggung jawab menandatangani pernyataan (simpan bersama run sheet):

> Saya menerima risiko pembuatan kunci Root CA di server produksi milik
> instansi yang berada di bawah kendali kami, dengan pengaman yang tercantum
> di RUNBOOK §3. Tanggal/jam, nama, tanda tangan, dua saksi.

Siapkan **run sheet** cetak: kolom waktu, langkah, fingerprint, tanda tangan
operator + dua saksi.

### 3.2 Intermediate: kunci + CSR dibuat di server

```sh
docker compose run --rm --no-deps --entrypoint ca-admin api \
  intermediate-csr --dir /ca --inter-cn "<Instansi> PQC Device Signing CA"
install -d -m 755 /opt/pqsign-ceremony/in && chown 10001:10001 /opt/pqsign-ceremony/in
docker compose run --rm --no-deps --entrypoint cat api /ca/intermediate/request.csr.pem \
  > /opt/pqsign-ceremony/in/intermediate.csr.pem
```

**Cek:** keluaran berisi `csr key fp : <hex>` → **tulis di run sheet**. File
CSR diawali `-----BEGIN CERTIFICATE REQUEST-----`. (CSR bersifat publik.)

### 3.3 Siapkan server untuk sesi Root

```sh
lsblk                                   # kenali USB-A
mount /dev/<usb-a-partisi> /media/ca-usb-a
chown 10001:10001 /media/ca-usb-a
swapoff -a && free -h | grep -i swap    # Swap: 0B
```

Pastikan tidak ada orang lain yang login (`who`), dan tidak ada sesi
perekaman terminal.

### 3.4 Sesi Root (satu kali, dengan saksi)

Pemegang passphrase mengetik passphrase (≥ 16 karakter; disarankan 6+ kata
diceware) — **tidak tampil di layar dan tidak tercatat di history**:

```sh
read -rs ROOTPASS && echo
printf '%s' "$ROOTPASS" | docker run --rm -i --network none --read-only \
  --tmpfs /work:rw,size=64m,mode=0700,uid=10001,gid=10001 \
  --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 \
  -v /opt/pqsign-ceremony/in:/in:ro \
  -v /media/ca-usb-a:/usb \
  -v /opt/pqsign/deploy/production/pki:/pki-out \
  -e PQC_CA_OPERATOR="<nama operator>" \
  --entrypoint sh pqsign-api:local -c '
set -eu; umask 077
cat > /work/.pass
export PQC_CA_ROOT_PASSPHRASE_FILE=/work/.pass
echo "network: $(ls /sys/class/net)"
ca-admin init-root --dir /work/root --root-cn "<Instansi> PQC Root CA"
ca-admin sign-intermediate --dir /work/root --csr /in/intermediate.csr.pem \
  --inter-cn "<Instansi> PQC Device Signing CA" --out /pki-out/intermediate.crt.pem
cp /work/root/public/root-ca.crt.pem /pki-out/root-ca.crt.pem
tar -C /work -czf /usb/root-ca-offline.tar.gz root
sha256sum /usb/root-ca-offline.tar.gz
rm -f /work/.pass'
unset ROOTPASS
chmod 644 pki/*.pem
```

**Cek dan catat di run sheet:**

- `network: lo` (tidak ada interface lain → tanpa jaringan).
- `init-root` → **fingerprint Root** dan `not_after`.
- `sign-intermediate` → **fingerprint Intermediate**, dan `csr key fp` **sama
  persis** dengan §3.2. Beda → ⛔ STOP.
- SHA-256 arsip Root.

### 3.5 USB kedua, bersihkan

```sh
mount /dev/<usb-b-partisi> /media/ca-usb-b
cp /media/ca-usb-a/root-ca-offline.tar.gz /media/ca-usb-b/
sha256sum /media/ca-usb-a/root-ca-offline.tar.gz /media/ca-usb-b/root-ca-offline.tar.gz   # harus sama
sync && umount /media/ca-usb-a /media/ca-usb-b
swapon -a
```

Isi arsip: `root/root/key.pem.enc` (terenkripsi passphrase Root),
`root/root/cert.pem`, `intermediates.jsonl`, `ceremony.jsonl`. Masukkan tiap
USB ke kantong tamper-evident bernomor, saksi tanda tangan, simpan di **dua
brankas terpisah**. Kertas passphrase tidak disimpan bersama USB.

**Cek bahwa kunci Root tidak tertinggal di server:**

```sh
find / -xdev \( -name 'key.pem' -o -name 'key.pem.enc' -o -name 'root-ca-offline.tar.gz' \) 2>/dev/null
docker run --rm -v pqsign_cadata:/ca:ro alpine:3.20 find /ca -name 'key.pem*'
ls /opt/pqsign/deploy/production/pki/
```

Hasil yang benar: tidak ada file dari `find /`; volume CA **hanya**
`/ca/intermediate/key.pem.enc`; `pki/` hanya `root-ca.crt.pem` dan
`intermediate.crt.pem`. Lain dari itu → ⛔ STOP.

---

## 4. DNS ⛔ STOP

Minta pemilik domain membuat record `A <domain> <IP-publik-server>` (TTL 300;
AAAA hanya jika IPv6 publik server benar).

**Cek** (ulangi sampai benar):

```sh
dig +short <domain> A @1.1.1.1
dig +short <domain> A @8.8.8.8
curl -s -4 ifconfig.me
```

Ketiganya sama. Jangan start Caddy sebelumnya (Let's Encrypt membatasi 5
kegagalan per jam).

---

## 5. Deploy

### 5.1 Validasi

```sh
docker compose config -q && echo compose-ok
docker run --rm --env-file .env -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:2.11-alpine \
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

### 5.2 Jalankan

```sh
docker compose up -d
docker compose ps
```

**Cek:**

- `postgres` dan `api` **healthy**, `caddy` running.
- `docker compose logs api | grep -E 'issuer|listening|MFA DISABLED|lab issuer'` →
  `online CA issuer (split CA, no Root key)`, dua baris `listening`; **tidak
  ada** `MFA DISABLED` / `lab issuer`.
- `docker compose logs caddy | grep -i 'certificate obtained'` → muncul.
- Migrasi: `docker compose exec postgres psql -U pqc -d pqc -Atc "select version from schema_migrations order by 1 desc limit 1"` → `0009_crls` atau lebih baru.

### 5.3 Pasang sertifikat Intermediate

**Cara A — konsol (disarankan, tanpa restart):** setelah §6.1, superadmin →
menu Admin → kartu **CA penerbit (Intermediate)** → pilih
`pki/intermediate.crt.pem` → **Pasang sertifikat**.

**Cara B — CLI:**

```sh
docker compose exec -T api ca-admin install-intermediate --dir /ca \
  --cert /pki/intermediate.crt.pem --root-cert /pki/root-ca.crt.pem
docker compose restart api
```

**Cek:**

```sh
docker compose exec -T api ca-admin status --dir /ca | grep -E '^root key|^intermediate|gate'
curl -s https://<domain>/api/v1/public/ca/chain.pem | grep -c 'BEGIN CERTIFICATE'   # 2
curl -s https://<domain>/api/v1/public/ca/crl.pem | head -1                        # BEGIN X509 CRL
```

`root key : absent (issuer)`, fingerprint Intermediate sama dengan run sheet,
`gate : OK`. CRL pertama terbit otomatis (paling lambat 1 jam; langsung pada
cara A).

### 5.4 Pengaman yang dijalankan API sendiri

API **menolak start** bila ada `root/key.pem*` di volume CA, bila
`PQC_CA_ROOT_PASSPHRASE[_FILE]` diset, atau bila passphrase Intermediate
kosong. Kalau API restart terus: `docker compose logs api | tail` dan
laporkan ⛔ STOP.

### 5.5 (Opsional) Batasi konsol admin ke IP kantor

Buka komentar blok `@adminOutside` di `Caddyfile`, isi IP, lalu
`docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`.

---

## 6. Setup pertama di konsol admin

### 6.1 Superadmin

```sh
docker compose logs api | grep 'SUPER ADMIN created'
```

Password acak tercetak **satu kali**; manusia yang menyalinnya ⛔ STOP.

Di `https://<domain>/admin`:

1. Login `superadmin` → **aktifkan MFA** (Google Authenticator), **simpan 10
   kode pemulihan** terpisah dari HP.
2. Menu Admin → **Ganti kata sandi saya**.
3. Kartu **CA penerbit** → status **Aktif** dengan fingerprint sesuai run sheet
   (atau pasang sekarang, §5.3 cara A).
4. Buat akun admin operasional (satu per orang); tiap admin memasang MFA saat
   login pertama.

### 6.2 CRL

Tidak ada impor manual: server menerbitkan CRL saat Intermediate terpasang,
setiap ada pencabutan, dan ulang setiap 24 jam.
**Cek:** admin → **Utilitas** → `CRL aktif #N · … · berlaku`.

---

## 7. Verifikasi sebelum go-live

Semua harus lulus. Satu gagal → ⛔ STOP.

### 7.1 Jaringan dan TLS

```sh
ss -tlnp | grep docker-proxy | grep -vE ':(80|443) ' || echo ok-hanya-80-443
curl -sI http://<domain>/ | head -3                             # 308 ke https
curl -sI https://<domain>/ | grep -i strict-transport-security
curl -s https://<domain>/api/v1/public/ca/root.crt | sha256sum  # cocok dengan root-ca.crt.pem dari ceremony
```

Dari komputer **lain**: `nmap -Pn -p 1-10000 <IP-server>` → hanya 22, 80, 443.

TLS 1.3 hybrid pasca-kuantum:

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

**Cek:** `TLS 1.3 X25519MLKEM768`.

### 7.2 Keamanan aplikasi

```sh
docker compose exec api id                                  # uid=10001(pqc)
docker inspect pqsign-api-1 --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}'   # bukan 0
docker compose exec api printenv | grep -E 'MFA_DISABLED|RATE_LIMIT_DISABLED|DEV_LAB|CA_ROOT' || echo ok-tidak-ada
for i in $(seq 1 12); do curl -s -o /dev/null -w "%{http_code} " -X POST https://<domain>/api/v1/auth/login -d '{"email":"x","password":"y"}'; done; echo
```

**Cek:** login beberapa `401` lalu `429` (tunggu 1 menit sesudahnya).

### 7.3 End-to-end dengan akun uji

1. App (build rilis, §9) → daftar akun uji → admin menyetujui.
2. App mendaftarkan perangkat → **sertifikat terbit otomatis** (konsol
   Perangkat: `issued`).
3. Tanda tangani PDF uji → pindai QR dengan HP biasa → `https://<domain>/v/...`
   tanpa peringatan, valid.
4. Unggah PDF di halaman verifikasi → valid.
5. Admin → Utilitas → cabut sertifikat uji → pesan *CRL baru sudah
   diterbitkan* → verifikasi ulang → **tidak valid, dicabut**.
6. `docker compose restart api` → CRL tetap nomor yang sama, PDF uji tetap
   dicabut, kartu CA penerbit tetap **Aktif**.
7. Nonaktifkan / hapus akun uji.

### 7.4 Backup dan restore drill

Setelah §8.1 terpasang, uji restore ke PostgreSQL sementara — data yang
berjalan tidak disentuh:

```sh
R="restic -r /var/backups/pqsign/repo --password-file /root/.config/pqsign-backup/restic-password"
DUMP=/var/backups/pqsign/staging/pqsign-db.dump
$R snapshots
$R restore latest --target /tmp/pqsign-restore --include $DUMP
docker run -d --name pqsign-cek -e POSTGRES_PASSWORD=cek postgres:17-alpine
docker cp /tmp/pqsign-restore$DUMP pqsign-cek:/db.dump
docker exec pqsign-cek sh -c 'until pg_isready -U postgres; do sleep 1; done; sleep 2; createdb -U postgres pqc && pg_restore -U postgres -d pqc --no-owner /db.dump'
docker exec pqsign-cek psql -U postgres -d pqc -Atc "select count(*) from accounts" -c "select count(*) from signatures"
docker compose exec -T postgres psql -U pqc -d pqc -Atc "select count(*) from accounts" -c "select count(*) from signatures"
$R restore latest --target /tmp/pqsign-restore --include /var/lib/docker/volumes/pqsign_cadata/_data
find /tmp/pqsign-restore -name 'key.pem*'
docker rm -f pqsign-cek && rm -rf /tmp/pqsign-restore
```

**Cek:** jumlah akun dan tanda tangan hasil restore sama dengan yang berjalan;
arsip CA hanya berisi `intermediate/key.pem.enc` (dan `retired/*/key.pem.enc`
setelah rotasi) — **tidak** ada `root/key.pem*`. Ulangi uji ini **sebulan
sekali** dan catat hasilnya.

---

## 8. Operasional rutin

### 8.1 Backup harian

**Model:** backup **lokal** di server ini, sekali sehari 02:30 UTC, dengan
restic (terenkripsi, inkremental): dump database, volume PDF (`objdata`) dan
volume CA (`cadata`). Masa simpan **7 harian + 4 mingguan + 6 bulanan** (satu
snapshot terakhir per hari/minggu/bulan). Laporan tampil untuk super admin di
**Admin → Backup data**; banner muncul bila backup gagal atau lebih dari 72
jam tidak berhasil (`PQC_BACKUP_MAX_AGE_HOURS`). Backup **tidak** bisa diunduh
dari konsol: pengambilan lewat SSH, dan tombol **Petunjuk tarik database**
menampilkan perintahnya dengan path server ini.

Pasang (sekali, sebelum atau sesudah §5):

```sh
apt-get install -y restic python3
install -d -m 700 /root/.config/pqsign-backup
(umask 077; openssl rand -base64 33 > /root/.config/pqsign-backup/restic-password)
install -m 600 /opt/pqsign/tools/backup/pqsign-backup.env.example /etc/pqsign-backup.env   # cek nama container/volume
install -m 755 /opt/pqsign/tools/backup/pqsign-backup.sh /usr/local/sbin/pqsign-backup
install -m 644 /opt/pqsign/tools/backup/pqsign-backup.cron /etc/cron.d/pqsign-backup
install -m 644 /opt/pqsign/tools/backup/pqsign-backup.logrotate /etc/logrotate.d/pqsign-backup
install -d -m 755 /var/backups/pqsign/status
/usr/local/sbin/pqsign-backup
docker compose up -d api        # memuat laporan backup (mount read-only)
```

⛔ STOP — **salin `/root/.config/pqsign-backup/restic-password` ke lokasi
aman di luar server** (mis. brankas digital instansi), terpisah dari salinan
`secrets/ca_intermediate_passphrase`. Tanpa file ini backup tidak bisa dibuka.
Backup berisi hash password, secret TOTP admin, riwayat CRL, dan kunci
Intermediate terenkripsi.

**Cek:** `tail -3 /var/log/pqsign-backup.log` → `backup ok`; konsol super admin
→ Backup data → **Normal**. Lalu uji restore §7.4.

**Batasan yang diterima untuk tahap ini:** backup berada di disk yang sama
dengan data. Ia melindungi dari salah hapus, update gagal, dan data rusak —
**tidak** dari disk rusak, server disusupi, atau server hilang. Tahap
berikutnya (§9): salinan di luar server.

**Mengambil database:** ikuti **Petunjuk tarik database** di konsol. Memulihkan
ke server yang berjalan **menimpa semua data** (akun, tanda tangan, audit):
hanya dengan persetujuan penanggung jawab, dan buat backup baru dulu.

### 8.2 Sertifikat perangkat

Terbit otomatis saat pengguna yang sudah disetujui mendaftarkan perangkat.
Bila gagal, konsol Perangkat menampilkan tombol **Terbitkan ulang**. Masa
berlaku mengikuti `PQC_CA_DEVICE_CERT_DAYS` (default 365) dan tidak pernah
melewati masa berlaku Intermediate.

**Perpanjangan otomatis:** setiap jam server menerbitkan ulang sertifikat yang
berakhir dalam `PQC_CA_RENEW_DAYS` (default 30) hari — dari CSR yang tersimpan
saat pendaftaran, untuk **kunci perangkat yang sama**, tanpa tindakan
pengguna. Sertifikat lama tidak dicabut dan tetap berlaku sampai habis. App
memeriksa sertifikat ke server sehari sekali dan saat sisa < 30 hari, lalu
memakai yang baru. Setiap perpanjangan tercatat di audit `certificate.renew`.
Akun nonaktif atau perangkat yang dilaporkan hilang tidak diperpanjang.

Dokumen yang sudah ditandatangani **tetap valid setelah sertifikatnya
kedaluwarsa**: verifikasi memakai waktu server menerima dokumen
(`validation_time_source: server_received_at`).

### 8.3 CRL

Otomatis (setiap pencabutan + setiap 24 jam, berlaku 7 hari). Konsol
**Utilitas** menampilkan **BASI** bila penerbitan otomatis berhenti — cek
`docker compose logs api | grep -i crl` dan audit `crl.publish` gagal.

### 8.4 Pemantauan

- Uptime `https://<domain>/api/v1/public/ca/root.crt` (200).
- Sertifikat TLS (Caddy memperbarui otomatis; alert < 14 hari).
- **Banner di konsol admin** (sumber: `GET /api/v1/admin/capabilities` →
  `notices`): Root < 5/2/1 tahun, Intermediate hampir habis atau rotasi
  menunggu Root, CA penerbit menunggu Intermediate, CRL basi. Level
  `critical` → tindak hari itu juga.
- Disk `pgdata`, `objdata`, `cadata`; CPU container `api` (SF-1).
- `GET /api/v1/admin/capabilities` → `crl.stale` harus `false`.
- Audit log: lonjakan login/MFA gagal, `certificate.issue` di luar kebiasaan,
  `certificate.renew` gagal, `ca.rotation.start`, `ca.intermediate.install`,
  `ca.intermediate.rotate`.
- Laporan backup di konsol super admin (**Admin → Backup data**) dan
  `/var/log/pqsign-backup.log`.

### 8.5 Update aplikasi

```sh
sudo /usr/local/sbin/pqsign-backup          # backup dulu
cd /opt/pqsign && git fetch --tags && git checkout <tag-baru>
cd deploy/production && docker compose build api && docker compose up -d api
docker compose logs --tail=50 api
```

Ulangi §7.1–7.2.

### 8.6 Sesi Root berikutnya (hanya saat diperlukan) ⛔ STOP

Untuk menandatangani Intermediate baru (rotasi §8.8), sesi Root memakai arsip
dari USB, dengan pengaman yang sama seperti §3.3–§3.5 (swap mati, saksi, run
sheet). Siapkan dulu:

```sh
install -d -m 755 -o 10001 -g 10001 /opt/pqsign-ceremony/in /opt/pqsign-ceremony/out
mount -o ro /dev/<usb-a-partisi> /media/ca-usb-a
swapoff -a
```

Lalu:

```sh
read -rs ROOTPASS && echo
printf '%s' "$ROOTPASS" | docker run --rm -i --network none --read-only \
  --tmpfs /work:rw,size=64m,mode=0700,uid=10001,gid=10001 \
  --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 \
  -v /media/ca-usb-a:/usb:ro -v /opt/pqsign-ceremony/in:/in:ro -v /opt/pqsign-ceremony/out:/out \
  --entrypoint sh pqsign-api:local -c '
set -eu; umask 077
cat > /work/.pass
export PQC_CA_ROOT_PASSPHRASE_FILE=/work/.pass
tar -C /work -xzf /usb/root-ca-offline.tar.gz
ca-admin sign-intermediate --dir /work/root --csr /in/intermediate.csr.pem \
  --inter-cn "<nama>" --out /out/intermediate.crt.pem
rm -f /work/.pass'
unset ROOTPASS
```

Sesudahnya: `umount /media/ca-usb-a && swapon -a`.

Catatan: `intermediates.jsonl` di arsip USB **tidak** ikut diperbarui dengan
cara ini; catat tanda tangan baru di run sheet.

### 8.7 Insiden

| Kejadian | Tindakan |
|---|---|
| Admin kehilangan HP | Kode pemulihan; atau superadmin → Reset MFA |
| Superadmin kehilangan HP + semua kode | `docker compose exec postgres psql -U pqc -d pqc -c "DELETE FROM admin_mfa WHERE account_id=(SELECT id FROM accounts WHERE role='superadmin')"` → login ulang, pasang MFA baru |
| HP/laptop pengguna hilang | Cabut sertifikatnya (CRL otomatis) |
| API restart terus | `docker compose logs api | tail -20`; pesan pengaman §5.4 → ⛔ STOP |
| Server disusupi | ⛔ STOP. Anggap **Intermediate bocor**: simpan bukti, pulihkan server bersih, lalu **Mulai rotasi Intermediate sekarang** (§8.8) — sertifikat semua perangkat diterbitkan ulang dari Intermediate baru. Root belum bisa mencabut Intermediate lama (§9): pantau audit `certificate.issue` sampai rotasi selesai |
| Root diduga bocor | ⛔ STOP. Ceremony penuh baru, build ulang app, semua perangkat daftar ulang |
| Database rusak | Restore dari backup terbaru |
| Versi baru bermasalah | `git checkout <tag-sebelumnya>` → build + `up -d api` (migrasi tidak di-rollback otomatis) |

### 8.8 Rotasi Intermediate (semi-otomatis)

**Kapan:** `PQC_CA_ROTATE_DAYS` (default 730) hari sebelum Intermediate
berakhir, server otomatis membuat kunci + CSR Intermediate berikutnya
(audit `ca.rotation.start`), dan konsol admin/super admin menampilkan banner
*Rotasi disiapkan*. Bisa dimulai lebih awal (mis. insiden): super admin →
kartu **CA penerbit** → **Mulai rotasi Intermediate sekarang**. Selama
menunggu, Intermediate aktif tetap bekerja seperti biasa.

**Langkah manusia (sekali, ±30 menit, dengan saksi) ⛔ STOP:**

1. Ambil CSR di server:
   ```sh
   docker compose exec -T api cat /ca/next/request.csr.pem > /opt/pqsign-ceremony/in/intermediate.csr.pem
   docker compose exec -T api ca-admin status --dir /ca | grep '^next'
   ```
   (atau super admin → **Unduh CSR Intermediate**). Catat SHA-256 CSR.
2. Sesi Root §8.6 dengan `--inter-cn "<Instansi> PQC Device Signing CA <tahun>"`.
   Catat `csr key fp` dan fingerprint Intermediate baru di run sheet.
3. Salin `/opt/pqsign-ceremony/out/intermediate.crt.pem` ke laptop super
   admin (`scp`), lalu super admin → kartu **CA penerbit** → pilih file →
   **Pasang sertifikat** → pesan *Rotasi selesai*.

**Yang terjadi otomatis sesudahnya:**

| Hal | Hasil |
|---|---|
| Akun, password, MFA | Tidak berubah |
| Kunci di perangkat pengguna | Tidak berubah, **tidak perlu daftar ulang** |
| Sertifikat perangkat | Diterbitkan ulang dari Intermediate baru dalam ≤ 1 jam (audit `certificate.renew`); app mengambilnya dalam ≤ 24 jam |
| Sertifikat lama | **Tidak dicabut**; tetap bisa dipakai sampai habis |
| Dokumen yang sudah ditandatangani | Tetap valid: PDF membawa rantainya, Root sama |
| Intermediate lama | Dipensiunkan: tetap di `chain.pem`, tetap menandatangani CRL untuk sertifikat lamanya; kuncinya dihapus otomatis setelah masa berlakunya habis |
| Mencabut sertifikat lama setelah rotasi | Tetap bisa (CRL bundel) |

**Cek:**

```sh
docker compose exec -T api ca-admin status --dir /ca | grep -E '^intermediate|^retired|^next|gate'
curl -s https://<domain>/api/v1/public/ca/chain.pem | grep -c 'BEGIN CERTIFICATE'   # 3
curl -s https://<domain>/api/v1/public/ca/crl.pem | grep -c 'BEGIN X509 CRL'        # 2
```

Dalam 1–2 jam audit berisi `certificate.renew ok` untuk tiap perangkat aktif.
`certificate.renew fail` → ⛔ STOP. Banner rotasi hilang dari konsol.

### 8.9 Rotasi Root (manual, rencana) ⛔ STOP

Root berlaku 20 tahun. Banner: < 5 tahun *info*, < 2 tahun *peringatan*,
< 1 tahun *kritis*. Rotasi Root **tidak otomatis**, butuh pekerjaan kode dan
rilis aplikasi, jadi dimulai **±tahun ke-15**:

1. **Pekerjaan kode** (§9): server dan app menerima **bundel Root lama + baru**
   sebagai jangkar kepercayaan, dan `install-intermediate --rotate` menerima
   Intermediate dari Root baru.
2. **Rilis app** yang mem-pin kedua Root; tunggu pengguna memperbarui.
3. **Ceremony Root baru** (§3.3–§3.5), nama baru, dua USB baru, penerimaan
   risiko baru.
4. **Rotasi Intermediate** (§8.8) dengan CSR ditandatangani **Root baru**;
   sertifikat perangkat diterbitkan ulang otomatis, kunci perangkat tetap.
5. **Transisi:** dokumen lama tetap diverifikasi dengan Root lama (tetap di
   bundel verifikasi); dokumen baru dengan Root baru.
6. Setelah semua Intermediate di bawah Root lama berakhir: Root lama tetap di
   bundel verifikasi untuk dokumen lama; USB Root lama tetap di brankas atau
   dimusnahkan dengan berita acara.

---

## 9. Yang BELUM selesai di kode (cek sebelum go-live) ⛔ STOP

| Item | Wajib sebelum | Keterangan |
|---|---|---|
| **App Android: `insecure_tls` default `true`** | Rilis app | Default `false`, opsi hanya di build debug |
| **App Windows: opsi `InsecureSkipVerify`** | Rilis app | Hapus dari build rilis |
| Alamat server default app `http://136.244.116.132:8099` | Rilis app | Ganti ke `https://<domain>` |
| Build rilis Android/EXE bertanda tangan | Rilis app | `docs/release-checklist.md` |
| App Android: pembaruan sertifikat otomatis diuji di perangkat | Rilis app | Kode Kotlin belum dikompilasi di server ini (tanpa Android SDK); uji: sertifikat baru terambil tanpa daftar ulang |
| **Banyak Root sekaligus** (rotasi Root) | ±tahun ke-15 (§8.9) | Server (`PQC_ROOT_CA_PEM`, pengecekan rantai issuer), `install-intermediate --rotate`, dan app masih mengasumsikan satu Root |
| Pencabutan Intermediate oleh Root (CRL Root) | Insiden | Belum ada `ca-admin` untuk CRL tingkat Root |
| Rate limit `auth/register` | Disarankan | Belum ada |
| Pencabutan token sesi | Disarankan | Token berlaku 15 menit |
| Reset / ganti password user biasa | Disarankan | Belum ada |
| SF-1 parser PDF (loop CPU) | Diterima dengan mitigasi | Batas memori/CPU + timeout |
| Salinan backup di luar server | Disarankan secepatnya | Backup §8.1 masih lokal (disk yang sama); tambah pull dari kantor atau fitur backup penyedia server |

## Dilarang di produksi

- Menyetel `PQC_CA_ROOT_PASSPHRASE` / `PQC_CA_ROOT_PASSPHRASE_FILE` di server
  atau `.env` (API menolak start).
- Menyimpan arsip Root (`root-ca-offline.tar.gz`) atau `root/key.pem*` di disk
  server, di `pki/`, atau di backup server.
- Menjalankan sesi Root dengan jaringan aktif, tanpa `--read-only` / tmpfs,
  atau tanpa saksi.
- Menyetel `PQC_DEV_LAB_CA_ADMIN`, `PQC_DEV_LAB_CA_DIR`,
  `PQC_ADMIN_MFA_DISABLED`, atau `PQC_RATE_LIMIT_DISABLED`.
- Menjalankan `deploy/local/seed.sh` atau `tools/dev-admin.sh`.
- Menambahkan `ports:` ke `api` atau `postgres`.
- Memakai CA, database, secret, atau password dari server lab.
- `docker compose down -v` (menghapus database, PDF, **dan kunci Intermediate**).
- Menyimpan file kata sandi backup (`/root/.config/pqsign-backup/restic-password`)
  **hanya** di server.
- Menambahkan endpoint atau cara untuk mengunduh backup lewat konsol web.
- Mengganti `PQC_DOMAIN` setelah dokumen pertama ditandatangani.
