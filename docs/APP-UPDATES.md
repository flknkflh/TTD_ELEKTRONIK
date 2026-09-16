# Pembaruan aplikasi 0.7.2

## Menu Tentang — 0.7.2 (code 9)

Menu **Tentang** tersedia di header Windows dan menu toolbar Android, termasuk
sebelum login. Isinya keterangan aplikasi, versi terpasang, dan panel pembaruan:

1. **Periksa pembaruan** menampilkan loading, lalu status terbaru atau versi baru
   beserta catatan perubahan dan ukuran unduhan.
2. **Unduh pembaruan** menampilkan progress bar dan persentase, dilanjutkan
   pemeriksaan integritas. Kegagalan ditampilkan dengan opsi mencoba lagi.
3. Setelah berhasil, muncul **Instal pembaruan**. Download tidak lagi langsung
   memulai instalasi. Windows meminta konfirmasi sebelum menutup aplikasi;
   Android membuka pemasang sistem setelah izin dan verifikasi ulang.

Status tetap tersedia saat menu Tentang ditutup dan dibuka kembali dalam sesi
aplikasi yang sama. Setelah proses aplikasi dihentikan/restart, periksa dan
unduh ulang bila diperlukan. Pada Android, membuka izin pemasangan lalu kembali
ke sesi yang sama tidak memerlukan unduhan ulang: tekan Instal pembaruan.

Unduhan terbaru:
- https://136.244.116.132/updates/PQC-PDF-Sign-windows-0.7.2.exe
- https://136.244.116.132/updates/PQC-PDF-Sign-android-debug-0.7.2.apk

Kanal android-debug kini diterbitkan untuk pengguna APK **new-key 0.7.1**;
sertifikatnya sama (`8df181...48e9ea`). APK ini tetap tidak dapat menimpa APK
0.6.0 lama dalam ZIP (`339717...999e01`). Jangan uninstall aplikasi lama untuk
mengatasi perbedaan kunci.

Validasi rilis: build Windows/Android berhasil; test Go updater/apiclient dan
16 unit test Android lulus. Test UI desktop dengan native bridge tiruan mencakup
versi terbaru, offline, update tersedia, downloading, ready, reopen, dan instal
eksplisit. Test downloader memeriksa progress monoton 0–100 dan integritas file.
Instalasi native pada perangkat pengguna belum diuji dalam lingkungan VPS.

Test UI: `tools/test-update-ui.cjs` menggunakan jsdom 26, dengan repo dipasang
sebagai /src. Status rilis sebelumnya di bawah dipertahankan sebagai riwayat.

## Rilis terbaru (14 September 2026)

- Windows: versi 0.7.1, code 8, tersedia melalui kanal update dan
  https://136.244.116.132/updates/PQC-PDF-Sign-windows-0.7.1.exe.
- Android: versi 0.7.1, code 8, dibangun dengan keystore yang diunggah pengguna.
  Sertifikat keystore ini **berbeda** dari kedua APK debug 0.6.0 dalam ZIP.
  APK ini tidak dipublikasikan ke manifest android-debug sebagai update lama.
  Berkas unduhan diberi akhiran `new-key` untuk membedakannya.
- Fingerprint kunci yang diunggah:
  `8df181736f8805b472f7540375b7dac0c795b15bac99f90ee7f8b4214748e9ea`.
- Fingerprint yang diperlukan untuk menimpa APK lama dalam ZIP:
  `3397174ab8daec662258c9b00d0c3a59ea4bac17ec12711c6c3d9b693c999e01`.
- Jangan uninstall aplikasi lama untuk mengatasi konflik sertifikat. Cari
  keystore dari lingkungan build APK lama, lalu build ulang dan bandingkan
  fingerprint sebelum menerbitkan kanal Android.

Bagian berikut mencatat implementasi awal updater 0.7.0.

Source Android dan Windows diimpor dari TTD_ELEKTRONIK.zip milik pengguna.
Salinan ekstraksi untuk pembanding ada di import-review/ (diabaikan Git).
Tampilan Liquid Glass, parser DN, dan perbaikan klien dalam ZIP dipertahankan.

## Penggunaan

- Windows: tombol **Periksa pembaruan** di samping versi aplikasi.
- Android: menu toolbar **Periksa pembaruan (v0.7.0)**.
- Pengguna mengonfirmasi unduhan/pemasangan. Tidak ada pemasangan diam-diam.
- Versi 0.6.0 belum memiliki updater: pasang 0.7.0 secara manual sekali dahulu.
- Simpan pekerjaan sebelum update Windows karena aplikasi akan ditutup.

Windows 0.7.0 tersedia di:
https://136.244.116.132/updates/PQC-PDF-Sign-windows-0.7.0.exe

Untuk pemasangan pertama, tutup EXE lama dan gunakan EXE baru. Vault tetap di
%LOCALAPPDATA%/PQC-PDF-Sign; jangan hapus folder tersebut. EXE portable perlu berada
di folder yang dapat ditulis pengguna (misalnya Documents/PQC-PDF-Sign).
Folder Program Files yang tidak dapat ditulis akan ditolak sebelum aplikasi
ditutup. Build ini belum diberi tanda tangan Authenticode.

## Android: kunci pemasangan lama

ZIP berisi APK debug dan APK release unsigned, tetapi tidak berisi debug.keystore.
APK debug lama telah diverifikasi dengan apksigner. SHA-256 sertifikatnya:
`3397174ab8daec662258c9b00d0c3a59ea4bac17ec12711c6c3d9b693c999e01`.
Build release 0.7.0 berhasil, hasilnya di
apps/android/app/build/outputs/apk/release/app-release-unsigned.apk.
Ini BUKAN berkas untuk dipasang/dipublikasikan.

Untuk memperbarui APK debug lama tanpa menghapus data, gunakan debug.keystore
yang sama dari komputer pembuat APK (biasanya C:/Users/LENOVO/.android/debug.keystore).
Simpan keystore di lokasi privat, bukan release-files. Build dengan:

```sh
PQC_ANDROID_DEBUG_KEYSTORE=/path/to/original/debug.keystore bash gradlew :app:assembleDebug
```

Bandingkan sertifikat APK lama dan baru menggunakan `apksigner verify --print-certs`
sebelum publikasi. Package ID debug tetap `id.example.pqcsign.debug`, release tetap
`id.example.pqcsign`. Jangan menghapus aplikasi lama untuk mengatasi mismatch:
penghapusan dapat menghilangkan kunci perangkat Android Keystore.

Setelah cocok, pengguna memasang APK 0.7.0 sekali; update berikutnya tersedia di
menu aplikasi. Android meminta izin pemasangan dari aplikasi ini, kemudian
konfirmasi pemasangan. Setelah memberikan izin, periksa pembaruan kembali.

## Menerbitkan versi berikutnya

1. Naikkan versionCode dan versionName Android; naikkan VersionCode/Version di
   apps/windows/internal/updater/update.go serta versi frontend dan wails.json.
2. Build dan uji APK/EXE. APK harus ditandatangani dengan keystore kanal yang sama.
3. Jalankan dari VPS, misalnya:

```sh
bash tools/publish-app-update.sh windows 0.8.0 10 /path/to/app.exe 'Catatan perubahan'
bash tools/publish-app-update.sh android-debug 0.8.0 10 /path/to/app-debug.apk 'Catatan perubahan'
```

Kanal release Android memakai `android`, terpisah dari `android-debug`.
Script menolak nomor versi yang tidak naik dan nama artefak yang sudah ada;
salinan artefak dan manifest dipublikasikan dengan rename. Jangan mengedit
artefak versi yang telah diterbitkan. Tidak perlu rebuild/restart server untuk
menerbitkan versi baru: direktori release-files dipasang read-only pada API.

Manifest `/updates/windows.json`, `/updates/android.json`, atau
`/updates/android-debug.json` berisi platform, version, version_code, path,
size, sha256, notes. Belum ada rilis menghasilkan 404 yang ditangani klien.

## Integritas dan perilaku kegagalan

Updater memakai origin HTTPS tetap https://136.244.116.132, validasi TLS normal,
tanpa token login, tanpa mengikuti redirect. Hanya path berkas dalam /updates/
yang diterima. Manifest dibatasi 64 KiB, artefak 256 MiB; ukuran dan SHA-256 harus
cocok sebelum pemasangan. Kepercayaan manifest bergantung pada HTTPS dan
pengamanan server rilis; manifest belum memakai tanda tangan terpisah.

Android juga memeriksa package ID, versionCode, dan sertifikat penandatangan APK.
Windows memakai helper salinan EXE lama, menunggu proses induk selesai, memeriksa
ulang hash, lalu mengganti EXE dan menjalankannya kembali. Salinan sebelumnya
disimpan sebagai `<nama-exe>.previous`. Jika pemindahan/peluncuran gagal, helper
mencoba mengembalikan EXE lama. Galat helper dicatat di direktori staging
%TEMP%/pqsign-update-*/update-error.txt. Ini bukan rollback otomatis untuk crash
aplikasi baru setelah berhasil diluncurkan.

## QR dan HTTPS

Default dan alamat tersimpan IP:8098/8099 dimigrasikan ke HTTPS. Server membentuk
QR baru sebagai https://136.244.116.132/v/<public_id>; header Host atau parameter
base dari klien tidak dapat mengganti origin produksi. Halaman verifikasi juga
memigrasikan alamat lama pada localStorage. Kamera browser diizinkan untuk
origin sendiri; tetap memerlukan izin pengguna dan dukungan pemindai browser.

QR dalam PDF lama tidak diedit (akan merusak tanda tangan). QR lama yang menunjuk
port HTTP yang sudah ditutup dapat dibaca melalui pemindai di aplikasi baru,
yang mengambil ID dan memeriksanya pada server HTTPS yang dipilih.

## Validasi

- Go: pengujian paket API/auth serta updater/apiclient lulus.
- Updater: path berbahaya, downgrade, ukuran berlebih, checksum salah, unduhan
  terpotong/berlebih ditolak dalam unit test.
- QR: origin HTTPS tetap dipakai walaupun request mencoba mengganti origin.
- Android: assembleRelease dan testDebugUnitTest lulus di JDK17/SDK36.
- Windows: cross-build windows/amd64 berhasil; belum diuji menjalankan GUI atau
  mengganti EXE pada perangkat Windows nyata.
- Endpoint manifest dan EXE publik merespons 200; hash unduhan HTTPS cocok.
- Pemasangan/update Android pada perangkat nyata menunggu keystore yang sesuai.
