# apps/android

Kotlin client. The signing/verification engine is the Go `core` compiled to an
AAR through gomobile (`core/mobilebridge`). Today this module is the **M1
on-device spike** — a one-screen debug app that proves the AAR runs ML-DSA-65
sign + verify on a real arm64 phone.

## 1. Build the AAR (§10.2)

```sh
export ANDROID_HOME=~/AppData/Local/Android/Sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.1.12297006
./apps/android/build-aar.sh          # -> apps/android/app/libs/pqcsign.aar
```

Pinned tool versions: `build-aar.sh` and `docs/toolchain.md`. The AAR is a
build output and is git-ignored.

## 2. Build the debug APK

The Gradle wrapper is committed — no local Gradle/Android Studio install
needed, only a JDK 17 and the Android SDK (platform 36, build-tools 36).

```sh
cd apps/android
echo "sdk.dir=/absolute/path/to/Android/Sdk" > local.properties   # forward slashes!
export JAVA_HOME=/path/to/jdk-17
./gradlew :app:assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk   (~19 MB, arm64-v8a only)
```

Or open `apps/android/` in Android Studio and Run.

**No local toolchain?** Push the branch — CI job `aar` builds the APK and
uploads it as artifact `pqc-pdf-sign-android-debug-apk` (Actions → the run →
Artifacts).

## Connect the app to a local server

On the PC:

```sh
bash tools/dev-up.sh          # builds + starts the receiver on 0.0.0.0:8099
```

It prints the LAN URL to type into the app (`Masuk` → `Server URL`). The
**debug** APK allows plain HTTP to the LAN; the release APK is HTTPS-only (use
Caddy). If the printed IP is a virtual adapter, run `ipconfig` and use your
Wi-Fi IPv4 instead. `dev-up.sh` starts the receiver with the online lab CA
issuer and `PQC_MFA_NOT_REQUIRED=1`.

Then, in another shell, provision the accounts:

```sh
bash tools/dev-admin.sh http://127.0.0.1:8099
# -> admin@local / admin12345  (the /admin console)
# -> user@local  / user12345   (the app; already approved)
```

RB flow: in the app, `Masuk` with `user@local` / `user12345`. The app then
**silently** generates the key, submits the CSR, and the server **auto-issues**
the certificate — no manual enrolment screen, no admin click. Then `Tanda
Tangani Dokumen` → pick a PDF → **drag the QR box onto the signature column and
size it** → `Tanda tangani di sini`. The server draws one "TTD Elektronik" QR
stamp at that spot before signing (page count unchanged); scanning it opens the
verification page, which also shows the authoritative signed PDF. The `/admin`
console's **Akun pengguna** tab is where an admin approves new
self-registrations and disables/deletes accounts.

## 3. Test on a phone

1. Copy `app-debug.apk` to an arm64 Android phone (Android 10 / API 29+).
2. Allow "install from unknown sources", install, open **PQC PDF Sign Spike**.
3. Tap **Jalankan spike**. It:
   - generates an ML-DSA-65 key **on the device** (shows size + time),
   - builds a CSR from that key,
   - signs the bundled `sample.pdf` and `sample-multipage.pdf` with the lab
     fixture key/chain,
   - verifies against the **embedded Root CA**,
   - confirms a tampered PDF and a wrong Root CA are both rejected,
   - prints the shared verification JSON and per-step timings.
4. Tap **Simpan signed.pdf**, pull the file to a PC, and cross-verify (§25.5):
   ```sh
   pqcsign-cli verify --in signed-android.pdf \
     --root  apps/android/app/src/main/assets/lab/root-ca.crt.pem \
     --intermediate apps/android/app/src/main/assets/lab/intermediate-ca.crt.pem \
     --crl   apps/android/app/src/main/assets/lab/crl.pem
   ```

### Fixtures

`app/src/main/assets/lab/` holds a **throwaway lab PKI**, including
`device-test-key.pem` — a test private key that exists only in this debug APK.
Real device keys are generated on-device and wrapped by the Android Keystore
(§12.2); that is M5. `AndroidManifest.xml` disables backup and there is no
`INTERNET` permission — the spike is fully offline.

### Still pending for full M1 sign-off (§25.1)

Capture logcat + network traffic during a run and confirm no key material
appears. Needs `adb` (or an on-device capture tool).

## Bridge surface (`core/mobilebridge`, §10.2)

```
GenerateKey() ([]byte, error)                                             // PKCS#8 DER
ExportPublicKey(privateKeyPKCS8 []byte) ([]byte, error)
CreateCSR(privateKeyPKCS8 []byte, requestJSON string) ([]byte, error)     // CSR PEM
SignPDF(pdf, privateKeyPKCS8, certChainPEM []byte, optionsJSON string) ([]byte, error)
VerifyPDF(pdf, rootPEM, crlPEM []byte) (string, error)                    // shared JSON
```

Kotlin wrapper: `app/src/main/java/id/example/pqcsign/core/SigningEngine.kt`.

## Full app (M5)

Pages (§21.1): Login, Register device, Certificate status, Pick PDF,
Biometric/PIN confirm, Sign, Verify PDF, Scan QR, History, Report problem.
Key wrapping: AES key in Android Keystore (auth-gated), ML-DSA PKCS#8
encrypted with it in internal storage, excluded from Auto Backup (§12.2).
