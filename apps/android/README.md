# apps/android (M5)

Kotlin / Jetpack Compose client. The signing/verification engine is the Go
`core` compiled to an AAR through gomobile, from `core/mobilebridge`.

## M1 Android spike (next task, §10.2)

```sh
go install golang.org/x/mobile/cmd/gomobile@<PINNED>   # pin after first success
gomobile init

cd core
gomobile bind -target=android/arm64 \
  -o ../apps/android/app/libs/pqcsign.aar \
  ./mobilebridge
```

`mobilebridge` exposes only `[]byte` / `string` / `error`:

```go
GenerateKey() ([]byte, error)                                             // PKCS#8 DER
ExportPublicKey(privateKeyPKCS8 []byte) ([]byte, error)
CreateCSR(privateKeyPKCS8 []byte, requestJSON string) ([]byte, error)     // CSR PEM
SignPDF(pdf, privateKeyPKCS8, certChainPEM []byte, optionsJSON string) ([]byte, error)
VerifyPDF(pdf, rootPEM, crlPEM []byte) (string, error)                    // shared JSON
```

Pass criteria: AAR imports into Android Studio; keygen + sign + verify succeed
on a real arm64 device; no crash on minimal and multi-page PDFs; time and
memory recorded; **no key material in logcat or network capture**.

If the AAR build fails on a platform API, fix portability in the `pdfsign`
fork first — do not swap the algorithm or hand-roll ML-DSA.

## App (M5)

Pages (§21.1): Login, Register device, Certificate status, Pick PDF,
Biometric/PIN confirm, Sign, Verify PDF, Scan QR, History, Report problem.
Key wrapping: AES key in Android Keystore (auth-gated), ML-DSA PKCS#8
encrypted with it in internal storage, excluded from Auto Backup (§12.2).
