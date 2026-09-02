# apps/windows

Two binaries share the client logic:

| binary | what |
|---|---|
| `cmd/pqcsign-cli` | M1 headless spike (lab PKI, sign, verify) — see below |
| `cmd/pqcsign-desktop` | **M4 GUI client** (Wails v2). Windows-only. |

## Client architecture (M4)

```
cmd/pqcsign-desktop   Wails shell + frontend/ (HTML), binds App -> appcore
internal/appcore      the seven §20 pages as plain Go, GUI-independent, tested
internal/apiclient    typed client for the §17 receiver endpoints
internal/keystore     DPAPI key protection (§12.1) — Windows-only + a stub
```

### Key protection (`internal/keystore`, §12.1)

```
ML-DSA-65 PKCS#8
  -> AES-256-GCM (fresh nonce)             encrypted key blob
random 32-byte wrapping key
  -> AES-256-GCM with Argon2id(PIN)        (only when a PIN is set)
  -> Windows DPAPI CryptProtectData, CurrentUser scope + app entropy
device-key.pqk   (under %LOCALAPPDATA%\PQC-PDF-Sign\)
```

The plaintext key exists only for a single sign/CSR call and is zeroed after.
Every write uses a fresh wrapping key + nonces. `keystore_windows_test.go`
covers round-trip, tamper rejection, wrong-PIN, and a corrupted/foreign DPAPI
blob failing to open (§26).

### End-to-end (`appcore_windows_test.go`)

Login → on-device keygen + DPAPI wrap → enrollment → offline cert issuance →
certificate status active (matched to the on-device key) → sign (local verify
then submit) → verify → history → wrong-PIN rejected → reset wipes the vault.
Runs against a fake receiver that checks submissions with the real
`core/verification`.

## Build the GUI (`cmd/pqcsign-desktop`)

Needs a JDK-free but Node-capable box: Go 1.27, the Wails CLI, and WebView2
(pre-installed on Windows 11).

```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0
cd apps/windows/cmd/pqcsign-desktop
wails dev        # hot-reload dev shell
wails build -platform windows/amd64 -clean   # -> build/bin/PQC-PDF-Sign.exe
```

The frontend is plain HTML in `frontend/dist/` (no build step) — one page per
§20 screen, each button calling a bound `App` method. Polishing the UI is a
later slice; the logic under it is done and tested.

Release artifacts (M9): `PQC-PDF-Sign-V1-Setup-x64.exe`,
`PQC-PDF-Sign-V1-Portable-x64.zip`, `SHA256SUMS.txt`; Authenticode signing
when a cert is available (separate from the user's ML-DSA key).

## M1 CLI spike (unchanged)

```sh
go build -o ../../dist/pqcsign-cli.exe ./cmd/pqcsign-cli
../../dist/pqcsign-cli.exe spike --out ../../dist/spike-out
```
