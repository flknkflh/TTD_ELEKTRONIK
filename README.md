# PQC PDF Sign V1 — client-side signing

Post-quantum PDF signing with **ML-DSA-65** (FIPS 204), client-side only. The
private key is generated on the user's device, protected by the OS
(Windows DPAPI / Android Keystore), and **never sent to the server**. The
server receives already-signed PDFs, re-verifies them strictly, stores the
result, and serves a public verifier.

Full plan: `Rencana_Pembuatan_PQC_PDF_Sign_V1_Client_Side.md` (section numbers
below refer to it).

## Status

This repository currently contains **M0 baseline + the M1 cross-platform
spike** (§10, §31, §32):

| Component | State |
|---|---|
| `core/` Go library — keygen, CSR, sign, verify, CRL | implemented, tested |
| `apps/windows/` `pqcsign-cli` — M1 desktop spike | implemented, builds `.exe`, spike PASSES on windows/amd64 |
| `core/mobilebridge/` + `apps/android/build-aar.sh` | AAR builds (arm64, API 29); on-device run still pending |
| `apps/android/` app | on-device spike (debug APK) + Kotlin wrapper; full app = M5 |
| `tools/ca-admin/` | offline CA operator CLI (init/validate/issue/revoke/crl/show), tested — M2 done, HSM/encryption = M7 |
| `server/` Receiver API | all §17 core routes, strict submit verification, public verifier; runs on in-memory **or PostgreSQL** (`api_test.go` passes against real PG16) + MinIO blobs; MFA/rate-limit = slice 2 remainder |
| `deploy/lab/` | Docker Compose (caddy+api+postgres+minio), multi-stage Dockerfile, Caddyfile — `compose config` validated |
| `pki/` | lab scripts + templates; production ceremony = M7 |

## Crypto profile (§4)

* Signature: ML-DSA-65, CMS pure mode (RFC 9882)
* Digest: SHA-512
* PDF: PAdES Baseline-B (`PAdES_B`)
* Trust: explicit Root CA only — a root embedded in a PDF is never an anchor (§5.3)
* Timestamp: not in V1 (client-claimed time is shown but not trusted)

## Layout

```
core/            framework-independent Go: keys, enrollment, signing, verification, mobilebridge
  keys/          ML-DSA-65 generation + PKCS#8 (de)serialisation
  enrollment/    device CSR creation + server-side CSR validation
  signing/       PAdES-B ML-DSA-65 signing + visible appearance + QR
  verification/  verify against explicit Root CA (+ offline CRL); shared JSON result (§11.3)
  certutil/      X.509 / CRL parsing and profile checks
  labpki/        LAB-ONLY throwaway Root/Intermediate CA + device cert + CRL
  spike/         the M1 end-to-end proof, callable from any platform
apps/windows/    Wails desktop client (UI = M4); today: pqcsign-cli spike
apps/android/    Kotlin/Compose client + Go AAR (M5)
server/          Receiver API — internal/{store,auth,api}; strict submit verify + public verifier
tools/ca-admin/  offline CA operator CLI: init / validate / issue / revoke / crl / show
pki/             CA templates, scripts, published public material
deploy/          lab (Compose) and production recipes
docs/            architecture, api, pki-ceremony, threat-model, release-checklist
research/        notes only — reference repos are cloned here, never vendored
```

## Quick start (M1 spike)

Requires Go 1.27.

```sh
# from repo root
cd apps/windows
go build -o ../../dist/pqcsign-cli.exe ./cmd/pqcsign-cli

cd ../..
./dist/pqcsign-cli.exe spike --out dist/spike-out
```

The spike builds a lab ML-DSA-65 PKI, enrolls a device, signs the bundled
sample PDF, verifies it against the explicit Root CA, and proves that a
tampered PDF and an unrelated Root CA are both rejected. Artifacts and
`report.json` (timings, sizes, memory) land in `dist/spike-out/`.

Other subcommands: `genpki`, `keygen`, `pubkey`, `csr`, `sign`, `verify`,
`version` — run `pqcsign-cli <cmd> -h`.

```sh
# sign an arbitrary PDF with lab material, then verify it standalone
./dist/pqcsign-cli.exe genpki --out dist/lab-pki
./dist/pqcsign-cli.exe sign   --in mydoc.pdf --key dist/lab-pki/device-key.pkcs8.pem \
                              --chain dist/lab-pki/ca-chain.pem --out mydoc.signed.pdf \
                              --signer "Nama Pengguna" --public-id sig_demo --qr
./dist/pqcsign-cli.exe verify --in mydoc.signed.pdf --root dist/lab-pki/root-ca.crt.pem \
                              --intermediate dist/lab-pki/intermediate-ca.crt.pem \
                              --crl dist/lab-pki/crl.pem
```

## Tests

```sh
cd core && go test ./...
```

`core/spike` runs the automated M1 acceptance checks (§25.3–§25.5).

## Licensing (§3, §9.3)

Built on `github.com/digitorus/pdfsign` (BSD-2-Clause), pinned to the baseline
commit `39f87fec…` / `v1.0.0-rc2`. `digitorus/pdfsigner` (GPLv3) is studied as
a reference only and is **not** a dependency. See
`LICENSES/THIRD_PARTY_NOTICES.md`.

Module paths use the `example.internal/` placeholder — replace with the real
organisation domain before any release.

## Security invariants (§5.3)

* No private key in source, logs, DB, HTTP requests, telemetry, crash reports, or images.
* The server has **no** endpoint that signs a PDF on a user's behalf.
* One key per device; never copied between devices.
* All trust decisions use the configured Root CA, not a root carried in the PDF.
* Certificate identity comes from the verified account, not from the CSR subject.
