# Release checklist

## Milestones (§23) and gate criteria

| ID | Deliverable | Passes when |
|---|---|---|
| M0 | Baseline + licences | `pdfsign` baseline tests pass; dependency lock committed; third-party notices written; GPL `pdfsigner` marked reference-only |
| M1 | ML-DSA spike cross-platform | one PDF signs + verifies on Windows amd64 **and** Android arm64; timings/size/memory recorded; corrupt PDF rejected |
| M2 | PKI lab | Root→Intermediate→device verifies; revoked cert rejected per policy |
| M3 | Core library | no UI deps; all golden + fuzz tests pass |
| M4 | Windows client | uninstall/reinstall, key loss, re-enrollment recovery all behave per policy; DPAPI wrapping verified |
| M5 | Android client | no key in logcat/network capture; sign+verify on ≥2 API levels |
| M6 | Receiver API | rejects corrupt PDF, wrong cert, revoked cert, user/device mismatch, transaction-id mismatch |
| M7 | CA admin + revocation | public server holds no Root/Intermediate private key |
| M8 | End-to-end | all §25 acceptance tests pass |
| M9 | Packaging + release | `.exe` + installer + `.apk` + server image from pipeline; SBOM + SHA256SUMS; backup/restore drill; tag `v1.0.0-lab` then `v1.0.0` |

## Current state

* **M0** done.
* **M1** done: `pqcsign-cli spike` green on Windows; debug APK runs the same
  spike on a physical arm64 device (keygen-on-device + sign + verify + tamper
  / wrong-root rejection). Left for full sign-off: a logcat/network capture
  proving no key leakage (§25.1).
* **M2** done: `tools/ca-admin` (`init/validate/issue/revoke/crl/show`) with
  the gate test — Root→Intermediate→device chain verifies, a revoked cert is
  rejected via a fresh ML-DSA-65 CRL, CA private keys stay out of any server.
* **M6 slice 1** done: `server/` receiver API — register/login (Argon2id +
  HS256 JWT), device + CSR registry, admin cert issuance (chain + CSR-key
  match), reservation, strict submit verification, public multipart verifier,
  audit log. `api_test.go` covers the §25.4 rejections (tampered PDF, wrong
  device cert, revoked cert, public-id mismatch, cross-account read) and
  asserts there is no signing endpoint.
* **M6 slice 2** done: `store.Postgres` behind an `api.Store` interface with
  embedded, `schema_migrations`-guarded migrations (`0001_init`, `0002_mfa`) —
  the **whole `api_test.go` suite passes against real PostgreSQL 16**.
  `store.NewS3Objects` (MinIO/S3) for signed blobs. **TOTP MFA** (RFC 6238,
  hand-rolled): `auth/mfa/setup` + `auth/mfa/verify`, `code` in login,
  enforced on enrollment / device-loss / all admin routes (§24). **Rate
  limiting** (`golang.org/x/time/rate`) on login / reserve / submit / verify.
  `deploy/lab/` Docker Compose (`compose config` validated), multi-stage
  Dockerfile, Caddyfile. Not run here: `docker compose up` + the API image
  build (this machine can't reach Docker Hub). Left: `auth/refresh` +
  token revocation, `admin/enrollments/{id}/approve|export`, backup/restore
  drill.
* **M3 core hardening** done: Go native fuzz tests for every
  attacker-controlled parser (`keys.ParsePKCS8`, `enrollment.ParseAndValidateCSR`,
  `certutil.ParseCertificatePEM`/`ParseChainPEM`/`ValidateCRL`,
  `verification.VerifyPDF`/`ListPDFSignatures`, `signing.SignPDF`). The stdlib
  `crypto/x509`-backed ones survive millions of execs with no panic (CI fuzzes
  them 20–30 s each). `VerifyPDF`/`SignPDF` gained a size cap (`MaxPDFBytes`
  64 MiB), a `recover` guard, and an `Options.Timeout` (server: 15 s). Fuzzing
  found **SF-1** — a CPU-loop DoS in `github.com/digitorus/pdf` on crafted
  input; mitigated (timeout + rate limits + size cap) and tracked in
  `docs/security-findings.md` with an upstream-report / sandbox TODO. Golden
  test pins the CMS shape (SubFilter, SHA-512, ML-DSA-65). `staticcheck` and
  `govulncheck` clean (one transitive advisory, `x/crypto/openpgp`, not
  reachable from our code).
* Next: M4/M5 client UIs.

## Per-release (M9)

* [ ] Windows build on a Windows runner; Authenticode signed if key available
* [ ] Android release APK signed with the release keystore
* [ ] Server multi-stage image; DB migrations from empty
* [ ] SBOM generated; `SHA256SUMS.txt` generated; artifacts signed
* [ ] Dependency + container + secret scans clean
* [ ] User + admin guides updated
* [ ] Backup/restore drill: PostgreSQL + MinIO restored, PDF hashes match
* [ ] All §25 acceptance boxes signed off by the test team
* [ ] CA / release / Authenticode keys are in CI secret storage, not the repo
