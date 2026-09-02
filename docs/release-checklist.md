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
  asserts there is no signing endpoint. **Slice 2**: PostgreSQL + MinIO +
  Docker Compose, MFA/TOTP, refresh-token revocation, rate limiting.
* Next: M6 slice 2, then M3 hardening (parser fuzzing).

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
