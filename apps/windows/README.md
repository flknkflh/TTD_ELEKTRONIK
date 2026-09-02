# apps/windows

## Today: `pqcsign-cli` (M1 desktop spike, §10.1 / §32)

```sh
go build -o ../../dist/pqcsign-cli.exe ./cmd/pqcsign-cli
../../dist/pqcsign-cli.exe spike --out ../../dist/spike-out
```

Subcommands: `spike`, `genpki`, `keygen`, `pubkey`, `csr`, `sign`, `verify`,
`version`. The CLI writes private keys **unencrypted** — lab use only.

## M4: Wails client

Pages (§20.1): Login, Register device, Certificate status, Sign PDF, Verify
PDF, History, Security settings.

Key protection (§12.1): ML-DSA PKCS#8 → AES-256-GCM → random wrapping key →
Windows DPAPI `CurrentUser`. Store under `%LOCALAPPDATA%\PQC-PDF-Sign\`. New
GCM nonce on every rewrite; never store the wrapping key in plaintext; no
cloud backup of the key folder.

Build: `wails build -platform windows/amd64 -clean`. Release artifacts:
`PQC-PDF-Sign-V1-Setup-x64.exe`, `PQC-PDF-Sign-V1-Portable-x64.zip`,
`SHA256SUMS.txt`. Authenticode signing is separate from the user's ML-DSA
document-signing key.
