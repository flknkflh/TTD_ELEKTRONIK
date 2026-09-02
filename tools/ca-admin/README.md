# tools/ca-admin

Offline CA operator for PQC PDF Sign V1 (Rencana V1 §13, §14, §17.5). Runs on
the air-gapped admin machine — never on a server. This is the **lab**
implementation (M2 / M7 foundation): CA private keys are stored unencrypted
under the CA directory. The production ceremony is `docs/pki-ceremony.md`.

```sh
cd tools/ca-admin && go build -o ../../dist/ca-admin.exe .

ca-admin init     --dir ./ca
ca-admin validate --csr device.csr.pem
ca-admin issue    --dir ./ca --csr device.csr.pem \
                  --account acct_42 --device "Windows Laptop" \
                  --cn "Nama Pengguna" --org "Instansi X" --out device.crt.pem
ca-admin revoke   --dir ./ca --serial <hex-from-issue> --reason keyCompromise
ca-admin crl      --dir ./ca
ca-admin show     --in ./ca/public/crl.pem
```

## CA directory layout

```
ca/
  root/key.pem  root/cert.pem                 # Root CA (offline)
  intermediate/key.pem  intermediate/cert.pem # signs device certs + CRLs
  public/  root-ca.crt.pem  intermediate-ca.crt.pem  ca-chain.pem  crl.pem
  ledger.json      { crl_number, revocations[] }
  issued.jsonl     one JSON line per issued device certificate
```

Only `public/` is ever copied to a server (§28). `init` refuses to run against
an existing directory.

## Guarantees

* Identity is taken from `--cn` / `--org`, **not** the CSR subject (§13.5).
* `validate` / `issue` enforce CSR proof-of-possession and ML-DSA-65.
* Issued device certs carry `keyUsage=digitalSignature` and the
  id-kp-documentSigning EKU, `CA:FALSE`.
* `crl` re-signs a fresh ML-DSA-65 CRL with a monotonic number covering every
  serial in the ledger.

`castore_test.go` runs the M2 gate: issue → sign a PDF → verify against the
published Root CA → revoke → CRL → the same PDF now verifies as revoked.

## M7 (still to add)

Encrypted CA keys / HSM (PKCS#11), enrollment-package import/export as a
single signed bundle, reason-coded CRL entries, ceremony logging with output
checksums.
