# PKI ceremony (production — M7)

Lab PKI is generated in-process by `core/labpki` and by `pqcsign-cli genpki`.
That code is **not** for production. The production Root and Intermediate keys
are created once, offline, with OpenSSL 3.5.x, following the checklist below
(Rencana V1 §13, §28).

## Prerequisites

* Air-gapped machine, fresh OS, no network.
* OpenSSL 3.5.x with ML-DSA:
  ```sh
  openssl list -signature-algorithms | grep -i mldsa
  ```
* Two witnesses, a ceremony script, and an offline log.

## Root CA (§13.2)

```sh
umask 077

openssl genpkey -algorithm ML-DSA-65 -aes-256-cbc -out root-ca.key.pem

openssl req -new -x509 -key root-ca.key.pem -days 3650 \
  -subj "/C=ID/O=ORGANISASI/OU=PQC Root CA/CN=PQC PDF Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out root-ca.crt.pem
```

Record SHA-256 of `root-ca.crt.pem`. The private key never leaves the
encrypted offline medium; make at least one separate backup. Only
`root-ca.crt.pem` is distributed.

## Intermediate Device Signing CA (§13.3)

`CA:TRUE, pathlen:0`, `keyUsage=keyCertSign,cRLSign`. Signs device certs and
CRLs. Its private key does **not** go on the public server; approved CSRs are
exported from the server, signed offline, and the resulting certs uploaded.

## Device certificate profile (§13.4)

* subject assigned from the verified account (ignore CSR subject)
* random/controlled unique serial
* ML-DSA-65 public key
* `basicConstraints=critical,CA:FALSE`
* `keyUsage=critical,digitalSignature`
* EKU `1.3.6.1.5.5.7.3.36` (id-kp-documentSigning) — required by the verifier
* AKI + SKI
* CRL Distribution Point if the verifier updates online
* no excess personal data (the cert is embedded in every signed PDF)

## Before "production ready"

Witness document, output checksums, serial-number policy, backup + recovery
procedure, and a rehearsed revocation + rotation drill.
