# tools/ca-admin (M7)

Offline CA operator tooling. Runs on the air-gapped admin machine, never on a
server.

Planned commands (§13, §17.5 admin flow):

* `import-enrollments <package>` — load approved CSRs exported from the server
* `issue <enrollment-id>` — validate CSR, apply the device-cert template, sign with the Intermediate key
* `export-certs <dir>` — bundle issued certs + chain for upload
* `revoke <serial> --reason <r>` — add to the revocation list
* `crl` — issue a fresh CRL signed by the Intermediate key
* `verify-ceremony` — checksum + log the run

Until M7, use `pqcsign-cli genpki` for lab material and `pki/scripts/gen-lab-root-ca.sh`
for the OpenSSL path.
