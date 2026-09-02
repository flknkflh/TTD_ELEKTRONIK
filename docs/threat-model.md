# Threat model (summary)

Full text: Rencana V1 §5, §24, §26, §29. This is the working checklist.

## Guarantees targeted (§5.1)

* Server compromise does not yield user private keys.
* The server cannot forge a user signature (it has no key, no signing endpoint).
* Every signature traces to account + device + certificate + PDF.
* A PDF altered after signing fails verification.
* A lost device is revoked without disabling the user's other devices.

## Limits (§5.2)

* Malware on the device can attempt to use/steal the key while the app has it in memory.
* Rooted Android / admin Windows raises local-attack risk.
* Without a TSA, the client-written signing time has no independent proof.
* A QR on paper only opens the server record; it does not attest the whole page.
* A private Root CA is not automatically trusted by general PDF readers.

## Invariants enforced in code (§5.3)

| Invariant | Where |
|---|---|
| No private key in logs / requests / DB / images | `core` never logs key bytes; server rejects PKCS#8 uploads (M6) |
| Trust only the configured Root CA | `verification.VerifyPDF` requires `RootPEM`; `TrustSelfSigned` never set in prod path |
| Root inside the PDF is not an anchor | uses `digitorus/pdfsign` `TrustedRoots` only |
| One key per device | key generated on-device; no import path |
| Identity from account, not CSR subject | `enrollment.ParseAndValidateCSR` returns subject as info only; `labpki.IssueDeviceCert` takes subject from caller |
| PQC-only profile | `RequireMLDSAOnly` rejects non-ML-DSA signers |

## Negative tests (§25.4, §26)

Covered by `core/spike` today: tampered PDF rejected, wrong Root CA rejected,
CSR with broken signature rejected, non-ML-DSA key rejected.

Pending (M6+): revoked cert rejected for new signatures, account/device
mismatch rejected, reserve/submit replay rejected, path-traversal on upload,
CRL-cache-stale warning surfaced to the user.
