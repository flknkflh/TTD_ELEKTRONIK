# Change spec: tamper detection via ByteRange coverage + stored-hash matching

Status: **implemented**. No database migration, no new environment variable.

## 0. The hole this closes

A signed PDF whose barcode was added *after* signing — appended as an
incremental update, bytes glued on behind the signed `/ByteRange` — still came
back **SAH** from `POST /api/v1/verify`. Three things lined up:

1. `digitorus/pdfsign` hashes only the spans `/ByteRange` names. Appended
   bytes are outside them, so the ML-DSA signature really does still verify —
   the crypto is not lying, it is answering a narrower question than the user
   is asking.
2. That library's own incremental-update detection only fires for a
   **certification** (DocMDP) signature. Ours are approval signatures
   (`ETSI.CAdES.detached`), which carry no `/Reference`, so the check is
   skipped.
3. `core/verification` never asked "does the signature cover the *whole*
   file?".

The same gap is the classic PDF *shadow attack*: sign a document, then append
an overlay that changes what a reader displays.

## 1. Two layers

| Layer | Where | Needs network | Catches |
|---|---|---|---|
| **A. `/ByteRange` coverage** | `core/verification` (server, exe, apk) | no | anything appended after the signed span |
| **B. stored-hash match** | server verify handlers | yes | any byte difference at all, including layer A's blind spot |

Layer A is structural and offline, so it protects local verification in the
clients too. Layer B is authoritative but only exists for documents the server
has a record of.

### Layer A — coverage check

`signedRangeEnd(pdf)` scans for the **last** `/ByteRange [a b c d]` by file
position (for incremental-update multi-signing that is the outermost
signature, the one covering the most) and returns `c + d`. `tailIsBenign`
then requires everything past that offset to be whitespace plus at most one
trailing `%%EOF` — which is exactly what a genuine signer leaves. Anything
else marks the result, and every signature in it, invalid:

```
dokumen diubah setelah ditandatangani (incremental update di luar tanda tangan)
```

Scanning for the array rather than parsing for it is deliberate: `/ByteRange`
sits outside the `/Contents` hex string and a signer cannot compress the
dictionary naming its own signed span, so it is cleartext in the realistic
case and the check stays parser-independent.

**Limit, stated plainly.** If an incremental update is written with a
cross-reference *stream* and its signature dictionary lives inside a
compressed object stream, the array is not cleartext and the scan misses it.
Ordinary tools that append a barcode or annotation keep it in the clear.
Layer B closes the remainder.

Because everything funnels through `VerifyPDF`, this applies at once to
`POST /api/v1/verify`, to `strictVerify` at submission time (a tampered
document is refused with 422), and to offline verification in both clients.

### Layer B — stored-hash match

The server already records `signatures.signed_pdf_sha512` for **both** tiers
at submit time, so no schema change was needed.

`hPublicVerify` now compares the uploaded document's digest against that
record and reports two new top-level fields:

```jsonc
{
  "verification": { ... },
  "registered": true,
  "hash_match": false,                 // NEW — null/absent when no record
  "uploaded_sha512": "…128 hex…"       // NEW
}
```

When the record is `accepted` (the server re-verified it at submission) and
the hash differs, `verification.valid` is forced to `false` with:

```
berkas berbeda dari yang diterbitkan server untuk ID ini (sidik jari SHA-512 tidak cocok)
```

For the `stored_unverified` tier the server never checked the signature
itself, so a mismatch is *reported* (`hash_match: false`, and the UI says the
bytes differ from the stored copy) but does not by itself flip the
cryptographic verdict.

The digest is reused from `Result.DocumentSHA512`, which `VerifyPDF` already
computed — a document may be up to 350 MB and hashing it twice is wasteful.

## 2. New endpoint — hash-only verification

For confidential documents (and for files too large to push through the
verifier): send the digest, never the document.

```
POST /api/v1/public/verify-hash
Content-Type: application/json

{ "public_id": "sig_…", "sha512": "<128 hex chars>" }
```

```jsonc
// 200
{
  "match": true,
  "public_id": "sig_…",
  "verification_status": "accepted",   // or "stored_unverified"
  "record": { … }                      // publicRecord shape; ONLY when match
}
// 400 { "error": "sha512 must be 128 hex characters" }
// 400 { "error": "public_id and sha512 required" }
// 404 { "error": "no such record" }
```

Hex comparison is case-insensitive. A non-matching hash deliberately returns
no `record`, so the endpoint cannot be used to read a record without already
holding the file.

This discloses nothing new — the public QR record already publishes
`signed_pdf_sha512`. It turns "read the hash and compare it yourself" into one
call. It is rate-limited on the same `rlVerify`/`byIP` bucket as
`POST /api/v1/verify`, and registered on **both** muxes: the full API
(`api.go`) and the standalone verification service (`verifyservice.go`).

**What a match proves.** That the bytes are the ones the server issued for
that id — not, on its own, that the signature verifies. For an `accepted`
record the server already verified the signature at submission, so the two
together are the whole story. For `stored_unverified` they are not, and both
clients and the web page say so.

## 3. Clients

Both clients hash locally and send only the digest:

- Desktop: `apiclient.VerifyHash` → `appcore.VerifyByHash(serverURL,
  publicID, path)` → Wails binding `VerifyByHash`; UI under **Verifikasi
  dokumen** → "Atau verifikasi tanpa mengunggah".
- Android: `ApiClient.verifyHash` → `AppCore.verifyByHash(serverUrl,
  publicId, uri)`; UI card "Verifikasi tanpa unggah" on the verify screen.
- Both also render `hash_match` in the ordinary upload-verify verdict.

Layer A reaches the clients through `core/verification` with no client code
change — they only need a rebuild.

## 4. QR landing page `/v/{id}`

The page gained a "Verifikasi tanpa mengunggah berkas" block: the browser
reads the chosen file, computes SHA-512 with `crypto.subtle`, and posts only
the digest.

**Secure-context caveat.** `crypto.subtle` exists only in a secure context —
HTTPS, or `localhost`. On a plain-HTTP LAN/VPS address it is `undefined`, so
the page checks `window.isSecureContext` and, when false, hides the block and
shows a note pointing at the desktop/Android apps, which have no such
restriction. Serving the site over HTTPS enables it in the browser too.

## 5. Tests

Core (`core/verification/verify_test.go`):
`TestVerify_AcceptsUntouchedPDF` (control), `TestVerify_RejectsAppendedBytes`,
`TestVerify_RejectsAppendedIncrementalUpdate`,
`TestVerify_AcceptsTrailingWhitespace`.

Server (`server/internal/api/hashverify_test.go`):
`TestPublicVerify_HashMatchOnGenuineFile`,
`TestPublicVerify_HashMismatchRejected`, `TestVerifyHashEndpoint`,
`TestStrictVerify_RejectsAppendedBytes`.

`TestPublicVerify_HashMismatchRejected` is the one worth understanding: it
appends a single newline. That keeps the ML-DSA signature valid over its own
`/ByteRange` **and** keeps layer A happy (whitespace is benign), so only the
stored-hash comparison can catch it. It is the test that proves layer B is
load-bearing rather than decorative.

Desktop (`appcore_windows_test.go`, Windows-only): hash-only match, mismatch
returns no record, empty id refused. Android (`ApiClientTest.kt`):
`verifyHash_posts_public_id_and_digest_only` asserts the request body carries
only the id and digest.

## 6. Deploy

No migration, no new env var:

```bash
cd /opt/pqc && git pull && cd deploy/local && docker compose up -d --build
```
