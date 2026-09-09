# Receiver API (M6)

Endpoint list from Rencana V1 §17. **M6 slice 1 is implemented** in
`server/internal/api` on an in-memory store (`✔` below); the rest lands in
slice 2 (PostgreSQL/MinIO/Docker, MFA/TOTP, refresh-token revocation, rate
limiting).

Implemented (`server/internal/api`, tested in `api_test.go`):

```
✔ POST /api/v1/auth/register          (lab; real deploys seed admins out of band)
✔ POST /api/v1/auth/login             ({email,password,code?}; code required once MFA is confirmed)
✔ POST /api/v1/auth/mfa/setup         (returns TOTP secret + otpauth:// URL)
✔ POST /api/v1/auth/mfa/verify        ({code} -> confirms the secret)
✔ POST /api/v1/devices
✔ GET  /api/v1/devices
✔ POST /api/v1/devices/{device_id}/csr
✔ GET  /api/v1/devices/{device_id}/certificate
✔ POST /api/v1/devices/{device_id}/report-lost
✔ POST /api/v1/signatures/reserve
✔ PUT  /api/v1/signatures/{public_id}/document      (strict verify, §15.3)
✔ GET  /api/v1/signatures/{public_id}
✔ GET  /api/v1/signatures/{public_id}/download
✔ GET  /api/v1/me/signatures
✔ POST /api/v1/verify                               (public, multipart)
✔ GET  /api/v1/public/signatures/{public_id}
✔ GET  /api/v1/public/ca/root.crt | chain.pem | crl.pem
✔ POST /api/v1/signatures/{public_id}/stamp         (RB-2c: draw a placed QR stamp, returns PDF)
✔ GET  /v/{public_id}/document                      (public: the authoritative signed PDF behind the QR)
✔ GET  /api/v1/admin/enrollments
✔ POST /api/v1/admin/enrollments/{id}/certificate   (chain + CSR-key match check)
✔ POST /api/v1/admin/enrollments/{id}/issue-lab     (RB-1: drive the online CA; when Config.LabIssuer set)
✔ POST /api/v1/admin/certificates/{id}/revoke
✔ POST /api/v1/admin/crl/import
✔ GET  /api/v1/admin/audit-events
✔ GET  /api/v1/admin/capabilities                   ({lab_issuer:bool})
✔ GET  /api/v1/admin/accounts                       (RB-1)
✔ POST /api/v1/admin/accounts/{id}/approve|disable|enable
✔ PATCH  /api/v1/admin/accounts/{id}                ({full_name,organization})
✔ DELETE /api/v1/admin/accounts/{id}                (cascade revoke + CRL; tombstone if it has history)
✔ GET  /admin                                       (static operator console)
```

Slice 2 remainder: `auth/refresh`, `auth/logout`.

## RB business flow (from RB-1..RB-6)

`register` takes `{email,password,full_name,organization}` and creates a
**pending** account; login is refused (`403 {account_status:"pending"}`) until
an admin `POST /admin/accounts/{id}/approve`. Once approved, the first
`POST /devices/{id}/csr` from that account is **auto-issued** by the server's
online CA (`Config.LabIssuer`) — the response carries `status:"issued"` and
`certificate_serial`, no separate admin step. Disabling or deleting an account
revokes every certificate it holds and republishes the CRL. Verification stays
public and needs no account.

**MFA gate (§24)**: `POST /devices/{id}/csr`, `POST /devices/{id}/report-lost`,
and every `admin/*` route require a session that presented a valid TOTP code
at login (`mfa` claim). Others are reachable without MFA.

**Rate limits (§24, per minute)**: `auth/login` 10/IP, `signatures/reserve`
60/account, `signatures/{id}/document` 30/account, `verify` 30/IP. Over the
cap → `429` + `Retry-After`. Configurable via `api.Config.RateLimits`.

## Auth
```
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/mfa/setup
POST /api/v1/auth/mfa/verify
```

## Devices and enrollment
```
POST /api/v1/devices
GET  /api/v1/devices
GET  /api/v1/devices/{device_id}
POST /api/v1/devices/{device_id}/csr
GET  /api/v1/devices/{device_id}/certificate
POST /api/v1/devices/{device_id}/report-lost
```

## Signatures
```
POST /api/v1/signatures/reserve
POST /api/v1/signatures/{public_id}/stamp        (body: application/pdf; ?page=&x=&y=&w=&reason=; x,y = top-left of the QR box as page fractions, w = width fraction. Returns the PDF with one QR stamp drawn at that spot, page count unchanged. 422 if the PDF cannot be processed.)
PUT  /api/v1/signatures/{public_id}/document
GET  /api/v1/signatures/{public_id}
GET  /api/v1/signatures/{public_id}/download
GET  /api/v1/me/signatures
```
Client sign flow: `reserve` → `stamp` (sign the returned bytes on-device) → `document`.

## Public verification
```
GET  /                              (browser upload page — verification-only service only)
POST /api/v1/verify                 (multipart 'file'; no auth)
GET  /v/{public_id}                 (QR landing page)
GET  /v/{public_id}/document        (authoritative signed PDF behind the QR)
GET  /api/v1/public/signatures/{public_id}
GET  /api/v1/public/ca/root.crt
GET  /api/v1/public/ca/chain.pem
GET  /api/v1/public/ca/crl.pem
```

Run `api --verify-addr :8098` (or `PQC_VERIFY_ADDR=:8098`) to also serve a
**verification-only** site on a second port: just the routes above, no
`/auth`, `/signatures`, `/devices`, or `/admin`. Publish it separately from
the signing API when only verification should be reachable.

## Admin
```
GET    /api/v1/admin/capabilities
GET    /api/v1/admin/accounts
POST   /api/v1/admin/accounts/{id}/approve
POST   /api/v1/admin/accounts/{id}/disable       (cascade: revoke all certs + republish CRL)
POST   /api/v1/admin/accounts/{id}/enable
PATCH  /api/v1/admin/accounts/{id}               ({full_name, organization})
DELETE /api/v1/admin/accounts/{id}               (cascade; kept as a disabled tombstone if it has signatures)
GET    /api/v1/admin/enrollments
POST   /api/v1/admin/enrollments/{id}/approve
GET    /api/v1/admin/enrollments/{id}/export
POST   /api/v1/admin/enrollments/{id}/certificate
POST   /api/v1/admin/enrollments/{id}/issue-lab   (only when Config.LabIssuer is set)
POST   /api/v1/admin/certificates/{id}/revoke
POST   /api/v1/admin/crl/import
GET    /api/v1/admin/audit-events
```
All `admin/*` routes require an admin role; all except `capabilities` also
require MFA (or `PQC_MFA_NOT_REQUIRED=1` on a dev receiver).

## Forbidden

There must be no `POST /api/v1/sign` and no `POST /api/v1/users/{id}/sign`
(§17.5).

## Shared verification result

`POST /api/v1/verify` and the local verifiers all return the JSON produced by
`core/verification` (`verification.Result`) — see §11.3 / §16.2. The server
adds `registered`, `signer_name`, `device_label`, `certificate_status`,
`server_received_at`.
