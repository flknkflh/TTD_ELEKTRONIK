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
✔ GET  /api/v1/admin/enrollments
✔ POST /api/v1/admin/enrollments/{id}/certificate   (chain + CSR-key match check)
✔ POST /api/v1/admin/certificates/{id}/revoke
✔ POST /api/v1/admin/crl/import
✔ GET  /api/v1/admin/audit-events
```

Slice 2 remainder: `auth/refresh`, `auth/logout`,
`admin/enrollments/{id}/approve`, `admin/enrollments/{id}/export`.

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
PUT  /api/v1/signatures/{public_id}/document
GET  /api/v1/signatures/{public_id}
GET  /api/v1/signatures/{public_id}/download
GET  /api/v1/me/signatures
```

## Public verification
```
POST /api/v1/verify
GET  /api/v1/public/signatures/{public_id}
GET  /api/v1/public/ca/root.crt
GET  /api/v1/public/ca/chain.pem
GET  /api/v1/public/ca/crl.pem
```

## Admin
```
GET  /api/v1/admin/enrollments
POST /api/v1/admin/enrollments/{id}/approve
GET  /api/v1/admin/enrollments/{id}/export
POST /api/v1/admin/enrollments/{id}/certificate
POST /api/v1/admin/certificates/{id}/revoke
POST /api/v1/admin/crl/import
GET  /api/v1/admin/audit-events
```

## Forbidden

There must be no `POST /api/v1/sign` and no `POST /api/v1/users/{id}/sign`
(§17.5).

## Shared verification result

`POST /api/v1/verify` and the local verifiers all return the JSON produced by
`core/verification` (`verification.Result`) — see §11.3 / §16.2. The server
adds `registered`, `signer_name`, `device_label`, `certificate_status`,
`server_received_at`.
