# Receiver API (planned — M6)

The endpoint list below is copied from Rencana V1 §17 and is the contract the
`server/` module will implement. Nothing here is built yet.

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
