# server/migrations

M6 slice 1 runs on the in-memory `store.Memory`. The PostgreSQL schema +
`golang-migrate`-style `NNNN_name.up.sql` / `.down.sql` files land in slice 2,
covering the tables from Rencana V1 §18.1:

```
users                 user_credentials       mfa_credentials
devices               device_enrollments
certificates          certificate_revocations
signature_reservations
documents             signatures
authentication_events audit_events
```

The `store` package method set is the contract the SQL implementation must
satisfy; keep all SQL behind it.
