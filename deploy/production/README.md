# deploy/production (M9 / post-V1)

Lab → production server move (§28). **Follow [RUNBOOK.md](RUNBOOK.md)** step
by step; it uses the files in this folder (`docker-compose.yml`, `Dockerfile`,
`Caddyfile`, `.env.example`) and the local backup in `tools/backup/`.

**Moved:** source/build recipe, API image, Caddy config, DB migrations, Root +
Intermediate **public** certs, public CRL, production config (no secrets in Git).

**Not moved:** any private key (Root, Intermediate, user/device), lab DB
password, lab JWT/TOTP secrets, lab TLS key, Android debug key, lab CA or any
certificate it issued.

Procedure (details in the runbook): decisions → verified release commit →
harden the server → offline PKI ceremony → DNS → deploy Caddy/API/Postgres →
super admin + MFA + first CRL → verification checklist (TLS 1.3 hybrid,
ports, rate limit, end-to-end sign/verify/revoke) → backup + restore drill →
routine operations (weekly CRL, offline issuance, monitoring).
