# Local prototype (Docker, persistent)

One `docker compose` stack: **PostgreSQL + the receiver API**. All data lives
in named volumes, so rebuilding the image does **not** wipe accounts,
certificates or signatures.

```sh
cd deploy/local
docker compose up -d --build      # first run also builds the CA
bash seed.sh                      # create admin@local + user@local (once per fresh volume)
```

- Admin console: <http://localhost:8099/admin> — `admin@local` / `admin12345`
- App (Windows / Android): server `http://localhost:8099`, `user@local` / `user12345`

### Persistence

| Command | Data |
|---|---|
| `docker compose up -d --build` | **kept** (image rebuilt, volumes reused) |
| `docker compose restart` / `down` then `up` | **kept** |
| `docker compose down -v` | **deleted** — fresh CA + empty database |

Volumes: `pqc-pdf-sign-local_pgdata` (database), `pqc-pdf-sign-local_cadata` (CA keys + ledger).

### Phones on your Wi-Fi

QR codes and the app must reach the machine by its LAN IP:

```sh
PQC_PUBLIC_BASE_URL=http://192.168.x.x:8099 docker compose up -d --build
```

Then use `http://192.168.x.x:8099` as the server URL in the app.

### What this configuration does

- No MFA. Rate limiting is off. Single-box prototype.
- The CA runs **inside** the container and issues device certificates
  automatically on first enrolment (no manual step).
- Signed-PDF blobs are stored in the database (`objects` table); no MinIO.
