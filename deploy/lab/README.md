# deploy/lab (M6)

Lab server via Docker Compose (§22). Services: `caddy`, `api`, `postgres`,
`minio`. No signing worker, no user-private-key volume.

Planned:

```
deploy/lab/
  docker-compose.yml
  .env.lab.example        # copy to .env.lab, never commit .env.lab
  caddy/Caddyfile
```

Run (once it exists):

```sh
docker compose --env-file deploy/lab/.env.lab -f deploy/lab/docker-compose.yml up -d --build
```

Addresses: `https://localhost:8443`, `/verify`, `/admin`. Postgres and MinIO
are not exposed to `0.0.0.0` — only Caddy accepts client connections. The
HTTPS CA for the lab is separate from the PDF-signing Root CA (§22.2).
