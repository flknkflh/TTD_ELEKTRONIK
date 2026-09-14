# Production image for the receiver API (deploy/production/RUNBOOK.md).
#
# Differences from deploy/local: no entrypoint that creates a CA, and the
# process runs as an unprivileged user. ca-admin is included for the online
# issuer of the split CA (Intermediate key in the /ca volume) and for the
# ephemeral Root ceremony container — the Root key is never written to this
# image or its volumes. Build context is the repo root.

FROM golang:1.27 AS build
WORKDIR /src
COPY core/ ./core/
COPY server/ ./server/
COPY tools/ca-admin/ ./tools/ca-admin/
WORKDIR /src/server
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api
WORKDIR /src/tools/ca-admin
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ca-admin .

FROM alpine:3.20
# tzdata: the stamp caption prints the server date in Asia/Jakarta.
# /objects is created here, owned by the app user, so the named volume mounted
# on it inherits that ownership on first use.
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 pqc \
 && mkdir -p /objects/_incoming /pki /ca \
 && chown -R pqc:pqc /objects /ca
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/ca-admin /usr/local/bin/ca-admin
USER pqc
EXPOSE 8099 8098
ENTRYPOINT ["/usr/local/bin/api"]
