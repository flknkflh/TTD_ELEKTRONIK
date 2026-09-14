# Production image for the receiver API (deploy/production/RUNBOOK.md).
#
# Differences from deploy/local: no ca-admin inside (certificates are issued on
# the offline CA machine, never on this server), no entrypoint that creates a
# CA, and the process runs as an unprivileged user. Build context is the repo
# root: server/go.mod replaces the core module with ../core.

FROM golang:1.27 AS build
WORKDIR /src
COPY core/ ./core/
COPY server/ ./server/
WORKDIR /src/server
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM alpine:3.20
# tzdata: the stamp caption prints the server date in Asia/Jakarta.
# /objects is created here, owned by the app user, so the named volume mounted
# on it inherits that ownership on first use.
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 pqc \
 && mkdir -p /objects/_incoming /pki \
 && chown -R pqc:pqc /objects
COPY --from=build /out/api /usr/local/bin/api
USER pqc
EXPOSE 8099 8098
ENTRYPOINT ["/usr/local/bin/api"]
