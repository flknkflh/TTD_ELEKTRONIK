// Command api runs the PQC PDF Sign V1 receiver server (Rencana V1 §17, §22).
//
// It accepts already-signed PDFs, re-verifies them strictly against the
// configured Root CA, stores metadata + the object, and serves the public
// verifier. It has NO endpoint that signs a PDF for a user (§1, §17.5).
//
// Backend selection:
//   - PQC_DATABASE_URL set  -> PostgreSQL (schema auto-applied)
//   - PQC_S3_ENDPOINT set   -> signed PDFs go to MinIO/S3, else the DB
//   - neither               -> in-memory (dev / tests)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

func main() {
	addr := flag.String("addr", envOr("PQC_ADDR", ":8080"), "listen address")
	rootPath := flag.String("root-ca", os.Getenv("PQC_ROOT_CA_PEM"), "Root CA PEM file (required)")
	chainPath := flag.String("ca-chain", os.Getenv("PQC_CA_CHAIN_PEM"), "Root+Intermediate chain PEM file")
	crlPath := flag.String("crl", os.Getenv("PQC_CRL_PEM"), "current CRL PEM file")
	baseURL := flag.String("public-base-url", envOr("PQC_PUBLIC_BASE_URL", "http://localhost:8443"), "public verifier base URL")
	flag.Parse()

	if *rootPath == "" {
		log.Fatal("api: -root-ca (or PQC_ROOT_CA_PEM) is required")
	}
	secret := []byte(os.Getenv("PQC_JWT_SECRET"))
	if len(secret) < 16 {
		log.Fatal("api: PQC_JWT_SECRET must be set to at least 16 bytes")
	}

	cfg := api.Config{JWTSecret: secret, PublicBaseURL: *baseURL, AccessTTL: 15 * time.Minute}
	if boolEnv("PQC_RATE_LIMIT_DISABLED") {
		cfg.RateLimits = &api.RateLimits{} // dev / scripted runs only
	}
	var err error
	if cfg.RootCAPEM, err = os.ReadFile(*rootPath); err != nil {
		log.Fatalf("api: read root CA: %v", err)
	}
	if *chainPath != "" {
		if cfg.CAChainPEM, err = os.ReadFile(*chainPath); err != nil {
			log.Fatalf("api: read CA chain: %v", err)
		}
	}
	if *crlPath != "" {
		if cfg.CRLPEM, err = os.ReadFile(*crlPath); err != nil {
			log.Fatalf("api: read CRL: %v", err)
		}
	}

	st, backend, err := openStore()
	if err != nil {
		log.Fatalf("api: store: %v", err)
	}

	srv, err := api.New(st, cfg)
	if err != nil {
		log.Fatalf("api: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		fmt.Printf("pqc-pdf-sign receiver API listening on %s (store: %s)\n", *addr, backend)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("api: serve: %v", err)
		}
	}()
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
}

func openStore() (api.Store, string, error) {
	dsn := os.Getenv("PQC_DATABASE_URL")
	if dsn == "" {
		return store.NewMemory(), "in-memory", nil
	}
	var objs store.ObjectStore
	if ep := os.Getenv("PQC_S3_ENDPOINT"); ep != "" {
		var err error
		objs, err = store.NewS3Objects(store.S3Config{
			Endpoint:  ep,
			Region:    envOr("PQC_S3_REGION", "us-east-1"),
			Bucket:    envOr("PQC_S3_BUCKET", "pqc-pdf-sign"),
			AccessKey: os.Getenv("PQC_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("PQC_S3_SECRET_KEY"),
			UseSSL:    boolEnv("PQC_S3_USE_SSL"),
		})
		if err != nil {
			return nil, "", err
		}
	}
	pg, err := store.OpenPostgres(dsn, objs)
	if err != nil {
		return nil, "", err
	}
	if objs != nil {
		return pg, "postgres + s3", nil
	}
	return pg, "postgres", nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func boolEnv(k string) bool {
	b, _ := strconv.ParseBool(os.Getenv(k))
	return b
}
