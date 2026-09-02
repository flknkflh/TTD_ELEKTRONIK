package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ObjectStore holds the signed PDF blobs. Keys are server-generated
// (Rencana V1 §19), never derived from a user file name.
type ObjectStore interface {
	PutObject(key string, data []byte) error
	GetObject(key string) ([]byte, error)
}

// --- DB-backed (objects table); the default when no S3 is configured ---

type dbObjects struct{ db *sql.DB }

func (o dbObjects) PutObject(key string, data []byte) error {
	_, err := o.db.Exec(
		`INSERT INTO objects(key,data) VALUES($1,$2)
		 ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data`, key, data)
	return err
}

func (o dbObjects) GetObject(key string) ([]byte, error) {
	var b []byte
	err := o.db.QueryRow(`SELECT data FROM objects WHERE key=$1`, key).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return b, err
}

// --- MinIO / S3 ---

// S3Config configures an S3-compatible object store (MinIO in the lab, §22).
type S3Config struct {
	Endpoint  string // host:port, no scheme
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool
}

type s3Objects struct {
	client *minio.Client
	bucket string
}

// NewS3Objects connects to the endpoint and ensures the bucket exists.
func NewS3Objects(cfg S3Config) (ObjectStore, error) {
	cl, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("store: minio client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ok, err := cl.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("store: minio reachability: %w", err)
	}
	if !ok {
		if err := cl.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, fmt.Errorf("store: create bucket %q: %w", cfg.Bucket, err)
		}
	}
	return s3Objects{client: cl, bucket: cfg.Bucket}, nil
}

func (o s3Objects) PutObject(key string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := o.client.PutObject(ctx, o.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/pdf"})
	return err
}

func (o s3Objects) GetObject(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	obj, err := o.client.GetObject(ctx, o.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	b, err := io.ReadAll(obj)
	if err != nil {
		return nil, ErrNotFound
	}
	return b, nil
}
