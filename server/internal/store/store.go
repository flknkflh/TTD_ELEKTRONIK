// Package store holds the receiver server's persistence types and an
// in-memory implementation (Rencana V1 §18). A PostgreSQL implementation of
// the same method set lands in M6 slice 2; keep all SQL out of the rest of
// the server so that swap is mechanical.
package store

import (
	"errors"
	"time"
)

// ErrNotFound is returned by every lookup that finds nothing.
var ErrNotFound = errors.New("store: not found")

// Role values.
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// Device / certificate / reservation status values.
const (
	DeviceActive = "active"
	DeviceLost   = "lost"

	EnrollmentSubmitted = "submitted"
	EnrollmentIssued    = "issued"

	CertActive  = "active"
	CertRevoked = "revoked"

	ReservationReserved = "reserved"
	ReservationAccepted = "accepted"
)

type Account struct {
	ID           string
	Email        string
	DisplayName  string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

type Device struct {
	ID        string
	AccountID string
	Label     string
	Platform  string
	Status    string
	CreatedAt time.Time
}

type Enrollment struct {
	ID        string
	DeviceID  string
	AccountID string
	CSRPEM    []byte
	CSRKeyFP  string // SHA-256 of the CSR public key
	Status    string
	CreatedAt time.Time
}

type Certificate struct {
	ID           string
	EnrollmentID string
	DeviceID     string
	AccountID    string
	Serial       string // hex
	Fingerprint  string // SHA-256 of DER
	PEM          []byte
	NotBefore    time.Time
	NotAfter     time.Time
	Status       string
	RevokedAt    time.Time
	RevReason    string
}

type Reservation struct {
	PublicID       string
	AccountID      string
	DeviceID       string
	OriginalSHA512 string
	FileName       string
	Status         string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

type Signature struct {
	PublicID                 string
	AccountID                string
	DeviceID                 string
	CertificateID            string
	CertSerial               string
	CertFingerprint          string
	Algorithm                string
	PDFProfile               string
	OriginalSHA512           string
	SignedSHA512             string
	ClientClaimedSigningTime string
	ServerReceivedAt         time.Time
	StorageObjectKey         string
	SignedSize               int
	VerificationStatus       string
	CreatedAt                time.Time
}

type AuditEvent struct {
	ID        string
	Time      time.Time
	Type      string
	AccountID string
	DeviceID  string
	Result    string
	Detail    string
}
