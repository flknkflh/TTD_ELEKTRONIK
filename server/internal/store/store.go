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

// Role values. RoleSuperAdmin is bootstrapped once (first generate) and is the
// only role that can create/disable RoleAdmin accounts; it otherwise has every
// admin capability. Self-registration only ever yields RoleUser.
const (
	RoleUser       = "user"
	RoleAdmin      = "admin"
	RoleSuperAdmin = "superadmin"
)

// Account status values (Rencana RB-1). A self-registered account starts
// pending; an admin's one-click approval flips it to active, which is what
// authorises automatic certificate issuance. disabled cascades to every
// device certificate the account holds.
const (
	AccountPending  = "pending"
	AccountActive   = "active"
	AccountDisabled = "disabled"
)

// Device / certificate / reservation status values.
const (
	DeviceActive = "active"
	DeviceLost   = "lost"

	EnrollmentSubmitted = "submitted"
	EnrollmentApproved  = "approved"
	EnrollmentIssued    = "issued"

	CertActive  = "active"
	CertRevoked = "revoked"

	ReservationReserved = "reserved"
	ReservationAccepted = "accepted"

	// Signature.VerificationStatus values.
	VerificationAccepted   = "accepted"          // strict re-verify passed on submit
	VerificationStoredOnly = "stored_unverified" // too large to verify server-side; hash recorded, file stored
)

type Account struct {
	ID           string
	Email        string
	DisplayName  string
	FullName     string // legal name (with academic titles), printed on the certificate + QR page
	Organization string // instansi, printed on the certificate + QR page
	Position     string // jabatan, printed in the e-signature caption on stamps
	NIP          string // employee number, printed in the caption ("NIP. ...")
	PasswordHash string
	Role         string
	Status       string // AccountPending | AccountActive | AccountDisabled
	CreatedAt    time.Time
}

// MFACredential is an admin's TOTP authenticator for the admin console. It is
// unconfirmed until the first code from the app checks out.
type MFACredential struct {
	AccountID string
	Secret    string // base32, as given to the authenticator app
	Confirmed bool
	LastStep  int64 // newest accepted TOTP time step; equal or older steps are replays
	CreatedAt time.Time
}

// CRL is one certificate revocation list the server accepted. The newest is
// the active one.
type CRL struct {
	Number     string // CRLNumber, decimal
	ThisUpdate time.Time
	NextUpdate time.Time // zero when the CRL has none
	Entries    int       // revoked serials listed
	PEM        []byte
	Source     string // "import" (admin upload) | "ca" (lab issuer) | "config" (PQC_CRL_PEM)
	ImportedBy string // account id; "" for config
	ImportedAt time.Time
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
	// The letter number and subject typed for this signature at stamp time.
	LetterNo      string
	LetterSubject string
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
