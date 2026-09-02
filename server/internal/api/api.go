// Package api is the PQC PDF Sign V1 receiver HTTP server (Rencana V1 §17).
//
// It accepts already-signed PDFs, re-verifies them strictly against the
// configured Root CA, stores metadata + the object, and serves a public
// verifier. There is deliberately NO endpoint that signs a PDF for a user
// (§1, §17.5).
package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Config wires the server. RootCAPEM is the only trust anchor for submissions
// and verification (§5.3).
type Config struct {
	RootCAPEM      []byte
	CAChainPEM     []byte // Root + Intermediate, served at /public/ca/chain.pem
	CRLPEM         []byte // current CRL; replaceable via /admin/crl/import
	JWTSecret      []byte
	PublicBaseURL  string // e.g. https://verify.example.id
	MaxUploadBytes int64  // 0 -> 25 MiB (§24)
	AccessTTL      time.Duration
	Issuer         string // TOTP issuer label; "" -> "PQC PDF Sign"

	// RateLimits are per-minute caps. nil applies sane defaults; pass
	// &RateLimits{} to disable every bucket (tests do this).
	RateLimits *RateLimits
}

// RateLimits — per-minute request caps (Rencana V1 §24). A zero value
// disables that bucket.
type RateLimits struct {
	LoginPerIP        int
	ReservePerAccount int
	SubmitPerAccount  int
	VerifyPerIP       int
}

func defaultRateLimits() RateLimits {
	return RateLimits{LoginPerIP: 10, ReservePerAccount: 60, SubmitPerAccount: 30, VerifyPerIP: 30}
}

// Store is everything the handlers need from persistence. Both
// store.Memory and store.Postgres satisfy it, so the backend is chosen at
// startup and nothing else in the package changes.
type Store interface {
	CreateAccount(store.Account) (store.Account, error)
	AccountByEmail(string) (store.Account, error)
	Account(string) (store.Account, error)

	CreateDevice(store.Device) (store.Device, error)
	Device(string) (store.Device, error)
	SetDeviceStatus(id, status string) error
	DevicesByAccount(string) []store.Device

	CreateEnrollment(store.Enrollment) (store.Enrollment, error)
	Enrollment(string) (store.Enrollment, error)
	ListEnrollments() []store.Enrollment
	SetEnrollmentStatus(id, status string) error

	CreateCertificate(store.Certificate) (store.Certificate, error)
	Certificate(string) (store.Certificate, error)
	CertificateByDevice(string) (store.Certificate, error)
	CertificateBySerial(string) (store.Certificate, error)
	RevokeCertificate(id, reason string) error

	CreateReservation(store.Reservation) (store.Reservation, error)
	Reservation(string) (store.Reservation, error)
	SetReservationStatus(publicID, status string) error

	CreateSignature(store.Signature) (store.Signature, error)
	Signature(string) (store.Signature, error)
	SignaturesByAccount(string) []store.Signature

	UpsertMFA(accountID, secret string) error
	MFA(accountID string) (store.MFACredential, error)
	ConfirmMFA(accountID string) error

	PutObject(key string, data []byte) error
	GetObject(key string) ([]byte, error)

	Append(store.AuditEvent)
	AuditEvents(limit int) []store.AuditEvent
}

type Server struct {
	st     Store
	signer *auth.Signer
	cfg    Config
	crl    []byte // mutable copy of cfg.CRLPEM
	issuer string

	rlLogin, rlReserve, rlSubmit, rlVerify *limiterSet
}

func New(st Store, cfg Config) (*Server, error) {
	if len(cfg.RootCAPEM) == 0 {
		return nil, errors.New("api: RootCAPEM is required")
	}
	if p := x509.NewCertPool(); !p.AppendCertsFromPEM(cfg.RootCAPEM) {
		return nil, errors.New("api: RootCAPEM has no valid certificate")
	}
	if len(cfg.JWTSecret) < 16 {
		return nil, errors.New("api: JWTSecret must be at least 16 bytes")
	}
	if cfg.MaxUploadBytes == 0 {
		cfg.MaxUploadBytes = 25 << 20
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "PQC PDF Sign"
	}
	rl := defaultRateLimits()
	if cfg.RateLimits != nil {
		rl = *cfg.RateLimits
	}
	mk := func(perMin int) *limiterSet {
		if perMin <= 0 {
			return nil
		}
		return newLimiterSet(perMin)
	}
	return &Server{
		st:        st,
		signer:    auth.NewSigner(cfg.JWTSecret, cfg.AccessTTL),
		cfg:       cfg,
		crl:       cfg.CRLPEM,
		issuer:    issuer,
		rlLogin:   mk(rl.LoginPerIP),
		rlReserve: mk(rl.ReservePerAccount),
		rlSubmit:  mk(rl.SubmitPerAccount),
		rlVerify:  mk(rl.VerifyPerIP),
	}, nil
}

// Routes returns the http.Handler for the whole API.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/auth/register", s.hRegister)
	mux.HandleFunc("POST /api/v1/auth/login", s.limit(s.rlLogin, byIP, s.hLogin))
	mux.HandleFunc("POST /api/v1/auth/mfa/setup", s.user(s.hMFASetup))
	mux.HandleFunc("POST /api/v1/auth/mfa/verify", s.user(s.hMFAVerify))

	mux.HandleFunc("POST /api/v1/devices", s.user(s.hCreateDevice))
	mux.HandleFunc("GET /api/v1/devices", s.user(s.hListDevices))
	mux.HandleFunc("POST /api/v1/devices/{device_id}/csr", s.user(s.mfaRequired(s.hSubmitCSR)))
	mux.HandleFunc("GET /api/v1/devices/{device_id}/certificate", s.user(s.hDeviceCertificate))
	mux.HandleFunc("POST /api/v1/devices/{device_id}/report-lost", s.user(s.mfaRequired(s.hReportLost)))

	mux.HandleFunc("POST /api/v1/signatures/reserve", s.user(s.limit(s.rlReserve, byAccount, s.hReserve)))
	mux.HandleFunc("PUT /api/v1/signatures/{public_id}/document", s.user(s.limit(s.rlSubmit, byAccount, s.hSubmitDocument)))
	mux.HandleFunc("GET /api/v1/signatures/{public_id}", s.user(s.hGetSignature))
	mux.HandleFunc("GET /api/v1/signatures/{public_id}/download", s.user(s.hDownload))
	mux.HandleFunc("GET /api/v1/me/signatures", s.user(s.hMySignatures))

	mux.HandleFunc("POST /api/v1/verify", s.limit(s.rlVerify, byIP, s.hPublicVerify))
	mux.HandleFunc("GET /api/v1/public/signatures/{public_id}", s.hPublicRecord)
	mux.HandleFunc("GET /api/v1/public/ca/root.crt", s.pem(func() []byte { return s.cfg.RootCAPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/chain.pem", s.pem(func() []byte { return s.cfg.CAChainPEM }))
	mux.HandleFunc("GET /api/v1/public/ca/crl.pem", s.pem(func() []byte { return s.crl }))

	mux.HandleFunc("GET /api/v1/admin/enrollments", s.admin(s.mfaRequired(s.hListEnrollments)))
	mux.HandleFunc("GET /api/v1/admin/enrollments/{id}/export", s.admin(s.mfaRequired(s.hExportEnrollment)))
	mux.HandleFunc("POST /api/v1/admin/enrollments/{id}/approve", s.admin(s.mfaRequired(s.hApproveEnrollment)))
	mux.HandleFunc("POST /api/v1/admin/enrollments/{id}/certificate", s.admin(s.mfaRequired(s.hIssueCertificate)))
	mux.HandleFunc("POST /api/v1/admin/certificates/{id}/revoke", s.admin(s.mfaRequired(s.hRevoke)))
	mux.HandleFunc("POST /api/v1/admin/crl/import", s.admin(s.mfaRequired(s.hImportCRL)))
	mux.HandleFunc("GET /api/v1/admin/audit-events", s.admin(s.mfaRequired(s.hAudit)))

	return mux
}

// ---- helpers ----

type ctxKey int

const claimsKey ctxKey = 0

func (s *Server) user(h http.HandlerFunc) http.HandlerFunc  { return s.authed(store.RoleUser, h) }
func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc { return s.authed(store.RoleAdmin, h) }

func (s *Server) authed(minRole string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || tok == r.Header.Get("Authorization") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		c, err := s.signer.Parse(tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if minRole == store.RoleAdmin && c.Role != store.RoleAdmin {
			writeErr(w, http.StatusForbidden, "admin only")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), claimsKey, c)))
	}
}

func claims(r *http.Request) auth.Claims {
	c, _ := r.Context().Value(claimsKey).(auth.Claims)
	return c
}

// mfaRequired gates the sensitive actions of Rencana V1 §24 (enrollment,
// device loss reporting, every admin action) behind a session that presented
// a valid TOTP code at login.
func (s *Server) mfaRequired(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !claims(r).Mfa {
			writeErr(w, http.StatusForbidden,
				"this action requires MFA: POST /api/v1/auth/mfa/setup, then log in again with a TOTP code")
			return
		}
		h(w, r)
	}
}

func (s *Server) pem(get func() []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := get()
		if len(b) == 0 {
			writeErr(w, http.StatusNotFound, "not configured")
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(b)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *Server) audit(t string, c auth.Claims, deviceID, result, detail string) {
	s.st.Append(store.AuditEvent{Type: t, AccountID: c.Sub, DeviceID: deviceID, Result: result, Detail: detail})
}

// readBody reads at most max bytes from the request body.
func readBody(r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, max+1))
}

var errTooLarge = errors.New("payload too large")

func withinLimit(b []byte, max int64) error {
	if int64(len(b)) > max {
		return errTooLarge
	}
	return nil
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }
