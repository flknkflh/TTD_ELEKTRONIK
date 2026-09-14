package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// LabIssuer wires the server to the ca-admin binary so certificate issuance,
// revocation, and CRL publication happen without a human in the loop. In the
// RB-1 model this is the normal path: an admin's one-click account approval is
// the only manual gate, and the device certificate is then issued
// automatically on first enrolment.
//
// Two shapes (issuer.go):
//   - Online (PQC_CA_ISSUER_DIR, production): a split-CA issuer directory. It
//     never holds the Root key; the server creates the Intermediate key + CSR
//     itself and waits until the offline Root's certificate is installed.
//   - lab (PQC_DEV_LAB_CA_ADMIN): a CA made by `ca-admin init` — DEV only.
//
// With Config.LabIssuer nil the CA is fully offline and an admin runs
// ca-admin by hand (docs/pki-ceremony.md).
type LabIssuer struct {
	Bin        string // path to the ca-admin executable
	Dir        string // CA directory (root/ intermediate/ public/)
	Passphrase string // Intermediate key passphrase (may be empty in a lab)
	Operator   string // PQC_CA_OPERATOR label recorded in ceremony.jsonl
	Org        string // default certificate organization when the account has none
	Online     bool   // production split-CA issuer (see above)
	InterCN    string // Intermediate common name for the CSR the server creates (Online)
	CRLURL     string // CRL distribution point written into device certificates
	CertDays   int    // device certificate validity in days; 0 -> 365
}

// run executes ca-admin. The child gets no PQC_CA_* variable from this
// process — in particular never a Root passphrase — only the Intermediate
// passphrase and the operator label.
func (li *LabIssuer) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, li.Bin, args...)
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PQC_CA_") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env,
		"PQC_CA_INTERMEDIATE_PASSPHRASE="+li.Passphrase,
		"PQC_CA_OPERATOR="+firstNonEmpty(li.Operator, "pqc-api"))
	return cmd.CombinedOutput()
}

func (li *LabIssuer) certDays() int {
	if li.CertDays > 0 {
		return li.CertDays
	}
	return 365
}

// issueViaCA runs `ca-admin issue` for an enrollment and returns the leaf
// certificate PEM. Identity is taken from the verified account, never the CSR.
func (s *Server) issueViaCA(ctx context.Context, e store.Enrollment) ([]byte, error) {
	li := s.cfg.LabIssuer
	if !s.issuerReady() {
		return nil, fmt.Errorf("no CA issuer ready")
	}
	acc, _ := s.st.Account(e.AccountID)
	dev, _ := s.st.Device(e.DeviceID)
	cn := firstNonEmpty(acc.FullName, acc.DisplayName, acc.Email, "Device")
	defaultOrg := "PQC PDF Sign (lab)"
	if li.Online {
		defaultOrg = "PQC PDF Sign"
	}
	org := firstNonEmpty(acc.Organization, li.Org, defaultOrg)

	tmp, err := os.MkdirTemp("", "pqc-issue-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	csrPath := filepath.Join(tmp, "device.csr.pem")
	outPath := filepath.Join(tmp, "device.crt.pem")
	if err := os.WriteFile(csrPath, e.CSRPEM, 0o600); err != nil {
		return nil, err
	}

	args := []string{"issue",
		"--dir", li.Dir, "--csr", csrPath,
		"--account", firstNonEmpty(acc.Email, e.AccountID),
		"--device", firstNonEmpty(dev.Label, e.DeviceID),
		"--cn", cn, "--org", org, "--days", strconv.Itoa(li.certDays()), "--out", outPath}
	if li.CRLURL != "" {
		args = append(args, "--crl-url", li.CRLURL)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := li.run(ctx, args...); err != nil {
		return nil, fmt.Errorf("ca-admin issue: %s", clip(out, 400))
	}
	return os.ReadFile(outPath)
}

// revokeViaCA records a serial as revoked in the CA ledger. An
// already-revoked serial is not an error.
func (s *Server) revokeViaCA(ctx context.Context, serialHex, reason string) error {
	if !s.issuerReady() {
		return nil
	}
	li := s.cfg.LabIssuer
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := li.run(ctx, "revoke", "--dir", li.Dir, "--serial", serialHex, "--reason", reason)
	if err != nil && !clipContains(out, "already revoked") {
		return fmt.Errorf("ca-admin revoke: %s", clip(out, 400))
	}
	return nil
}

// publishCRLViaCA asks the CA to publish a fresh CRL and returns its PEM so
// the caller can make it active (refreshCRL).
func (s *Server) publishCRLViaCA(ctx context.Context) ([]byte, error) {
	if !s.issuerReady() {
		return nil, nil
	}
	li := s.cfg.LabIssuer
	tmp, err := os.MkdirTemp("", "pqc-crl-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	outPath := filepath.Join(tmp, "crl.pem")
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if out, err := li.run(ctx, "crl", "--dir", li.Dir, "--out", outPath); err != nil {
		return nil, fmt.Errorf("ca-admin crl: %s", clip(out, 400))
	}
	return os.ReadFile(outPath)
}

// hLabIssue is the manual "issue straight from an enrollment" admin endpoint
// (retries when automatic issuance on enrolment failed).
func (s *Server) hLabIssue(w http.ResponseWriter, r *http.Request) {
	if !s.issuerReady() {
		writeErr(w, http.StatusConflict, "CA penerbit belum siap (sertifikat Intermediate belum terpasang)")
		return
	}
	e, err := s.st.Enrollment(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "enrollment not found")
		return
	}
	leaf, err := s.issueViaCA(r.Context(), e)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "issuance failed: "+err.Error())
		return
	}
	stored, err := s.bindIssuedCert(e, leaf)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"certificate_id": stored.ID, "serial": stored.Serial, "fingerprint": stored.Fingerprint,
	})
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func clip(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

func clipContains(b []byte, sub string) bool {
	return len(b) > 0 && strings.Contains(string(b), sub)
}
