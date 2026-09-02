// Package apiclient is the desktop client's typed wrapper over the receiver
// API (Rencana V1 §17). It performs no crypto and holds no private key — it
// only moves bytes between the app and the server.
package apiclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	base   string
	http   *http.Client
	token  string
	MFAReq bool // set by Login when the server wants a TOTP code
}

// New returns a client for baseURL (e.g. https://localhost:8443). insecureTLS
// accepts a self-signed server cert — LAB ONLY (Caddy internal CA, §22.2).
func New(baseURL string, insecureTLS bool) *Client {
	tr := &http.Transport{}
	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // lab only
	}
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: 60 * time.Second, Transport: tr},
	}
}

func (c *Client) SetToken(t string) { c.token = t }
func (c *Client) Token() string     { return c.token }

type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("server %d: %s", e.Status, e.Msg) }

func (c *Client) do(method, path string, body io.Reader, contentType string) ([]byte, int, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(raw))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return raw, resp.StatusCode, &apiError{resp.StatusCode, msg}
	}
	return raw, resp.StatusCode, nil
}

func (c *Client) postJSON(path string, in any, out any) error {
	var buf bytes.Buffer
	if in != nil {
		_ = json.NewEncoder(&buf).Encode(in)
	}
	raw, _, err := c.do(http.MethodPost, path, &buf, "application/json")
	if err != nil {
		return err
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// ---- auth ----

func (c *Client) Register(email, password, displayName, role string) (string, error) {
	var out struct {
		AccountID string `json:"account_id"`
	}
	err := c.postJSON("/api/v1/auth/register", map[string]string{
		"email": email, "password": password, "display_name": displayName, "role": role,
	}, &out)
	return out.AccountID, err
}

// Login stores the access token. If the server needs a TOTP code and none was
// given, c.MFAReq is set and a non-nil error is returned.
func (c *Client) Login(email, password, code string) error {
	body := map[string]string{"email": email, "password": password}
	if code != "" {
		body["code"] = code
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	raw, status, err := c.do(http.MethodPost, "/api/v1/auth/login", &buf, "application/json")

	var out struct {
		AccessToken string `json:"access_token"`
		MFARequired bool   `json:"mfa_required"`
	}
	_ = json.Unmarshal(raw, &out)
	c.MFAReq = out.MFARequired
	if err != nil {
		if status == http.StatusUnauthorized && out.MFARequired {
			return fmt.Errorf("a TOTP code is required")
		}
		return err
	}
	if out.AccessToken == "" {
		return fmt.Errorf("login: no access token in response")
	}
	c.token = out.AccessToken
	return nil
}

func (c *Client) MFASetup() (secret, otpauthURL string, err error) {
	var out struct {
		Secret     string `json:"secret"`
		OTPAuthURL string `json:"otpauth_url"`
	}
	err = c.postJSON("/api/v1/auth/mfa/setup", nil, &out)
	return out.Secret, out.OTPAuthURL, err
}

func (c *Client) MFAVerify(code string) error {
	return c.postJSON("/api/v1/auth/mfa/verify", map[string]string{"code": code}, nil)
}

// ---- devices & enrollment ----

func (c *Client) CreateDevice(label, platform string) (string, error) {
	var out struct {
		DeviceID string `json:"device_id"`
	}
	err := c.postJSON("/api/v1/devices", map[string]string{"label": label, "platform": platform}, &out)
	return out.DeviceID, err
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func (c *Client) SubmitCSR(deviceID string, csrPEM []byte) (string, error) {
	raw, _, err := c.do(http.MethodPost, "/api/v1/devices/"+deviceID+"/csr", bytes.NewReader(csrPEM), "application/x-pem-file")
	if err != nil {
		return "", err
	}
	var out struct {
		EnrollmentID string `json:"enrollment_id"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.EnrollmentID, nil
}

// DeviceCertificate returns the issued cert PEM, or ErrNotYetIssued.
func (c *Client) DeviceCertificate(deviceID string) ([]byte, error) {
	raw, status, err := c.do(http.MethodGet, "/api/v1/devices/"+deviceID+"/certificate", nil, "")
	if status == http.StatusNotFound {
		return nil, ErrNotYetIssued
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// ErrNotYetIssued means the CA has not yet uploaded a certificate.
var ErrNotYetIssued = fmt.Errorf("certificate not issued yet")

func (c *Client) ReportLost(deviceID string) error {
	_, _, err := c.do(http.MethodPost, "/api/v1/devices/"+deviceID+"/report-lost", nil, "")
	return err
}

// ---- admin: offline certificate issuance (Rencana V1 §14, §17.5) ----

type Enrollment struct {
	EnrollmentID string `json:"enrollment_id"`
	DeviceID     string `json:"device_id"`
	AccountID    string `json:"account_id"`
	Status       string `json:"status"`
}

func (c *Client) ListEnrollments() ([]Enrollment, error) {
	raw, _, err := c.do(http.MethodGet, "/api/v1/admin/enrollments", nil, "")
	if err != nil {
		return nil, err
	}
	var out struct {
		Enrollments []Enrollment `json:"enrollments"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Enrollments, nil
}

func (c *Client) ExportEnrollmentCSR(enrollmentID string) ([]byte, error) {
	raw, _, err := c.do(http.MethodGet, "/api/v1/admin/enrollments/"+enrollmentID+"/export", nil, "")
	return raw, err
}

func (c *Client) ApproveEnrollment(enrollmentID string) error {
	_, _, err := c.do(http.MethodPost, "/api/v1/admin/enrollments/"+enrollmentID+"/approve", nil, "")
	return err
}

func (c *Client) IssueCertificate(enrollmentID string, certPEM []byte) (map[string]any, error) {
	raw, _, err := c.do(http.MethodPost, "/api/v1/admin/enrollments/"+enrollmentID+"/certificate",
		bytesReader(certPEM), "application/x-pem-file")
	if err != nil {
		return nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func (c *Client) RevokeCertificate(certID, reason string) error {
	return c.postJSON("/api/v1/admin/certificates/"+certID+"/revoke", map[string]string{"reason": reason}, nil)
}

// ---- public CA material ----

func (c *Client) PublicRootCA() ([]byte, error) { return c.getRaw("/api/v1/public/ca/root.crt") }
func (c *Client) PublicChain() ([]byte, error)  { return c.getRaw("/api/v1/public/ca/chain.pem") }
func (c *Client) PublicCRL() ([]byte, error)    { return c.getRaw("/api/v1/public/ca/crl.pem") }

func (c *Client) getRaw(path string) ([]byte, error) {
	raw, _, err := c.do(http.MethodGet, path, nil, "")
	return raw, err
}

// ---- signatures ----

type Reservation struct {
	PublicID        string `json:"public_id"`
	VerificationURL string `json:"verification_url"`
	ExpiresAt       string `json:"expires_at"`
}

func (c *Client) Reserve(deviceID, originalSHA512, fileName string) (Reservation, error) {
	var out Reservation
	err := c.postJSON("/api/v1/signatures/reserve", map[string]string{
		"device_id": deviceID, "original_sha512": originalSHA512, "file_name": fileName,
	}, &out)
	return out, err
}

func (c *Client) SubmitDocument(publicID string, signedPDF []byte) (map[string]any, error) {
	raw, _, err := c.do(http.MethodPut, "/api/v1/signatures/"+publicID+"/document",
		bytes.NewReader(signedPDF), "application/pdf")
	if err != nil {
		return nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func (c *Client) MySignatures() ([]map[string]any, error) {
	raw, _, err := c.do(http.MethodGet, "/api/v1/me/signatures", nil, "")
	if err != nil {
		return nil, err
	}
	var out struct {
		Signatures []map[string]any `json:"signatures"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Signatures, nil
}

// VerifyPublic uploads a PDF to the public verifier and returns the raw JSON.
func (c *Client) VerifyPublic(pdf []byte) (map[string]any, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "document.pdf")
	_, _ = fw.Write(pdf)
	_ = mw.Close()
	raw, _, err := c.do(http.MethodPost, "/api/v1/verify", &buf, mw.FormDataContentType())
	if err != nil {
		return nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, nil
}
