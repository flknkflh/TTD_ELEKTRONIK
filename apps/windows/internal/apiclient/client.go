// Package apiclient is the desktop client's typed wrapper over the receiver
// API (Rencana V1 §17). It performs no crypto and holds no private key — it
// only moves bytes between the app and the server.
package apiclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// uploadChunkBytes is the size of one resumable-upload chunk, and the
// threshold above which a body is pushed through /api/v1/uploads instead of a
// single request (docs/large-files.md).
const uploadChunkBytes = 8 << 20

type Client struct {
	base  string
	http  *http.Client
	token string
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
		// enough headroom for one ~8 MiB resumable-upload chunk on a slow link
		http: &http.Client{Timeout: 2 * time.Minute, Transport: tr},
	}
}

// IsTooLarge reports whether err is a 413 from the server — the payload is
// past a size tier (e.g. too big for a server-drawn QR stamp).
func IsTooLarge(err error) bool {
	var e *apiError
	return errors.As(err, &e) && e.Status == http.StatusRequestEntityTooLarge
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

// RegisterResult mirrors the server's RB-1 register response.
type RegisterResult struct {
	AccountID string `json:"account_id"`
	Status    string `json:"status"` // "pending" for a self-registered user
	Message   string `json:"message"`
}

// Register self-registers an account (Rencana RB-1). The account is created
// pending; an admin approves it before the user can log in. position and nip
// fill the electronic-signature caption drawn on stamps.
func (c *Client) Register(fullName, org, email, password, position, nip string) (RegisterResult, error) {
	var out RegisterResult
	err := c.postJSON("/api/v1/auth/register", map[string]string{
		"email": email, "password": password,
		"full_name": fullName, "organization": org, "display_name": fullName,
		"position": position, "nip": nip,
	}, &out)
	return out, err
}

// Login stores the access token on success.
func (c *Client) Login(email, password string) error {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]string{"email": email, "password": password})
	raw, _, err := c.do(http.MethodPost, "/api/v1/auth/login", &buf, "application/json")
	if err != nil {
		return err
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(raw, &out)
	if out.AccessToken == "" {
		return fmt.Errorf("login: no access token in response")
	}
	c.token = out.AccessToken
	return nil
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

// StampPlacement is one QR box the signer dropped: page number (1-based) and
// a page-relative rectangle with the origin at the top-left. X,Y is the box's
// top-left corner; W is its width. All fractions in [0,1].
type StampPlacement struct {
	Page int     `json:"page"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	W    float64 `json:"w"`
}

// Stamp uploads the original PDF and returns it with one caption+QR stamp per
// placement (Rencana RB-2c), ready to sign on-device. The page count is
// unchanged. Placements go through as a JSON `stamps` query param; the server
// still accepts a single placement via page/x/y/w for older clients.
func (c *Client) Stamp(publicID string, pdf []byte, placements []StampPlacement, reason, issuedPlace string) ([]byte, error) {
	q := url.Values{}
	if reason != "" {
		q.Set("reason", reason)
	}
	if issuedPlace != "" {
		q.Set("issued_place", issuedPlace)
	}
	if js, err := json.Marshal(placements); err == nil {
		q.Set("stamps", string(js))
	}
	if len(placements) == 1 { // keep the single-placement params for compatibility
		p := placements[0]
		if p.Page > 0 {
			q.Set("page", strconv.Itoa(p.Page))
		}
		q.Set("x", strconv.FormatFloat(p.X, 'f', 4, 64))
		q.Set("y", strconv.FormatFloat(p.Y, 'f', 4, 64))
		q.Set("w", strconv.FormatFloat(p.W, 'f', 4, 64))
	}
	base := "/api/v1/signatures/" + publicID + "/stamp"
	if len(pdf) > uploadChunkBytes {
		id, uerr := c.uploadBytes(pdf)
		if uerr != nil {
			return nil, fmt.Errorf("unggah bertahap: %w", uerr)
		}
		q.Set("upload_id", id)
		raw, _, err := c.do(http.MethodPost, base+"?"+q.Encode(), nil, "")
		return raw, err
	}
	raw, _, err := c.do(http.MethodPost, base+"?"+q.Encode(), bytes.NewReader(pdf), "application/pdf")
	return raw, err
}

func (c *Client) SubmitDocument(publicID string, signedPDF []byte) (map[string]any, error) {
	path := "/api/v1/signatures/" + publicID + "/document"
	var (
		raw []byte
		err error
	)
	if len(signedPDF) > uploadChunkBytes {
		id, uerr := c.uploadBytes(signedPDF)
		if uerr != nil {
			return nil, fmt.Errorf("unggah bertahap: %w", uerr)
		}
		raw, _, err = c.do(http.MethodPut, path+"?upload_id="+id, nil, "")
	} else {
		raw, _, err = c.do(http.MethodPut, path, bytes.NewReader(signedPDF), "application/pdf")
	}
	if err != nil {
		return nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

// uploadBytes pushes data to a fresh resumable upload (POST /api/v1/uploads +
// PATCH chunks) and returns the upload id to hand to ?upload_id=.
func (c *Client) uploadBytes(data []byte) (string, error) {
	raw, _, err := c.do(http.MethodPost, "/api/v1/uploads", nil, "")
	if err != nil {
		return "", err
	}
	var mk struct {
		UploadID string `json:"upload_id"`
	}
	if json.Unmarshal(raw, &mk); mk.UploadID == "" {
		return "", fmt.Errorf("respons unggah tanpa upload_id")
	}
	for off := int64(0); off < int64(len(data)); {
		end := off + uploadChunkBytes
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		resp, _, cerr := c.do(http.MethodPatch,
			"/api/v1/uploads/"+mk.UploadID+"?offset="+strconv.FormatInt(off, 10),
			bytes.NewReader(data[off:end]), "application/octet-stream")
		if cerr != nil {
			return "", cerr
		}
		var pr struct {
			Received int64 `json:"received"`
		}
		_ = json.Unmarshal(resp, &pr)
		if pr.Received <= off {
			return "", fmt.Errorf("unggah macet di offset %d", off)
		}
		off = pr.Received
	}
	return mk.UploadID, nil
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

// VerifyHash asks the public hash verifier whether sha512Hex is the digest the
// server recorded for publicID. Only the 64-byte digest is sent -- the document
// itself never leaves the machine, which is the point: a confidential file can
// be checked without uploading it (and a very large one without the wait).
func (c *Client) VerifyHash(publicID, sha512Hex string) (map[string]any, error) {
	var out map[string]any
	err := c.postJSON("/api/v1/public/verify-hash",
		map[string]string{"public_id": publicID, "sha512": sha512Hex}, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
