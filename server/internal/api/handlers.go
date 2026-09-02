package api

import (
	"crypto/mldsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"example.internal/pqc-pdf-sign/core/certutil"
	"example.internal/pqc-pdf-sign/core/enrollment"
	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/verification"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// ---- auth ----

func (s *Server) hRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if err := decode(r, &in); err != nil || in.Email == "" || len(in.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "email and an 8+ char password are required")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash")
		return
	}
	role := store.RoleUser
	if in.Role == store.RoleAdmin {
		role = store.RoleAdmin // lab convenience; real deployments seed admins out of band
	}
	a, err := s.st.CreateAccount(store.Account{
		Email: in.Email, DisplayName: in.DisplayName, PasswordHash: hash, Role: role,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.register", AccountID: a.ID, Result: "ok"})
	writeJSON(w, http.StatusCreated, map[string]string{"account_id": a.ID, "role": a.Role})
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	a, err := s.st.AccountByEmail(in.Email)
	if err != nil || !auth.VerifyPassword(in.Password, a.PasswordHash) {
		s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "fail"})
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": s.signer.Issue(a.ID, a.Role),
		"token_type":   "Bearer",
		"expires_in":   int(s.signer.TTL().Seconds()),
	})
}

// ---- devices & enrollment ----

func (s *Server) hCreateDevice(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	var in struct{ Label, Platform string }
	_ = decode(r, &in)
	d, _ := s.st.CreateDevice(store.Device{AccountID: c.Sub, Label: in.Label, Platform: in.Platform})
	s.audit("device.create", c, d.ID, "ok", d.Label)
	writeJSON(w, http.StatusCreated, map[string]string{"device_id": d.ID, "status": d.Status})
}

func (s *Server) hListDevices(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	out := []map[string]any{}
	for _, d := range s.st.DevicesByAccount(c.Sub) {
		row := map[string]any{"device_id": d.ID, "label": d.Label, "platform": d.Platform, "status": d.Status}
		if cert, err := s.st.CertificateByDevice(d.ID); err == nil {
			row["certificate_serial"] = cert.Serial
			row["certificate_status"] = cert.Status
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) deviceOwnedBy(r *http.Request) (store.Device, error) {
	d, err := s.st.Device(r.PathValue("device_id"))
	if err != nil {
		return store.Device{}, err
	}
	if d.AccountID != claims(r).Sub {
		return store.Device{}, errors.New("forbidden")
	}
	return d, nil
}

func (s *Server) hSubmitCSR(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	d, err := s.deviceOwnedBy(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	body, err := readBody(r, 64<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	csr, info, err := enrollment.ParseAndValidateCSR(body)
	if err != nil {
		s.audit("csr.submit", c, d.ID, "reject", err.Error())
		writeErr(w, http.StatusBadRequest, "CSR rejected: "+err.Error())
		return
	}
	_ = csr
	e, _ := s.st.CreateEnrollment(store.Enrollment{
		DeviceID: d.ID, AccountID: c.Sub, CSRPEM: body, CSRKeyFP: info.PublicKeyFP,
	})
	s.audit("csr.submit", c, d.ID, "accept", e.ID)
	writeJSON(w, http.StatusCreated, map[string]string{"enrollment_id": e.ID, "status": e.Status})
}

func (s *Server) hDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	if _, err := s.deviceOwnedBy(r); err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	cert, err := s.st.CertificateByDevice(r.PathValue("device_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no certificate issued yet")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(cert.PEM)
}

func (s *Server) hReportLost(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	d, err := s.deviceOwnedBy(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	_ = s.st.SetDeviceStatus(d.ID, store.DeviceLost)
	s.audit("device.report_lost", c, d.ID, "ok", "")
	writeJSON(w, http.StatusOK, map[string]string{
		"device_id": d.ID, "status": store.DeviceLost,
		"note": "an admin must now revoke the device certificate and publish a new CRL",
	})
}

// ---- admin: certificate issuance & revocation ----

func (s *Server) hListEnrollments(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, e := range s.st.ListEnrollments() {
		out = append(out, map[string]any{
			"enrollment_id": e.ID, "device_id": e.DeviceID, "account_id": e.AccountID,
			"csr_key_fingerprint": e.CSRKeyFP, "status": e.Status, "created_at": fmtTime(e.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollments": out})
}

// hIssueCertificate accepts the certificate an offline CA issued for an
// enrollment, checks it chains to the configured Root CA and that its public
// key matches the CSR, then binds it to the enrollment's account+device.
func (s *Server) hIssueCertificate(w http.ResponseWriter, r *http.Request) {
	e, err := s.st.Enrollment(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "enrollment not found")
		return
	}
	body, err := readBody(r, 64<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	cert, info, err := certutil.ParseAndValidateCertificate(body, time.Now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "certificate rejected: "+err.Error())
		return
	}
	inter, _ := certutil.ParseChainPEM(s.cfg.CAChainPEM) // Root+Intermediate
	chain := certutil.ValidateCertificateChain(cert, inter, s.cfg.RootCAPEM, time.Now())
	if chain.Error != nil || !chain.TrustedChain {
		writeErr(w, http.StatusBadRequest, "certificate does not chain to the configured Root CA")
		return
	}
	// public key must match the CSR that was enrolled
	csr, _, err := enrollment.ParseAndValidateCSR(e.CSRPEM)
	if err != nil {
		writeErr(w, http.StatusConflict, "stored CSR no longer parses")
		return
	}
	csrPub, _ := csr.PublicKey.(*mldsa.PublicKey)
	certPub, _ := cert.PublicKey.(*mldsa.PublicKey)
	if csrPub == nil || certPub == nil || !csrPub.Equal(certPub) {
		writeErr(w, http.StatusBadRequest, "certificate public key does not match the enrolled CSR")
		return
	}
	stored, _ := s.st.CreateCertificate(store.Certificate{
		EnrollmentID: e.ID, DeviceID: e.DeviceID, AccountID: e.AccountID,
		Serial: info.SerialNumber, Fingerprint: info.FingerprintSHA256, PEM: body,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Status: store.CertActive,
	})
	_ = s.st.SetEnrollmentStatus(e.ID, store.EnrollmentIssued)
	s.st.Append(store.AuditEvent{Type: "certificate.issue", AccountID: e.AccountID, DeviceID: e.DeviceID, Result: "ok", Detail: stored.Serial})
	writeJSON(w, http.StatusCreated, map[string]string{
		"certificate_id": stored.ID, "serial": stored.Serial, "fingerprint": stored.Fingerprint,
	})
}

func (s *Server) hRevoke(w http.ResponseWriter, r *http.Request) {
	var in struct{ Reason string }
	_ = decode(r, &in)
	id := r.PathValue("id")
	if err := s.st.RevokeCertificate(id, in.Reason); err != nil {
		writeErr(w, http.StatusNotFound, "certificate not found")
		return
	}
	cert, _ := s.st.Certificate(id)
	s.st.Append(store.AuditEvent{Type: "certificate.revoke", AccountID: cert.AccountID, DeviceID: cert.DeviceID, Result: "ok", Detail: cert.Serial + " " + in.Reason})
	writeJSON(w, http.StatusOK, map[string]string{"certificate_id": id, "status": store.CertRevoked})
}

func (s *Server) hImportCRL(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r, 256<<10)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	if err := parseCRLBytes(body); err != nil {
		writeErr(w, http.StatusBadRequest, "not a parseable CRL: "+err.Error())
		return
	}
	s.crl = body
	s.st.Append(store.AuditEvent{Type: "crl.import", Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "crl updated"})
}

func (s *Server) hAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": s.st.AuditEvents(500)})
}

// ---- reservation & submission ----

func (s *Server) hReserve(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	var in struct {
		DeviceID       string `json:"device_id"`
		OriginalSHA512 string `json:"original_sha512"`
		FileName       string `json:"file_name"`
	}
	if err := decode(r, &in); err != nil || in.DeviceID == "" {
		writeErr(w, http.StatusBadRequest, "device_id is required")
		return
	}
	d, err := s.st.Device(in.DeviceID)
	if err != nil || d.AccountID != c.Sub {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	if d.Status != store.DeviceActive {
		writeErr(w, http.StatusForbidden, "device is "+d.Status)
		return
	}
	cert, err := s.st.CertificateByDevice(d.ID)
	if err != nil || cert.Status != store.CertActive {
		writeErr(w, http.StatusForbidden, "device has no active certificate")
		return
	}
	res, _ := s.st.CreateReservation(store.Reservation{
		AccountID: c.Sub, DeviceID: d.ID, OriginalSHA512: in.OriginalSHA512,
		FileName: sanitizeName(in.FileName), ExpiresAt: time.Now().Add(2 * time.Hour),
	})
	s.audit("signature.reserve", c, d.ID, "ok", res.PublicID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"public_id":        res.PublicID,
		"verification_url": s.verifyURL(res.PublicID),
		"expires_at":       fmtTime(res.ExpiresAt),
	})
}

func (s *Server) hSubmitDocument(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	res, err := s.st.Reservation(r.PathValue("public_id"))
	if err != nil || res.AccountID != c.Sub {
		writeErr(w, http.StatusNotFound, "reservation not found")
		return
	}
	if res.Status == store.ReservationAccepted {
		// idempotent: already completed
		if sig, err := s.st.Signature(res.PublicID); err == nil {
			writeJSON(w, http.StatusOK, submissionResult(sig))
			return
		}
	}
	body, err := readBody(r, s.cfg.MaxUploadBytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	if err := withinLimit(body, s.cfg.MaxUploadBytes); err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "PDF exceeds the upload limit")
		return
	}
	info, reason := s.strictVerify(res, body)
	if reason != "" {
		s.audit("signature.submit", c, res.DeviceID, "reject", reason)
		writeErr(w, http.StatusUnprocessableEntity, reason)
		return
	}

	key := fmt.Sprintf("documents/%d/%02d/%s/signed.pdf", time.Now().Year(), int(time.Now().Month()), res.PublicID)
	_ = s.st.PutObject(key, body)
	sig, err := s.st.CreateSignature(store.Signature{
		PublicID: res.PublicID, AccountID: res.AccountID, DeviceID: res.DeviceID,
		OriginalSHA512: res.OriginalSHA512, SignedSHA512: hashutil.CalculateSHA512(body),
		StorageObjectKey: key, SignedSize: len(body),
		ServerReceivedAt: time.Now().UTC(), VerificationStatus: "accepted",
		Algorithm: "ML-DSA-65", PDFProfile: "PAdES_B",
		CertSerial: info.CertSerial, CertFingerprint: info.CertFingerprint,
		CertificateID: info.CertificateID, ClientClaimedSigningTime: info.ClaimedTime,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, "submission already recorded")
		return
	}
	_ = s.st.SetReservationStatus(res.PublicID, store.ReservationAccepted)
	s.audit("signature.submit", c, res.DeviceID, "accept", res.PublicID)
	writeJSON(w, http.StatusOK, submissionResult(sig))
}

func submissionResult(sig store.Signature) map[string]any {
	return map[string]any{
		"public_id":          sig.PublicID,
		"status":             "accepted",
		"signed_pdf_sha512":  sig.SignedSHA512,
		"certificate_serial": sig.CertSerial,
		"server_received_at": fmtTime(sig.ServerReceivedAt),
	}
}

func (s *Server) hGetSignature(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil || sig.AccountID != claims(r).Sub {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, sig)
}

func (s *Server) hDownload(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil || sig.AccountID != claims(r).Sub {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	b, err := s.st.GetObject(sig.StorageObjectKey)
	if err != nil {
		writeErr(w, http.StatusNotFound, "object missing")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	_, _ = w.Write(b)
}

func (s *Server) hMySignatures(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"signatures": s.st.SignaturesByAccount(claims(r).Sub)})
}

// ---- public verifier ----

func (s *Server) hPublicVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(s.cfg.MaxUploadBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "expected multipart/form-data with a 'file' field")
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing 'file'")
		return
	}
	defer f.Close()
	pdf, err := readAll(f, s.cfg.MaxUploadBytes)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
		return
	}
	res, err := verification.VerifyPDF(pdf, verification.Options{
		RootPEM: s.cfg.RootCAPEM, IntermediatePEM: s.cfg.CAChainPEM, CRLPEM: s.crl,
		RequireMLDSAOnly: true,
	})
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	out := map[string]any{"verification": res, "registered": false}
	if len(res.Signatures) > 0 {
		if pid := res.Signatures[0].PublicID(); pid != "" {
			if sig, err := s.st.Signature(pid); err == nil {
				a, _ := s.st.Account(sig.AccountID)
				d, _ := s.st.Device(sig.DeviceID)
				out["registered"] = true
				out["record"] = publicRecord(sig, a, d)
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) hPublicRecord(w http.ResponseWriter, r *http.Request) {
	sig, err := s.st.Signature(r.PathValue("public_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such record")
		return
	}
	a, _ := s.st.Account(sig.AccountID)
	d, _ := s.st.Device(sig.DeviceID)
	writeJSON(w, http.StatusOK, publicRecord(sig, a, d))
}

func publicRecord(sig store.Signature, a store.Account, d store.Device) map[string]any {
	certStatus := "active"
	if d.Status == store.DeviceLost {
		certStatus = "device_reported_lost"
	}
	return map[string]any{
		"public_id":                   sig.PublicID,
		"signer_name":                 a.DisplayName,
		"device_label":                d.Label,
		"certificate_serial":          sig.CertSerial,
		"certificate_fingerprint":     sig.CertFingerprint,
		"certificate_status":          certStatus,
		"signed_pdf_sha512":           sig.SignedSHA512,
		"client_claimed_signing_time": sig.ClientClaimedSigningTime,
		"server_received_at":          fmtTime(sig.ServerReceivedAt),
		"note":                        "QR memastikan kecocokan dengan catatan server; integritas seluruh dokumen diverifikasi dari file PDF asli.",
	}
}

func (s *Server) verifyURL(publicID string) string {
	base := strings.TrimRight(s.cfg.PublicBaseURL, "/")
	if base == "" {
		base = "http://localhost:8443"
	}
	return base + "/v/" + publicID
}
