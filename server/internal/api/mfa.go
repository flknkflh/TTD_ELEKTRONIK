package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Admin-console second factor (TOTP, Google Authenticator compatible). Only
// admin and superadmin accounts are involved; end users and the signing apps
// never see it. With Config.AdminMFA on:
//
//   - an admin without a confirmed authenticator logs in to a setup-only
//     session that reaches nothing but /admin/mfa/{setup,confirm};
//   - once confirmed, login needs a 6-digit code or an unused recovery code;
//   - the super admin can reset an admin's authenticator. The super admin's
//     own is recovered with a recovery code (or on the server, see docs/api.md).

const recoveryCodeCount = 10

func isAdminRole(role string) bool {
	return role == store.RoleAdmin || role == store.RoleSuperAdmin
}

// mfaPending reports a session that must set up / pass the second factor
// before it may use any other route.
func (s *Server) mfaPending(c auth.Claims) bool {
	return s.cfg.AdminMFA && isAdminRole(c.Role) && !c.MFA
}

func (s *Server) mfaEnabled(accountID string) bool {
	cred, err := s.st.MFA(accountID)
	return err == nil && cred.Confirmed
}

// loginAdminMFA finishes a password-verified admin login when AdminMFA is on.
func (s *Server) loginAdminMFA(w http.ResponseWriter, a store.Account, code string) {
	cred, err := s.st.MFA(a.ID)
	if err != nil || !cred.Confirmed {
		s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "ok", Detail: "mfa setup required"})
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":       s.signer.Issue(a.ID, a.Role),
			"token_type":         "Bearer",
			"expires_in":         int(s.signer.TTL().Seconds()),
			"mfa_setup_required": true,
		})
		return
	}
	if strings.TrimSpace(code) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "masukkan kode dari aplikasi authenticator", "mfa_required": true,
		})
		return
	}
	via, ok := s.checkSecondFactor(cred, code)
	if !ok {
		s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "fail", Detail: "mfa code"})
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "kode verifikasi salah atau sudah dipakai", "mfa_required": true,
		})
		return
	}
	s.st.Append(store.AuditEvent{Type: "auth.login", AccountID: a.ID, Result: "ok", Detail: "mfa " + via})
	resp := map[string]any{
		"access_token": s.signer.IssueMFA(a.ID, a.Role),
		"token_type":   "Bearer",
		"expires_in":   int(s.signer.TTL().Seconds()),
	}
	if via == "recovery" {
		resp["recovery_codes_left"] = s.st.RecoveryCodesLeft(a.ID)
	}
	writeJSON(w, http.StatusOK, resp)
}

// checkSecondFactor accepts a TOTP code (each time step only once) or an
// unused recovery code, which is spent. It returns which one matched.
func (s *Server) checkSecondFactor(cred store.MFACredential, code string) (string, bool) {
	if step, ok := auth.MatchTOTP(cred.Secret, code, time.Now()); ok {
		return "totp", s.st.AdvanceMFAStep(cred.AccountID, step) == nil
	}
	return "recovery", s.st.UseRecoveryCode(cred.AccountID, auth.HashRecoveryCode(code)) == nil
}

// hMFASetup: POST /api/v1/admin/mfa/setup. Issues a fresh, unconfirmed secret
// (replacing an earlier unconfirmed one) and returns it as an otpauth:// URL
// plus a QR PNG for Google Authenticator.
func (s *Server) hMFASetup(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AdminMFA {
		writeErr(w, http.StatusNotFound, "verifikasi 2 langkah tidak diaktifkan di server ini")
		return
	}
	a, err := s.st.Account(claims(r).Sub)
	if err != nil {
		writeErr(w, http.StatusNotFound, "akun tidak ditemukan")
		return
	}
	if s.mfaEnabled(a.ID) {
		writeErr(w, http.StatusConflict, "verifikasi 2 langkah sudah aktif untuk akun ini")
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "secret")
		return
	}
	if err := s.st.UpsertMFA(a.ID, secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	uri := auth.OTPAuthURL(s.issuer, a.Email, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "qr")
		return
	}
	s.st.Append(store.AuditEvent{Type: "mfa.setup", AccountID: a.ID, Result: "ok"})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_url": uri,
		"issuer":      s.issuer,
		"account":     a.Email,
		"qr_png":      "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

// hMFAConfirm: POST /api/v1/admin/mfa/confirm {code}. The first code from the
// app confirms the secret; the response carries a full session token and the
// recovery codes, which are shown this once and stored only as hashes.
func (s *Server) hMFAConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AdminMFA {
		writeErr(w, http.StatusNotFound, "verifikasi 2 langkah tidak diaktifkan di server ini")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	c := claims(r)
	cred, err := s.st.MFA(c.Sub)
	if err != nil {
		writeErr(w, http.StatusConflict, "mulai penyiapan dulu (POST /api/v1/admin/mfa/setup)")
		return
	}
	if cred.Confirmed {
		writeErr(w, http.StatusConflict, "verifikasi 2 langkah sudah aktif untuk akun ini")
		return
	}
	step, ok := auth.MatchTOTP(cred.Secret, in.Code, time.Now())
	if !ok {
		s.st.Append(store.AuditEvent{Type: "mfa.enable", AccountID: c.Sub, Result: "fail"})
		writeErr(w, http.StatusUnauthorized, "kode salah — pastikan jam HP diatur otomatis, lalu coba kode terbaru")
		return
	}
	codes, err := auth.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "recovery codes")
		return
	}
	hashes := make([]string, len(codes))
	for i, rc := range codes {
		hashes[i] = auth.HashRecoveryCode(rc)
	}
	if err := s.st.ConfirmMFA(c.Sub, step, hashes); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "mfa.enable", AccountID: c.Sub, Result: "ok"})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":   s.signer.IssueMFA(c.Sub, c.Role),
		"token_type":     "Bearer",
		"expires_in":     int(s.signer.TTL().Seconds()),
		"recovery_codes": codes,
	})
}

// hMFAReset (super admin only): POST /api/v1/admin/admins/{id}/mfa/reset.
// Removes an admin's authenticator so the next login sets up a new one.
func (s *Server) hMFAReset(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.Account(r.PathValue("id"))
	if err == nil && a.Role == store.RoleSuperAdmin {
		writeErr(w, http.StatusForbidden, "MFA super admin tidak bisa di-reset dari sini — gunakan kode pemulihan")
		return
	}
	if err != nil || a.Role != store.RoleAdmin {
		writeErr(w, http.StatusNotFound, "admin tidak ditemukan")
		return
	}
	if err := s.st.DeleteMFA(a.ID); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusConflict, "admin ini belum mengaktifkan verifikasi 2 langkah")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "mfa.reset", AccountID: a.ID, Result: "ok", Detail: claims(r).Sub})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
