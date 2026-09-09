package api

import (
	"net/http"
	"strings"

	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Admin account CRUD (Rencana RB-1). The admin's job in the new model is
// account lifecycle: approve pending registrations, and disable/delete
// accounts — which cascades to every device certificate the account holds so
// that all of that person's past signatures immediately read "revoked" in the
// public verifier.

func (s *Server) accountView(a store.Account) map[string]any {
	certs := s.st.CertificatesByAccount(a.ID)
	active := 0
	for _, c := range certs {
		if c.Status == store.CertActive {
			active++
		}
	}
	return map[string]any{
		"account_id":          a.ID,
		"email":               a.Email,
		"username":            a.Email, // the login identifier; "username" for admin rows
		"full_name":           a.FullName,
		"organization":        a.Organization,
		"role":                a.Role,
		"status":              a.Status,
		"created_at":          fmtTime(a.CreatedAt),
		"certificates":        len(certs),
		"active_certificates": active,
	}
}

// hCreateAdmin (super admin only): create an active admin from a username +
// password. Admins can no longer self-register.
func (s *Server) hCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"` // alias for username
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	u := strings.TrimSpace(in.Username)
	if u == "" {
		u = strings.TrimSpace(in.Email)
	}
	if u == "" || len(in.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "username dan kata sandi minimal 8 karakter wajib diisi")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash")
		return
	}
	a, err := s.st.CreateAccount(store.Account{
		Email: u, DisplayName: u, Role: store.RoleAdmin, Status: store.AccountActive,
		PasswordHash: hash,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.st.Append(store.AuditEvent{Type: "admin.create", AccountID: a.ID, Result: "ok", Detail: claims(r).Sub})
	writeJSON(w, http.StatusCreated, s.accountView(a))
}

// hListAdmins (super admin only): the admin roster for the SU console.
func (s *Server) hListAdmins(w http.ResponseWriter, r *http.Request) {
	me := claims(r).Sub
	out := []map[string]any{}
	for _, a := range s.st.ListAccounts() {
		if a.Role != store.RoleAdmin && a.Role != store.RoleSuperAdmin {
			continue
		}
		out = append(out, map[string]any{
			"account_id": a.ID,
			"username":   a.Email,
			"role":       a.Role,
			"status":     a.Status,
			"self":       a.ID == me,
			"created_at": fmtTime(a.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": out})
}

func (s *Server) hListAccounts(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, a := range s.st.ListAccounts() {
		out = append(out, s.accountView(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

func (s *Server) hApproveAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := s.st.Account(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	if a.Status == store.AccountActive {
		writeJSON(w, http.StatusOK, s.accountView(a))
		return
	}
	if err := s.st.SetAccountStatus(id, store.AccountActive); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.approve", AccountID: id, Result: "ok"})
	a, _ = s.st.Account(id)
	writeJSON(w, http.StatusOK, s.accountView(a))
}

func (s *Server) hEnableAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := s.st.Account(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	if a.Role == store.RoleAdmin && claims(r).Role != store.RoleSuperAdmin {
		writeErr(w, http.StatusForbidden, "hanya super admin yang bisa mengaktifkan admin")
		return
	}
	if err := s.st.SetAccountStatus(id, store.AccountActive); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.enable", AccountID: id, Result: "ok",
		Detail: "prior certificates stay revoked; the user re-enrols on next login"})
	a, _ = s.st.Account(id)
	writeJSON(w, http.StatusOK, s.accountView(a))
}

func (s *Server) hUpdateAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.st.Account(id); err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	var in struct {
		FullName     string `json:"full_name"`
		Organization string `json:"organization"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if err := s.st.UpdateAccountProfile(id, in.FullName, in.Organization); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.update", AccountID: id, Result: "ok"})
	a, _ := s.st.Account(id)
	writeJSON(w, http.StatusOK, s.accountView(a))
}

// disableCascade revokes every active certificate of an account and publishes
// a fresh CRL. Returns the number of certificates revoked.
func (s *Server) disableCascade(r *http.Request, accountID, reason string) int {
	n := 0
	for _, c := range s.st.CertificatesByAccount(accountID) {
		if c.Status != store.CertActive {
			continue
		}
		_ = s.st.RevokeCertificate(c.ID, reason)
		_ = s.revokeViaCA(r.Context(), c.Serial, "cessationOfOperation")
		for _, d := range s.st.DevicesByAccount(accountID) {
			if d.ID == c.DeviceID {
				_ = s.st.SetDeviceStatus(d.ID, store.DeviceLost)
			}
		}
		s.st.Append(store.AuditEvent{Type: "certificate.revoke", AccountID: accountID,
			DeviceID: c.DeviceID, Result: "ok", Detail: c.Serial + " " + reason})
		n++
	}
	if n > 0 {
		if crl, err := s.publishCRLViaCA(r.Context()); err == nil && len(crl) > 0 {
			s.crl = crl
			s.st.Append(store.AuditEvent{Type: "crl.publish", AccountID: accountID, Result: "ok"})
		}
	}
	return n
}

func (s *Server) hDisableAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := s.st.Account(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	// The super admin can never be disabled — that would lock the console.
	if a.Role == store.RoleSuperAdmin {
		writeErr(w, http.StatusForbidden, "akun super admin tidak bisa dinonaktifkan")
		return
	}
	// An active admin may only be toggled by the super admin. A *pending* row
	// (there are none in the new model, but keep the carve-out) is fair game.
	if a.Role == store.RoleAdmin && a.Status != store.AccountPending && claims(r).Role != store.RoleSuperAdmin {
		writeErr(w, http.StatusForbidden, "hanya super admin yang bisa menonaktifkan admin")
		return
	}
	_ = s.st.SetAccountStatus(id, store.AccountDisabled)
	revoked := s.disableCascade(r, id, "account disabled")
	s.st.Append(store.AuditEvent{Type: "account.disable", AccountID: id, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"account_id": id, "status": store.AccountDisabled, "certificates_revoked": revoked,
	})
}

func (s *Server) hDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := s.st.Account(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	if a.Role == store.RoleSuperAdmin {
		writeErr(w, http.StatusForbidden, "akun super admin tidak bisa dihapus")
		return
	}
	if a.Role == store.RoleAdmin && a.Status != store.AccountPending {
		writeErr(w, http.StatusForbidden, "tidak bisa menghapus akun admin yang sudah aktif; nonaktifkan saja")
		return
	}
	_ = s.st.SetAccountStatus(id, store.AccountDisabled)
	revoked := s.disableCascade(r, id, "account deleted")
	// True row deletion only succeeds when nothing references the account
	// (no signatures/devices). Signatures are legal records, so a used
	// account is kept as a disabled tombstone instead.
	if err := s.st.DeleteAccount(id); err != nil {
		s.st.Append(store.AuditEvent{Type: "account.delete", AccountID: id, Result: "tombstone"})
		writeJSON(w, http.StatusOK, map[string]any{
			"account_id": id, "status": store.AccountDisabled, "certificates_revoked": revoked,
			"note": "akun punya riwayat tanda tangan; dinonaktifkan permanen alih-alih dihapus",
		})
		return
	}
	s.st.Append(store.AuditEvent{Type: "account.delete", AccountID: id, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{
		"account_id": id, "status": "deleted", "certificates_revoked": revoked,
	})
}
