package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/api"
	"example.internal/pqc-pdf-sign/server/internal/auth"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Admin-console TOTP (Google Authenticator). newEnv logs the super admin in
// before it has an authenticator, so e.su starts as a setup-only session.

func newMFAEnv(t *testing.T) *env {
	return newEnvWith(t, func(c *api.Config) { c.AdminMFA = true })
}

func (e *env) loginCode(email, code string) *httptest.ResponseRecorder {
	e.t.Helper()
	body := map[string]string{"email": email, "password": "password123"}
	if code != "" {
		body["code"] = code
	}
	return e.do("POST", "/api/v1/auth/login", "", body)
}

// enrollMFA runs setup + confirm on a setup-only token and returns the
// secret and the full (second-factor) token.
func (e *env) enrollMFA(tok string) (secret, full string) {
	e.t.Helper()
	w := e.do("POST", "/api/v1/admin/mfa/setup", tok, nil)
	mustCode(e.t, w, http.StatusOK)
	secret = jbody(e.t, w)["secret"].(string)
	code, _ := auth.TOTPAt(secret, time.Now())
	w = e.do("POST", "/api/v1/admin/mfa/confirm", tok, map[string]string{"code": code})
	mustCode(e.t, w, http.StatusOK)
	return secret, jbody(e.t, w)["access_token"].(string)
}

// wrong returns a 6-digit code that differs from code in the last digit.
func wrong(code string) string {
	return code[:5] + string(rune('0'+(code[5]-'0'+1)%10))
}

func TestAdminMFAEnrollAndLogin(t *testing.T) {
	e := newMFAEnv(t)

	// setup-only session: every other route, even user routes, is refused
	w := e.do("GET", "/api/v1/admin/admins", e.su, nil)
	mustCode(t, w, http.StatusForbidden)
	if jbody(t, w)["mfa_setup_required"] != true {
		t.Fatalf("403 body = %s, want mfa_setup_required", w.Body.String())
	}
	mustCode(t, e.do("POST", "/api/v1/admin/me/password", e.su, map[string]string{
		"current_password": "password123", "new_password": "another-pass"}), http.StatusForbidden)
	mustCode(t, e.do("GET", "/api/v1/devices", e.su, nil), http.StatusForbidden)

	// Google Authenticator-compatible provisioning
	w = e.do("POST", "/api/v1/admin/mfa/setup", e.su, nil)
	mustCode(t, w, http.StatusOK)
	b := jbody(t, w)
	uri, _ := b["otpauth_url"].(string)
	for _, want := range []string{"otpauth://totp/", "secret=", "issuer=PQC", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("otpauth url %q lacks %q", uri, want)
		}
	}
	if png, _ := b["qr_png"].(string); !strings.HasPrefix(png, "data:image/png;base64,") {
		t.Fatal("setup response has no QR PNG")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("setup response must not be cached")
	}
	secret := b["secret"].(string)

	code, _ := auth.TOTPAt(secret, time.Now())
	mustCode(t, e.do("POST", "/api/v1/admin/mfa/confirm", e.su, map[string]string{"code": wrong(code)}), http.StatusUnauthorized)
	w = e.do("POST", "/api/v1/admin/mfa/confirm", e.su, map[string]string{"code": code})
	mustCode(t, w, http.StatusOK)
	b = jbody(t, w)
	full := b["access_token"].(string)
	recovery := b["recovery_codes"].([]any)
	if len(recovery) != 10 {
		t.Fatalf("got %d recovery codes, want 10", len(recovery))
	}
	mustCode(t, e.do("GET", "/api/v1/admin/admins", full, nil), http.StatusOK)
	mustCode(t, e.do("POST", "/api/v1/admin/mfa/setup", full, nil), http.StatusConflict)
	e.su, e.badmin = full, full

	// login now needs the code
	w = e.loginCode("_su@test", "")
	mustCode(t, w, http.StatusUnauthorized)
	if jbody(t, w)["mfa_required"] != true {
		t.Fatalf("login body = %s, want mfa_required", w.Body.String())
	}
	next, _ := auth.TOTPAt(secret, time.Now().Add(30*time.Second)) // confirm spent the current step
	mustCode(t, e.loginCode("_su@test", wrong(next)), http.StatusUnauthorized)
	w = e.loginCode("_su@test", next)
	mustCode(t, w, http.StatusOK)
	mustCode(t, e.do("GET", "/api/v1/admin/admins", jbody(t, w)["access_token"].(string), nil), http.StatusOK)
	mustCode(t, e.loginCode("_su@test", next), http.StatusUnauthorized) // no replay

	// a recovery code works once, however it is typed
	rc := recovery[0].(string)
	w = e.loginCode("_su@test", strings.ToUpper(rc))
	mustCode(t, w, http.StatusOK)
	if left := jbody(t, w)["recovery_codes_left"]; left != float64(9) {
		t.Fatalf("recovery_codes_left = %v, want 9", left)
	}
	mustCode(t, e.loginCode("_su@test", rc), http.StatusUnauthorized)

	// end users are never asked
	user := e.account("user@test", store.RoleUser)
	mustCode(t, e.do("GET", "/api/v1/devices", user, nil), http.StatusOK)
}

func TestAdminMFAResetBySuperAdmin(t *testing.T) {
	e := newMFAEnv(t)
	_, full := e.enrollMFA(e.su)
	e.su, e.badmin = full, full

	mustCode(t, e.do("POST", "/api/v1/admin/admins", e.su, map[string]string{
		"username": "op@test", "password": "password123"}), http.StatusCreated)
	w := e.loginCode("op@test", "")
	mustCode(t, w, http.StatusOK)
	b := jbody(t, w)
	if b["mfa_setup_required"] != true {
		t.Fatalf("new admin login = %s, want mfa_setup_required", w.Body.String())
	}
	opSetup := b["access_token"].(string)
	mustCode(t, e.do("GET", "/api/v1/admin/accounts", opSetup, nil), http.StatusForbidden)
	_, opFull := e.enrollMFA(opSetup)
	mustCode(t, e.do("GET", "/api/v1/admin/accounts", opFull, nil), http.StatusOK)

	id := adminID(t, e, "op@test")
	for _, a := range jbody(t, e.do("GET", "/api/v1/admin/admins", e.su, nil))["admins"].([]any) {
		if m := a.(map[string]any); m["account_id"] == id && m["mfa"] != true {
			t.Fatalf("roster row %v, want mfa true", m)
		}
	}

	// only the super admin resets, and never its own
	mustCode(t, e.do("POST", "/api/v1/admin/admins/"+id+"/mfa/reset", opFull, nil), http.StatusForbidden)
	mustCode(t, e.do("POST", "/api/v1/admin/admins/"+adminID(t, e, "_su@test")+"/mfa/reset", e.su, nil), http.StatusForbidden)
	mustCode(t, e.do("POST", "/api/v1/admin/admins/"+id+"/mfa/reset", e.su, nil), http.StatusOK)
	mustCode(t, e.do("POST", "/api/v1/admin/admins/"+id+"/mfa/reset", e.su, nil), http.StatusConflict)

	if jbody(t, e.loginCode("op@test", ""))["mfa_setup_required"] != true {
		t.Fatal("after reset the admin must set up a new authenticator")
	}
}

func TestAdminMFAOffByDefault(t *testing.T) {
	e := newEnv(t) // Config.AdminMFA false (lab / PQC_ADMIN_MFA_DISABLED)
	mustCode(t, e.do("GET", "/api/v1/admin/admins", e.su, nil), http.StatusOK)
	mustCode(t, e.do("POST", "/api/v1/admin/mfa/setup", e.su, nil), http.StatusNotFound)
}
