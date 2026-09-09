package api_test

import (
	"net/http"
	"testing"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// RB-1: a self-registered account is pending until an admin approves, and a
// disabled account both loses its session and has every certificate revoked.

func TestAccountApprovalGate(t *testing.T) {
	e := newEnv(t)
	admin := e.account("admin@test", store.RoleAdmin)

	w := e.do("POST", "/api/v1/auth/register", "", map[string]string{
		"email": "pegawai@test", "password": "password123",
		"full_name": "Budi Pegawai", "organization": "Dinas X",
	})
	mustCode(t, w, http.StatusCreated)
	body := jbody(t, w)
	if body["status"] != store.AccountPending {
		t.Fatalf("register status = %v, want pending", body["status"])
	}
	id := body["account_id"].(string)

	// login is refused while pending
	w = e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"})
	mustCode(t, w, http.StatusForbidden)
	if jbody(t, w)["account_status"] != store.AccountPending {
		t.Fatalf("login body = %s", w.Body.String())
	}

	// admin approves -> login works
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/approve", admin, nil), http.StatusOK)
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"}), http.StatusOK)

	// admin disables -> login refused again
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/disable", admin, nil), http.StatusOK)
	w = e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"})
	mustCode(t, w, http.StatusForbidden)
	if jbody(t, w)["account_status"] != store.AccountDisabled {
		t.Fatalf("login body = %s", w.Body.String())
	}

	// re-enable
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/enable", admin, nil), http.StatusOK)
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{"email": "pegawai@test", "password": "password123"}), http.StatusOK)
}

// Only the first admin bootstraps itself; later admin sign-ups sit in the
// approval queue until an already-active admin lets them in.
func TestAdminSignupNeedsApproval(t *testing.T) {
	e := newEnv(t) // newEnv already created the one bootstrap admin
	admin := e.adminTok()

	reg := func(email string) map[string]any {
		w := e.do("POST", "/api/v1/auth/register", "", map[string]string{
			"email": email, "password": "password123", "role": store.RoleAdmin,
		})
		mustCode(t, w, http.StatusCreated)
		return jbody(t, w)
	}
	login := func(email string) int {
		return e.do("POST", "/api/v1/auth/login", "", map[string]string{
			"email": email, "password": "password123"}).Code
	}

	// a second admin request is queued, not granted
	b := reg("admin2@test")
	if b["role"] != store.RoleAdmin || b["status"] != store.AccountPending {
		t.Fatalf("second admin = %v/%v, want admin/pending", b["role"], b["status"])
	}
	if code := login("admin2@test"); code != http.StatusForbidden {
		t.Fatalf("pending admin login = %d, want 403", code)
	}

	// the active admin approves -> it can log in and use admin routes
	id := b["account_id"].(string)
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/approve", admin, nil), http.StatusOK)
	if code := login("admin2@test"); code != http.StatusOK {
		t.Fatalf("approved admin login = %d, want 200", code)
	}
	tok2 := e.login("admin2@test")
	mustCode(t, e.do("GET", "/api/v1/admin/accounts", tok2, nil), http.StatusOK)

	// a pending admin may be rejected outright...
	b3 := reg("admin3@test")
	id3 := b3["account_id"].(string)
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id3+"/disable", admin, nil), http.StatusOK)
	if code := login("admin3@test"); code != http.StatusForbidden {
		t.Fatalf("rejected admin login = %d, want 403", code)
	}

	// ...but an approved admin is protected, so the console can't be locked out
	mustCode(t, e.do("POST", "/api/v1/admin/accounts/"+id+"/disable", admin, nil), http.StatusForbidden)
	mustCode(t, e.do("DELETE", "/api/v1/admin/accounts/"+id, admin, nil), http.StatusForbidden)
}

func TestAccountDisableCascadesRevocation(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")

	// sign + submit a document so there is a public record to check later
	pid := e.reserve(user, d.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d, pid)), http.StatusOK)

	// resolve the account id from the admin account list
	var accID string
	for _, a := range jbody(t, e.do("GET", "/api/v1/admin/accounts", admin, nil))["accounts"].([]any) {
		if m := a.(map[string]any); m["email"] == "user@test" {
			accID = m["account_id"].(string)
		}
	}
	if accID == "" {
		t.Fatal("user account not found in admin list")
	}

	w := e.do("POST", "/api/v1/admin/accounts/"+accID+"/disable", admin, nil)
	mustCode(t, w, http.StatusOK)
	if n := jbody(t, w)["certificates_revoked"]; n != float64(1) {
		t.Fatalf("certificates_revoked = %v, want 1", n)
	}

	// the public record now reports the certificate as revoked
	w = e.do("GET", "/api/v1/public/signatures/"+pid, "", nil)
	mustCode(t, w, http.StatusOK)
	if got := jbody(t, w)["certificate_status"]; got != "revoked" {
		t.Fatalf("certificate_status = %v, want revoked", got)
	}

	// the disabled user can no longer log in or reserve
	mustCode(t, e.do("POST", "/api/v1/auth/login", "", map[string]string{
		"email": "user@test", "password": "password123",
	}), http.StatusForbidden)
}

func TestAccountListAndProfile(t *testing.T) {
	e := newEnv(t)
	admin := e.account("admin@test", store.RoleAdmin)

	reg := jbody(t, e.do("POST", "/api/v1/auth/register", "", map[string]string{
		"email": "c@test", "password": "password123", "full_name": "C Orig", "organization": "Org A",
	}))
	id := reg["account_id"].(string)

	w := e.do("PATCH", "/api/v1/admin/accounts/"+id, admin, map[string]string{
		"full_name": "C Updated", "organization": "Org B",
	})
	mustCode(t, w, http.StatusOK)
	got := jbody(t, w)
	if got["full_name"] != "C Updated" || got["organization"] != "Org B" {
		t.Fatalf("profile not updated: %s", w.Body.String())
	}

	list := jbody(t, e.do("GET", "/api/v1/admin/accounts", admin, nil))["accounts"].([]any)
	if len(list) < 2 {
		t.Fatalf("account list too short: %v", list)
	}
}
