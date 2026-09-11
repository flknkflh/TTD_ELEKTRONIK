package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// Every response carries the browser hardening headers — JSON, PEM and the
// server-rendered pages alike.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/api/v1/public/ca/root.crt", "/v/sig_unknown"} {
		h := e.do("GET", path, "", nil).Header()
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: missing nosniff / frame headers: %v", path, h)
		}
		if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", path, h.Get("Content-Security-Policy"))
		}
	}
}

// Self-registration refuses malformed input with a reason the user can act on.
func TestRegisterValidation(t *testing.T) {
	e := newEnv(t)
	valid := func() map[string]string {
		return map[string]string{
			"email": "baru@instansi.go.id", "password": "rahasia123",
			"full_name": "Gita Aurora, S.Ap., M.P.A.", "organization": "Deputi Bidang Koordinasi",
			"position": "Plt. Asisten Deputi", "nip": "198704012011012005",
		}
	}
	for _, tc := range []struct{ name, field, value, want string }{
		{"email tanpa @", "email", "bukan-email", "format email"},
		{"email dengan nama", "email", "Budi <budi@x.id>", "format email"},
		{"kata sandi pendek", "password", "1234567", "kata sandi"},
		{"nama terlalu panjang", "full_name", strings.Repeat("a", 101), "Nama lengkap maksimal"},
		{"baris baru di jabatan", "position", "Kepala\nBagian", "baris baru"},
		{"NIP berisi huruf", "nip", "19870401ABC", "NIP hanya boleh berisi angka"},
		{"NIP terlalu panjang", "nip", strings.Repeat("1", 19), "NIP maksimal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := valid()
			in[tc.field] = tc.value
			w := e.do("POST", "/api/v1/auth/register", "", in)
			mustCode(t, w, http.StatusBadRequest)
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("reason = %s, want it to mention %q", w.Body.String(), tc.want)
			}
		})
	}
	t.Run("valid registration is accepted", func(t *testing.T) {
		in := valid()
		in["email"] = "  ok@instansi.go.id "
		mustCode(t, e.do("POST", "/api/v1/auth/register", "", in), http.StatusCreated)
	})
}
