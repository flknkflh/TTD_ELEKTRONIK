package api_test

import (
	"net/http"
	"testing"
	"time"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// A document signed and accepted while its certificate was valid stays valid
// in the upload verifier after that certificate expires; a tampered copy does
// not.
func TestPublicVerifyAfterCertificateExpiry(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)

	// x509 validity has one-second resolution; this certificate expires a few
	// seconds after the submission below.
	notBefore := time.Now().Add(-time.Minute).Truncate(time.Second)
	notAfter := time.Now().Add(5 * time.Second).Truncate(time.Second)
	d := e.enrolledDeviceFor(user, e.su, "Laptop", notBefore, notAfter.Sub(notBefore))
	pid := e.reserve(user, d.id)
	signed := signWith(t, d, pid)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signed), http.StatusOK)

	verdict := func(pdf []byte) (bool, string) {
		t.Helper()
		w := e.verifyMultipart(pdf)
		mustCode(t, w, http.StatusOK)
		b := jbody(t, w)
		src, _ := b["validation_time_source"].(string)
		return b["verification"].(map[string]any)["valid"] == true, src
	}
	if ok, src := verdict(signed); !ok || src != "now" {
		t.Fatalf("before expiry: valid=%v source=%q, want true/now", ok, src)
	}

	time.Sleep(time.Until(notAfter) + 1500*time.Millisecond)

	if ok, src := verdict(signed); !ok || src != "server_received_at" {
		t.Fatalf("after expiry: valid=%v source=%q, want true/server_received_at", ok, src)
	}

	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)/2] ^= 0xff
	if ok, _ := verdict(tampered); ok {
		t.Fatal("a tampered copy verified after expiry")
	}
}
