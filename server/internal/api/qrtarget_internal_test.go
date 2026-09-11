package api

import (
	"net/http/httptest"
	"testing"
)

// A configured public base is the only QR target: the Host header and ?base=
// come from the signer's request and must not steer the QR to another site.
// Without a real base (dev / LAN on localhost) the request decides, and an
// all-loopback setup falls through to the bare verification ID.
func TestQRTarget(t *testing.T) {
	pub := &Server{cfg: Config{PublicBaseURL: "http://136.244.116.132:8099/"}}
	for _, u := range []string{
		"http://172.16.23.177:8099/api/v1/signatures/x/stamp",
		"http://evil.example/api/v1/signatures/x/stamp?base=http://evil.example",
		"http://127.0.0.1:8099/api/v1/signatures/x/stamp",
	} {
		r := httptest.NewRequest("POST", u, nil)
		if got := pub.qrTarget(r, "sig_abc"); got != "http://136.244.116.132:8099/v/sig_abc" {
			t.Errorf("configured base, request %s: got %q", u, got)
		}
	}

	dev := &Server{cfg: Config{PublicBaseURL: "http://localhost:8443"}}

	// request Host is a real LAN IP -> QR is a link there
	r := httptest.NewRequest("POST", "http://172.16.23.177:8099/api/v1/signatures/x/stamp", nil)
	if got := dev.qrTarget(r, "sig_abc"); got != "http://172.16.23.177:8099/v/sig_abc" {
		t.Errorf("LAN host: got %q", got)
	}

	// explicit ?base= wins over Host
	r = httptest.NewRequest("POST", "http://172.16.23.177:8099/api/v1/signatures/x/stamp?base=http://10.0.0.5:8098", nil)
	if got := dev.qrTarget(r, "sig_abc"); got != "http://10.0.0.5:8098/v/sig_abc" {
		t.Errorf("?base=: got %q", got)
	}

	// everything loopback -> bare id
	r = httptest.NewRequest("POST", "http://localhost:8099/api/v1/signatures/x/stamp", nil)
	if got := dev.qrTarget(r, "sig_abc"); got != "sig_abc" {
		t.Errorf("loopback: got %q, want bare id", got)
	}
}

// X-Forwarded-For only counts behind a trusted proxy; on a directly exposed
// port it is attacker-controlled and must not pick the rate-limit bucket.
func TestClientIPIgnoresForwardedForUnlessTrusted(t *testing.T) {
	r := httptest.NewRequest("POST", "http://api/api/v1/auth/login", nil)
	r.RemoteAddr = "203.0.113.7:51000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 10.0.0.1")
	if got := clientIP(r, false); got != "203.0.113.7" {
		t.Errorf("untrusted: got %q, want the socket address", got)
	}
	if got := clientIP(r, true); got != "198.51.100.1" {
		t.Errorf("trusted: got %q, want the first forwarded hop", got)
	}
}
