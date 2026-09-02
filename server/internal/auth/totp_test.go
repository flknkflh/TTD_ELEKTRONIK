package auth

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	code, err := TOTPAt(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("code %q is not 6 digits", code)
	}
	if !ValidateTOTP(secret, code) {
		t.Fatal("fresh code rejected")
	}
	if ValidateTOTP(secret, "000000") && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	if ValidateTOTP(secret, "12345") {
		t.Fatal("short code accepted")
	}
}

func TestTOTPSkewWindow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	prev, _ := TOTPAt(secret, time.Now().Add(-30*time.Second))
	if !ValidateTOTP(secret, prev) {
		t.Fatal("code from the previous step should be accepted (±1 window)")
	}
	old, _ := TOTPAt(secret, time.Now().Add(-5*time.Minute))
	if old != prev && ValidateTOTP(secret, old) {
		t.Fatal("a 5-minute-old code must be rejected")
	}
}

func TestOTPAuthURL(t *testing.T) {
	u := OTPAuthURL("PQC PDF Sign", "user@example.id", "ABC234")
	if !strings.HasPrefix(u, "otpauth://totp/") || !strings.Contains(u, "secret=ABC234") {
		t.Fatalf("bad otpauth url: %s", u)
	}
}
