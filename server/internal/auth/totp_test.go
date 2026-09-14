package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1 key "12345678901234567890", truncated to the 6
// digits authenticator apps show. Matching these is what makes the codes line
// up with Google Authenticator.
func TestTOTPRFC6238Vectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32("12345678901234567890")
	for unix, want := range map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1234567890: "005924",
		2000000000: "279037",
	} {
		got, err := TOTPAt(secret, time.Unix(unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("TOTP at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestMatchTOTPWindowAndStep(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	cur := now.Unix() / totpPeriod

	code, _ := TOTPAt(secret, now)
	if step, ok := MatchTOTP(secret, code, now); !ok || step != cur {
		t.Fatalf("current code: step=%d ok=%v, want %d true", step, ok, cur)
	}
	prev, _ := TOTPAt(secret, now.Add(-30*time.Second))
	if step, ok := MatchTOTP(secret, prev, now); !ok || step != cur-1 {
		t.Fatalf("previous-step code: step=%d ok=%v, want %d true", step, ok, cur-1)
	}
	old, _ := TOTPAt(secret, now.Add(-5*time.Minute))
	if _, ok := MatchTOTP(secret, old, now); ok && old != code && old != prev {
		t.Fatal("a 5-minute-old code must be rejected")
	}
	if _, ok := MatchTOTP(secret, "12345", now); ok {
		t.Fatal("short code accepted")
	}
}

func TestOTPAuthURL(t *testing.T) {
	u := OTPAuthURL("PQC PDF Sign", "admin@example.id", "ABC234")
	for _, want := range []string{"otpauth://totp/PQC%20PDF%20Sign:admin@example.id?", "secret=ABC234",
		"issuer=PQC+PDF+Sign", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Fatalf("otpauth url %q lacks %q", u, want)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 13 || c[6] != '-' {
			t.Fatalf("recovery code %q is not xxxxxx-xxxxxx", c)
		}
		if seen[c] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[c] = true
	}
	loose := " " + strings.ToUpper(strings.ReplaceAll(codes[0], "-", " ")) + " "
	if HashRecoveryCode(loose) != HashRecoveryCode(codes[0]) {
		t.Fatal("recovery code hash must ignore case, spaces and dashes")
	}
	if HashRecoveryCode(codes[0]) == HashRecoveryCode(codes[1]) {
		t.Fatal("different codes hash the same")
	}
}
