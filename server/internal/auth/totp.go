package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RFC 6238 TOTP with the parameters Google Authenticator (and every other
// authenticator app) assumes: SHA-1, 30-second step, 6 digits. Hand-rolled
// to keep the server dependency-free, like the Argon2id/JWT code.

const (
	totpDigits = 6
	totpPeriod = 30 // seconds
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh 160-bit base32 secret.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// OTPAuthURL builds the otpauth:// URI an authenticator app scans as a QR
// code (or opens directly when tapped on the phone).
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPAt computes the code for a specific time.
func TOTPAt(secret string, t time.Time) (string, error) {
	return totpCode(secret, t.Unix()/totpPeriod)
}

func totpCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("auth: bad TOTP secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	code := uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	code %= 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// MatchTOTP checks code against secret at now, allowing ±1 step of clock
// skew, and returns the time step that matched. Callers keep the newest
// accepted step and refuse any step not newer than it, so a code works once.
func MatchTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for _, step := range []int64{cur, cur - 1, cur + 1} {
		want, err := totpCode(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// GenerateRecoveryCodes returns n single-use codes such as "k7m2qx-9p4dab"
// (56 bits each) for an admin who has lost the authenticator app.
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		b := make([]byte, 7)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		s := strings.ToLower(b32.EncodeToString(b)) // 12 chars
		codes[i] = s[:6] + "-" + s[6:]
	}
	return codes, nil
}

// HashRecoveryCode normalises a typed recovery code (case, spaces, dashes)
// and returns the SHA-256 hex that is stored instead of the code. The codes
// carry 56 bits of entropy, so a fast hash is enough.
func HashRecoveryCode(code string) string {
	c := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:])
}
