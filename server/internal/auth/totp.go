package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RFC 6238 TOTP, SHA-1, 30-second step, 6 digits — the parameters every
// authenticator app assumes. Hand-rolled to keep the server dependency-free
// (same choice as the Argon2id/JWT code above).

const (
	totpDigits = 6
	totpStep   = 30 * time.Second
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

// OTPAuthURL builds the otpauth:// URI an app scans as a QR code.
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPAt computes the code for a specific time.
func TOTPAt(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("auth: bad TOTP secret: %w", err)
	}
	counter := uint64(t.Unix()) / uint64(totpStep.Seconds())
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3]))
	code %= 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateTOTP checks code against secret, allowing ±1 step of clock skew.
func ValidateTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	now := time.Now()
	for _, d := range []time.Duration{0, -totpStep, totpStep} {
		want, err := TOTPAt(secret, now.Add(d))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
