package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"
)

// cmdTOTP prints the current RFC 6238 code for a base32 secret. Used by the
// local end-to-end script to satisfy the server's MFA gate; not part of the
// signing flow.
func cmdTOTP(args []string) error {
	fs := flag.NewFlagSet("totp", flag.ExitOnError)
	secret := fs.String("secret", "", "base32 TOTP secret (from /auth/mfa/setup)")
	_ = fs.Parse(args)
	if *secret == "" {
		return errors.New("-secret is required")
	}
	code, err := totpAt(*secret, time.Now())
	if err != nil {
		return err
	}
	fmt.Println(code)
	return nil
}

func totpAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("bad base32 secret: %w", err)
	}
	counter := uint64(t.Unix()) / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])) % 1_000_000
	return fmt.Sprintf("%06d", v), nil
}
