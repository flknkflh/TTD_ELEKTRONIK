package api

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits for account fields. They bound what ends up in a certificate
// subject and on the QR caption, not just in the database.
const (
	maxEmailLen    = 254
	minPasswordLen = 8
	maxPasswordLen = 128
	maxNameLen     = 100
	maxOrgLen      = 150
	maxPositionLen = 200
	maxNIPLen      = 18
)

// accountProfile is the user-supplied part of a self-registration.
type accountProfile struct {
	Email, Password, DisplayName, FullName, Organization, Position, NIP string
}

// normalize trims surrounding whitespace from every free-text field (never
// from the password).
func (p *accountProfile) normalize() {
	for _, f := range []*string{&p.Email, &p.DisplayName, &p.FullName, &p.Organization, &p.Position, &p.NIP} {
		*f = strings.TrimSpace(*f)
	}
}

// validateRegistration returns why a self-registration is refused, or "".
func validateRegistration(p accountProfile) string {
	if msg := validateEmail(p.Email); msg != "" {
		return msg
	}
	if n := utf8.RuneCountInString(p.Password); n < minPasswordLen || n > maxPasswordLen {
		return fmt.Sprintf("kata sandi harus %d–%d karakter", minPasswordLen, maxPasswordLen)
	}
	return firstProblem(
		validateText("Nama tampilan", p.DisplayName, maxNameLen),
		validateText("Nama lengkap", p.FullName, maxNameLen),
		validateText("Instansi", p.Organization, maxOrgLen),
		validateText("Jabatan", p.Position, maxPositionLen),
		validateNIP(p.NIP),
	)
}

func validateEmail(e string) string {
	if e == "" {
		return "email wajib diisi"
	}
	if len(e) > maxEmailLen {
		return fmt.Sprintf("email maksimal %d karakter", maxEmailLen)
	}
	// ParseAddress also accepts "Name <a@b>" and comments; requiring the
	// parsed address to equal the input keeps it to a bare address.
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e {
		return "format email tidak valid (contoh: nama@instansi.go.id)"
	}
	return ""
}

// validateText refuses over-long values and control characters (newlines,
// tabs, ...): the value lands in a certificate subject and on the stamp.
func validateText(label, v string, max int) string {
	if !utf8.ValidString(v) {
		return label + " berisi karakter yang tidak valid"
	}
	if utf8.RuneCountInString(v) > max {
		return fmt.Sprintf("%s maksimal %d karakter", label, max)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return label + " tidak boleh berisi baris baru atau karakter kontrol"
		}
	}
	return ""
}

func validateNIP(nip string) string {
	if nip == "" {
		return ""
	}
	if len(nip) > maxNIPLen {
		return fmt.Sprintf("NIP maksimal %d digit", maxNIPLen)
	}
	for _, r := range nip {
		if r < '0' || r > '9' {
			return "NIP hanya boleh berisi angka"
		}
	}
	return ""
}

func firstProblem(msgs ...string) string {
	for _, m := range msgs {
		if m != "" {
			return m
		}
	}
	return ""
}
