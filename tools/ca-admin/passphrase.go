package main

import (
	"fmt"
	"os"
	"strings"
)

// Passphrases per CA role. In a split CA the Root key and the Intermediate key
// are sealed under different passphrases, so the one an online issuer must
// hold cannot open a Root backup. Each role reads, in order:
//
//	PQC_CA_<ROLE>_PASSPHRASE        the value
//	PQC_CA_<ROLE>_PASSPHRASE_FILE   a file holding it (Docker secret, /dev/stdin)
//
// Commands that act on an issuer or a CA made by `init` also accept the legacy
// PQC_CA_PASSPHRASE. The split-CA commands do not, so the two keys can never
// silently end up under one passphrase. Issuer commands never read ROOT.

const (
	roleRoot         = "ROOT"
	roleIntermediate = "INTERMEDIATE"

	// minPassphraseLen guards the split-CA commands, which exist for production.
	minPassphraseLen = 16
)

// rolePassphrase returns the role-specific passphrase ("" when unset).
func rolePassphrase(role string) (string, error) {
	if v := os.Getenv("PQC_CA_" + role + "_PASSPHRASE"); v != "" {
		return v, nil
	}
	f := os.Getenv("PQC_CA_" + role + "_PASSPHRASE_FILE")
	if f == "" {
		return "", nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return "", fmt.Errorf("ca-admin: read PQC_CA_%s_PASSPHRASE_FILE: %w", role, err)
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" {
		return "", fmt.Errorf("ca-admin: PQC_CA_%s_PASSPHRASE_FILE is empty", role)
	}
	return v, nil
}

// passphraseFor is rolePassphrase with the legacy PQC_CA_PASSPHRASE fallback.
func passphraseFor(role string) (string, error) {
	v, err := rolePassphrase(role)
	if err != nil || v != "" {
		return v, err
	}
	return os.Getenv("PQC_CA_PASSPHRASE"), nil
}

// requireRolePassphrase is rolePassphrase for the split-CA commands: set,
// role-specific, and long enough.
func requireRolePassphrase(role string) (string, error) {
	v, err := rolePassphrase(role)
	if err != nil {
		return "", err
	}
	if len(v) < minPassphraseLen {
		return "", fmt.Errorf("ca-admin: set PQC_CA_%s_PASSPHRASE or PQC_CA_%s_PASSPHRASE_FILE (at least %d characters; PQC_CA_PASSPHRASE is not accepted here)",
			role, role, minPassphraseLen)
	}
	return v, nil
}

func operator() string { return os.Getenv("PQC_CA_OPERATOR") }
