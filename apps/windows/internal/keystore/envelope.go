// Package keystore protects the device ML-DSA-65 private key on Windows
// (Rencana V1 §12.1):
//
//	ML-DSA PKCS#8
//	  -> AES-256-GCM (fresh nonce)          encrypted key blob
//	random 32-byte wrapping key
//	  -> AES-256-GCM with an Argon2id(PIN)  (only when a PIN is set)
//	  -> Windows DPAPI CryptProtectData, CurrentUser scope
//	wrapped wrapping key
//
// The plaintext key exists only transiently in memory for a single sign/CSR
// operation. This file is platform-independent; DPAPI itself is in
// dpapi_windows.go (a stub errors on other platforms).
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// BlobVersion is bumped on any on-disk format change.
const BlobVersion = 1

// Options controls Protect/Open. A zero value means "no PIN".
type Options struct {
	PIN string
}

type kdfParams struct {
	Name    string `json:"name"` // "argon2id"
	TimeCst uint32 `json:"t"`
	MemKiB  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
}

// blob is the serialized form written to device-key.pqk.
type blob struct {
	Version   int        `json:"version"`
	CreatedAt time.Time  `json:"created_at"`
	KDF       *kdfParams `json:"kdf,omitempty"`        // present iff a PIN is used
	KeyNonce  []byte     `json:"key_nonce"`            // AES-GCM nonce over the PKCS#8
	KeyCT     []byte     `json:"key_ct"`               // AES-GCM(wrappingKey, pkcs8)
	WrapNonce []byte     `json:"wrap_nonce,omitempty"` // AES-GCM nonce over wrappingKey (PIN only)
	WrapCT    []byte     `json:"wrap_ct,omitempty"`    // AES-GCM(pinKey, wrappingKey) (PIN only)
	DPAPIBlob []byte     `json:"dpapi_blob"`           // DPAPI over (wrapCT || wrappingKey)
}

const (
	argonTime    = 3
	argonMemKiB  = 64 * 1024
	argonThreads = 4
	wrapKeyLen   = 32
	saltLen      = 16
)

func newGCM(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

func seal(key, plaintext []byte) (nonce, ct []byte, err error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, plaintext, nil), nil
}

func openSeal(key, nonce, ct []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, nil)
}

func pinKey(pin string, k kdfParams) []byte {
	return argon2.IDKey([]byte(pin), k.Salt, k.TimeCst, k.MemKiB, k.Threads, wrapKeyLen)
}

// Protect wraps a PKCS#8 ML-DSA-65 key into a .pqk blob. The wrapping key is
// random and never persisted in the clear; DPAPI (CurrentUser) binds the blob
// to this Windows account (Rencana V1 §12.1, §26).
func Protect(pkcs8 []byte, opt Options) ([]byte, error) {
	if len(pkcs8) == 0 {
		return nil, errors.New("keystore: empty key")
	}
	wrapKey := make([]byte, wrapKeyLen)
	if _, err := io.ReadFull(rand.Reader, wrapKey); err != nil {
		return nil, err
	}
	defer zero(wrapKey)

	keyNonce, keyCT, err := seal(wrapKey, pkcs8)
	if err != nil {
		return nil, err
	}

	b := blob{Version: BlobVersion, CreatedAt: time.Now().UTC(), KeyNonce: keyNonce, KeyCT: keyCT}

	toProtect := wrapKey
	if opt.PIN != "" {
		salt := make([]byte, saltLen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		kp := kdfParams{Name: "argon2id", TimeCst: argonTime, MemKiB: argonMemKiB, Threads: argonThreads, Salt: salt}
		pk := pinKey(opt.PIN, kp)
		defer zero(pk)
		wn, wct, err := seal(pk, wrapKey)
		if err != nil {
			return nil, err
		}
		b.KDF = &kp
		b.WrapNonce = wn
		b.WrapCT = wct
		toProtect = wct // DPAPI protects the PIN-wrapped wrapping key
	}

	dp, err := dpapiProtect(toProtect)
	if err != nil {
		return nil, fmt.Errorf("keystore: DPAPI protect: %w", err)
	}
	b.DPAPIBlob = dp

	return json.MarshalIndent(&b, "", "  ")
}

// Open reverses Protect, returning the PKCS#8 key. The caller must zero the
// result as soon as the single operation that needs it completes.
func Unprotect(data []byte, opt Options) ([]byte, error) {
	var b blob
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("keystore: parse blob: %w", err)
	}
	if b.Version != BlobVersion {
		return nil, fmt.Errorf("keystore: unsupported blob version %d", b.Version)
	}

	unprotected, err := dpapiUnprotect(b.DPAPIBlob)
	if err != nil {
		return nil, fmt.Errorf("keystore: DPAPI unprotect (wrong Windows account or tampered blob): %w", err)
	}
	defer zero(unprotected)

	var wrapKey []byte
	if b.KDF != nil {
		if opt.PIN == "" {
			return nil, errors.New("keystore: this key is PIN-protected")
		}
		pk := pinKey(opt.PIN, *b.KDF)
		defer zero(pk)
		wrapKey, err = openSeal(pk, b.WrapNonce, unprotected) // unprotected == wrapCT
		if err != nil {
			return nil, errors.New("keystore: wrong PIN")
		}
	} else {
		wrapKey = append([]byte(nil), unprotected...)
	}
	defer zero(wrapKey)

	pkcs8, err := openSeal(wrapKey, b.KeyNonce, b.KeyCT)
	if err != nil {
		return nil, errors.New("keystore: key blob is corrupt or tampered")
	}
	return pkcs8, nil
}

// zero best-effort wipes a secret slice.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
