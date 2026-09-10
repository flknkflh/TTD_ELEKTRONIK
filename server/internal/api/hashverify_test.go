package api_test

import (
	"net/http"
	"strings"
	"testing"

	"example.internal/pqc-pdf-sign/core/hashutil"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// submitted runs the full flow and returns the exact bytes the server accepted
// and recorded for pid.
func (e *env) submitted(userTok string, d device, pid string) []byte {
	e.t.Helper()
	signed := e.stampAndSign(userTok, d, pid)
	mustCode(e.t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", userTok, signed), http.StatusOK)
	return signed
}

func verifyTop(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	v, _ := body["verification"].(map[string]any)
	if v == nil {
		t.Fatalf("no verification object in %v", body)
	}
	return v
}

// errText flattens the verification errors into one searchable string.
func errText(v map[string]any) string {
	var b strings.Builder
	for _, e := range v["errors"].([]any) {
		b.WriteString(e.(string))
		b.WriteByte('\n')
	}
	return b.String()
}

// TestPublicVerify_HashMatchOnGenuineFile is the control for the two tests
// below: the exact bytes the server recorded must come back matching + valid.
func TestPublicVerify_HashMatchOnGenuineFile(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	signed := e.submitted(user, d, pid)

	body := jbody(t, e.verifyMultipart(signed))
	if body["hash_match"] != true {
		t.Fatalf("genuine file must match the stored hash, got %v", body["hash_match"])
	}
	if got := body["uploaded_sha512"]; got != hashutil.CalculateSHA512(signed) {
		t.Fatalf("uploaded_sha512 = %v", got)
	}
	if v := verifyTop(t, body); v["valid"] != true {
		t.Fatalf("genuine file must verify: %v", v["errors"])
	}
}

// TestPublicVerify_HashMismatchRejected isolates the stored-hash layer. A
// single trailing newline keeps the ML-DSA signature valid over its own
// /ByteRange AND keeps the coverage check happy (whitespace is benign), so
// nothing but the hash comparison can catch it -- yet these are not the bytes
// the server issued, so the answer must be "not valid".
func TestPublicVerify_HashMismatchRejected(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	signed := e.submitted(user, d, pid)

	altered := append(append([]byte(nil), signed...), '\n')
	body := jbody(t, e.verifyMultipart(altered))

	if body["registered"] != true {
		t.Fatalf("record should still be found by public id: %v", body)
	}
	if body["hash_match"] != false {
		t.Fatalf("hash_match must be false for altered bytes, got %v", body["hash_match"])
	}
	v := verifyTop(t, body)
	if v["valid"] != false {
		t.Fatalf("an accepted-tier record with a hash mismatch must be reported invalid")
	}
	if !contains(errText(v), "SHA-512") {
		t.Fatalf("expected an SHA-512 mismatch reason, got %v", v["errors"])
	}
}

// TestVerifyHashEndpoint covers the hash-only contract end to end.
func TestVerifyHashEndpoint(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)
	signed := e.submitted(user, d, pid)
	sum := hashutil.CalculateSHA512(signed)

	t.Run("match returns the record", func(t *testing.T) {
		w := e.do("POST", "/api/v1/public/verify-hash", "",
			map[string]string{"public_id": pid, "sha512": sum})
		mustCode(t, w, http.StatusOK)
		b := jbody(t, w)
		if b["match"] != true {
			t.Fatalf("match = %v", b["match"])
		}
		if b["verification_status"] != store.VerificationAccepted {
			t.Fatalf("verification_status = %v", b["verification_status"])
		}
		rec, _ := b["record"].(map[string]any)
		if rec == nil || rec["public_id"] != pid {
			t.Fatalf("record missing or wrong: %v", b["record"])
		}
	})

	t.Run("uppercase hex still matches", func(t *testing.T) {
		w := e.do("POST", "/api/v1/public/verify-hash", "",
			map[string]string{"public_id": pid, "sha512": strings.ToUpper(sum)})
		mustCode(t, w, http.StatusOK)
		if jbody(t, w)["match"] != true {
			t.Fatal("hex comparison must be case-insensitive")
		}
	})

	t.Run("one flipped hex char does not match and leaks no record", func(t *testing.T) {
		bad := []byte(sum)
		if bad[0] == '0' {
			bad[0] = '1'
		} else {
			bad[0] = '0'
		}
		w := e.do("POST", "/api/v1/public/verify-hash", "",
			map[string]string{"public_id": pid, "sha512": string(bad)})
		mustCode(t, w, http.StatusOK)
		b := jbody(t, w)
		if b["match"] != false {
			t.Fatalf("match = %v", b["match"])
		}
		if _, ok := b["record"]; ok {
			t.Fatal("a non-matching hash must not return the record")
		}
	})

	t.Run("malformed hash is a 400", func(t *testing.T) {
		for _, bad := range []string{"", "abc", strings.Repeat("z", 128), sum + "0"} {
			w := e.do("POST", "/api/v1/public/verify-hash", "",
				map[string]string{"public_id": pid, "sha512": bad})
			mustCode(t, w, http.StatusBadRequest)
		}
	})

	t.Run("unknown public id is a 404", func(t *testing.T) {
		w := e.do("POST", "/api/v1/public/verify-hash", "",
			map[string]string{"public_id": "sig_does_not_exist", "sha512": sum})
		mustCode(t, w, http.StatusNotFound)
	})
}

// TestStrictVerify_RejectsAppendedBytes: the same coverage rule must also
// refuse a tampered document at submission time, not only at public verify.
func TestStrictVerify_RejectsAppendedBytes(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	signed := e.stampAndSign(user, d, pid)
	tampered := append(append([]byte(nil), signed...), []byte("\n99 0 obj<<>>endobj\n")...)

	w := e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, tampered)
	mustCode(t, w, http.StatusUnprocessableEntity)
	if !contains(w.Body.String(), "diubah setelah ditandatangani") {
		t.Fatalf("reason = %s", w.Body.String())
	}
}

// TestStamp_LetterFields: the per-signature letter number and subject ride in
// as query params and must be accepted alongside reason/issued_place.
func TestStamp_LetterFields(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	w := e.do("POST", "/api/v1/signatures/"+pid+
		"/stamp?x=0.6&y=0.78&w=0.28&reason=Persetujuan&issued_place=Bandung"+
		"&letter_no=B-1%2FUM%2FIX%2F2026&letter_subject=Undangan+Rapat+Koordinasi",
		user, testpdf.Sample())
	mustCode(t, w, http.StatusOK)
	if w.Header().Get("X-QR-Stamp") != "applied" {
		t.Fatalf("stamp not applied: %s", w.Header().Get("X-QR-Stamp"))
	}
	if !contains(w.Body.String()[:5], "%PDF-") {
		t.Fatalf("response is not a PDF")
	}
}
