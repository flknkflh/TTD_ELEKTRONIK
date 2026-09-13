package api_test

import (
	"net/http"
	"testing"

	"example.internal/pqc-pdf-sign/core/signing"
	"example.internal/pqc-pdf-sign/core/testpdf"
	"example.internal/pqc-pdf-sign/server/internal/store"
)

// The letter number and subject sent with /stamp are kept with the signature
// and shown wherever the record is: the public API and the QR landing page.
func TestLetterFieldsReachThePublicRecord(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	w := e.do("POST", "/api/v1/signatures/"+pid+"/stamp?x=0.6&y=0.78&w=0.28"+
		"&letter_no=B-1%2FUM%2FIX%2F2026&letter_subject=Undangan+Rapat+Koordinasi", user, testpdf.Sample())
	mustCode(t, w, http.StatusOK)
	res, err := signing.SignPDF(w.Body.Bytes(), d.keyPEM, d.chainPEM, signing.Options{SignerName: "Tester", PublicID: pid})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, res.SignedPDF), http.StatusOK)

	rec := jbody(t, e.do("GET", "/api/v1/public/signatures/"+pid, "", nil))
	if rec["letter_no"] != "B-1/UM/IX/2026" || rec["letter_subject"] != "Undangan Rapat Koordinasi" {
		t.Fatalf("letter fields = %q / %q", rec["letter_no"], rec["letter_subject"])
	}
	page := e.do("GET", "/v/"+pid, "", nil).Body.String()
	for _, want := range []string{"Nomor surat", "B-1/UM/IX/2026", "Perihal surat", "Undangan Rapat Koordinasi"} {
		if !contains(page, want) {
			t.Errorf("QR page lacks %q", want)
		}
	}
}

// A letter field with a line break would split the stamp caption; refuse it.
func TestStampRejectsControlCharsInLetterFields(t *testing.T) {
	e := newEnv(t)
	user := e.account("user@test", store.RoleUser)
	admin := e.account("admin@test", store.RoleAdmin)
	d := e.enrolledDevice(user, admin, "Laptop")
	pid := e.reserve(user, d.id)

	w := e.do("POST", "/api/v1/signatures/"+pid+"/stamp?x=0.6&y=0.78&w=0.28&letter_no=B-1%0AUM", user, testpdf.Sample())
	mustCode(t, w, http.StatusBadRequest)
	if !contains(w.Body.String(), "Nomor surat") {
		t.Fatalf("reason = %s", w.Body.String())
	}
}
