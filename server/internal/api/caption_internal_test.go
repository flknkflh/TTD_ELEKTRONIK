package api

import (
	"strings"
	"testing"
)

func lineTexts(ls []captionLine) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.text
	}
	return out
}

// TestCaptionLines_LetterFieldsLeadTheBlock: the letter number and subject are
// drawn above the signer block, in that order.
func TestCaptionLines_LetterFieldsLeadTheBlock(t *testing.T) {
	got := lineTexts(captionLines(captionData{
		LetterNo:      "B-1/UM/IX/2026",
		LetterSubject: "Undangan Rapat Koordinasi",
		FullName:      "Gita Aurora",
		Position:      "Kepala Biro",
		NIP:           "19800101",
		IssuedPlace:   "Bandung",
		DateText:      "8 September 2026",
	}))
	want := []string{
		"Nomor: B-1/UM/IX/2026",
		"Perihal: Undangan Rapat Koordinasi",
		"Ditandatangani secara elektronik oleh:",
		"Gita Aurora",
		"Kepala Biro",
		"NIP. 19800101",
		"Dikeluarkan di Bandung",
		"Pada tanggal 8 September 2026",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("caption lines\n got: %v\nwant: %v", got, want)
	}
}

// TestCaptionLines_EmptyLetterFieldsSkipped: both fields are optional, and an
// empty or whitespace-only value must not leave a stray "Nomor: " line.
func TestCaptionLines_EmptyLetterFieldsSkipped(t *testing.T) {
	got := lineTexts(captionLines(captionData{
		LetterNo: "   ", LetterSubject: "",
		FullName: "Gita Aurora", DateText: "8 September 2026",
	}))
	for _, l := range got {
		if strings.HasPrefix(l, "Nomor:") || strings.HasPrefix(l, "Perihal:") {
			t.Fatalf("empty letter fields must be skipped, got %v", got)
		}
	}
	if got[0] != "Ditandatangani secara elektronik oleh:" {
		t.Fatalf("signer block should lead when no letter fields: %v", got)
	}
}

// TestCaptionLines_HeaderFlaggedNotPositional: drawCaption picks the small
// header face off the flag. With a letter number present the lead-in is no
// longer line 0, so only the flag can identify it.
func TestCaptionLines_HeaderFlaggedNotPositional(t *testing.T) {
	ls := captionLines(captionData{
		LetterNo: "B-1/UM/IX/2026", FullName: "Gita Aurora",
	})
	var headers []int
	for i, l := range ls {
		if l.header {
			headers = append(headers, i)
		}
	}
	if len(headers) != 1 {
		t.Fatalf("expected exactly one header line, got %v in %v", headers, lineTexts(ls))
	}
	if ls[headers[0]].text != "Ditandatangani secara elektronik oleh:" {
		t.Fatalf("wrong line flagged as header: %q", ls[headers[0]].text)
	}
	if headers[0] == 0 {
		t.Fatal("with a letter number the header must not be the first line (guards the old i==0 heuristic)")
	}
}
