package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	qrcode "github.com/skip2/go-qrcode"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Cover page (Rencana RB-2b). The client uploads the original PDF here right
// after reserving; the server appends one A4 page carrying the signer
// identity (taken from the verified account, so it cannot be spoofed) and a
// QR code to the verification URL, and returns the augmented PDF for the
// client to sign on-device. PDF composition lives here, not in core, so the
// Android AAR carries no extra dependency.

func (s *Server) hCoverPage(w http.ResponseWriter, r *http.Request) {
	c := claims(r)
	res, err := s.st.Reservation(r.PathValue("public_id"))
	if err != nil || res.AccountID != c.Sub {
		writeErr(w, http.StatusNotFound, "reservation not found")
		return
	}
	if res.Status == store.ReservationAccepted {
		writeErr(w, http.StatusConflict, "this reservation is already completed")
		return
	}
	acc, err := s.st.Account(c.Sub)
	if err != nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	dev, _ := s.st.Device(res.DeviceID)
	cert, err := s.st.CertificateByDevice(res.DeviceID)
	if err != nil || cert.Status != store.CertActive {
		writeErr(w, http.StatusConflict, "perangkat belum punya sertifikat aktif")
		return
	}

	body, err := readBody(r, s.cfg.MaxUploadBytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read")
		return
	}
	if err := withinLimit(body, s.cfg.MaxUploadBytes); err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "PDF exceeds the upload limit")
		return
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		writeErr(w, http.StatusUnprocessableEntity, "bukan berkas PDF")
		return
	}

	augmented, err := composeCoverPage(body, coverData{
		SignerName: firstNonEmpty(acc.FullName, acc.DisplayName, acc.Email),
		Org:        acc.Organization,
		Reason:     strings.TrimSpace(r.URL.Query().Get("reason")),
		Serial:     cert.Serial,
		Algorithm:  "ML-DSA-65",
		Profile:    "PAdES Baseline-B",
		PublicID:   res.PublicID,
		VerifyURL:  s.verifyURL(res.PublicID),
		DeviceName: dev.Label,
	})
	if err != nil {
		s.audit("cover.append", c, res.DeviceID, "fail", err.Error())
		writeErr(w, http.StatusUnprocessableEntity,
			"PDF ini tidak bisa diproses untuk halaman verifikasi (mungkin memakai fitur seperti "+
				"Content Credentials/C2PA, enkripsi, atau formulir yang kompleks). "+
				"Cetak ulang ke PDF (Print → Simpan sebagai PDF) lalu coba lagi.")
		return
	}
	s.audit("cover.append", c, res.DeviceID, "ok", res.PublicID)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("X-Cover-Page", "appended")
	_, _ = w.Write(augmented)
}

type coverData struct {
	SignerName, Org, Reason, Serial, Algorithm, Profile, PublicID, VerifyURL, DeviceName string
}

// sanitizePDF re-reads pdf WITHOUT pdfcpu's spec validation, removes the
// document-level attachment / associated-file entries (which is where a C2PA
// manifest lives, and what the validator most often rejects), and writes a
// clean copy. The signed document does not need those attachments.
func sanitizePDF(pdf []byte, conf *model.Configuration) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sanitize: %v", r)
		}
	}()
	ctx, err := pdfcpu.ReadContext(bytes.NewReader(pdf), conf)
	if err != nil {
		return nil, err
	}
	if root, e := ctx.Catalog(); e == nil {
		delete(root, "Names")
		delete(root, "AF")
	}
	var buf bytes.Buffer
	if err = pdfcpu.WriteContext(ctx, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// composeCoverPage returns pdf with one appended A4 page. Any failure is
// returned so hCoverPage can tell the user the PDF is unsupported.
func composeCoverPage(pdf []byte, d coverData) ([]byte, error) {
	conf := model.NewDefaultConfiguration() // ValidationRelaxed

	pageCount, err := pdfcpu.PageCount(bytes.NewReader(pdf), conf)
	if err != nil {
		// Real-world PDFs sometimes carry catalog entries pdfcpu's validator
		// rejects (e.g. a C2PA / Content Credentials manifest in the
		// EmbeddedFiles name tree). Read without validation, drop the
		// attachment tree, and try again on the laundered copy.
		if clean, cerr := sanitizePDF(pdf, conf); cerr == nil {
			if pc, perr := pdfcpu.PageCount(bytes.NewReader(clean), conf); perr == nil {
				pdf, pageCount, err = clean, pc, nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("gagal membaca PDF: %w", err)
		}
	}

	tmp, err := os.MkdirTemp("", "pqc-cover-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	qrContent := d.VerifyURL
	if qrContent == "" {
		qrContent = d.PublicID
	}
	var qrPath string
	if qrContent != "" {
		png, err := qrcode.Encode(qrContent, qrcode.Medium, 480)
		if err != nil {
			return nil, fmt.Errorf("encode QR: %w", err)
		}
		qrPath = filepath.Join(tmp, "qr.png")
		if err := os.WriteFile(qrPath, png, 0o600); err != nil {
			return nil, err
		}
	}

	desc, err := json.Marshal(buildCoverDoc(d, qrPath, pageCount+1))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := pdfcpu.Create(bytes.NewReader(pdf), bytes.NewReader(desc), &out, conf); err != nil {
		return nil, fmt.Errorf("menyisipkan halaman: %w", err)
	}
	return out.Bytes(), nil
}

// --- pdfcpu "create" JSON (tiny subset) ---

type cpFont struct {
	Name string  `json:"name"`
	Size float64 `json:"size,omitempty"`
}
type cpText struct {
	Value string     `json:"value"`
	Pos   [2]float64 `json:"pos"`
	Align string     `json:"align,omitempty"`
	Font  cpFont     `json:"font"`
}
type cpImage struct {
	Src    string     `json:"src"`
	Pos    [2]float64 `json:"pos"`
	Width  float64    `json:"width,omitempty"`
	Height float64    `json:"height,omitempty"`
}
type cpContent struct {
	Text  []cpText  `json:"text,omitempty"`
	Image []cpImage `json:"image,omitempty"`
}
type cpPage struct {
	Content cpContent `json:"content"`
}
type cpDoc struct {
	Paper  string            `json:"paper"`
	Origin string            `json:"origin"`
	Pages  map[string]cpPage `json:"pages"`
}

func buildCoverDoc(d coverData, qrPath string, pageNo int) cpDoc {
	body := cpFont{Name: "Helvetica", Size: 10}
	mono := cpFont{Name: "Courier", Size: 9}

	texts := []cpText{
		{Value: "LEMBAR VERIFIKASI TANDA TANGAN DIGITAL", Pos: [2]float64{-1, 792}, Align: "center",
			Font: cpFont{Name: "Helvetica-Bold", Size: 14}},
		{Value: "Dokumen ini ditandatangani secara elektronik dengan kriptografi", Pos: [2]float64{60, 748}, Font: body},
		{Value: "pasca-kuantum " + d.Algorithm + " (FIPS 204), profil " + d.Profile + ".", Pos: [2]float64{60, 732}, Font: body},
	}

	rows := [][2]string{
		{"Penanda tangan", d.SignerName},
		{"Instansi", d.Org},
		{"Perangkat", d.DeviceName},
		{"Alasan", d.Reason},
		{"No. sertifikat", d.Serial},
		{"ID verifikasi", d.PublicID},
	}
	y := 700.0
	for _, row := range rows {
		if strings.TrimSpace(row[1]) == "" {
			continue
		}
		texts = append(texts, cpText{
			Value: fmt.Sprintf("%-16s : %s", row[0], oneLine(row[1])),
			Pos:   [2]float64{60, y}, Font: mono,
		})
		y -= 18
	}
	if d.VerifyURL != "" {
		texts = append(texts,
			cpText{Value: "Pindai QR atau buka tautan berikut untuk memeriksa keaslian:", Pos: [2]float64{60, y - 16}, Font: body},
			cpText{Value: oneLine(d.VerifyURL), Pos: [2]float64{60, y - 34}, Font: mono},
		)
	}
	texts = append(texts, cpText{
		Value: "Keaslian & keutuhan dokumen diverifikasi dari berkas PDF ini; QR hanya mencocokkan catatan server.",
		Pos:   [2]float64{60, 64}, Font: cpFont{Name: "Helvetica", Size: 8},
	})

	content := cpContent{Text: texts}
	if qrPath != "" {
		content.Image = []cpImage{{
			Src: filepath.ToSlash(qrPath), Pos: [2]float64{372, 470}, Width: 160, Height: 160,
		}}
	}
	return cpDoc{
		Paper: "A4P", Origin: "LowerLeft",
		Pages: map[string]cpPage{fmt.Sprintf("%d", pageNo): {Content: content}},
	}
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}
