package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// QR stamp (Rencana RB-2c, supersedes the appended A4 cover page). The client
// uploads the original PDF right after reserving, together with where the
// signer dropped the QR box in the app (page + fractional rectangle). The
// server draws one "TTD Elektronik" stamp there — signer identity comes from
// the verified account, so it cannot be spoofed — and returns the stamped PDF
// for the client to sign on-device. PDF work stays here, not in core, so the
// Android AAR carries no extra dependency.

// stampPlacement is where the QR goes, as page-relative fractions with the
// origin at the TOP-left (matching how the app's preview canvas reports
// coordinates). X,Y is the top-left corner of the box; W is its width.
type stampPlacement struct {
	Page int
	X, Y float64
	W    float64
}

func (s *Server) hStamp(w http.ResponseWriter, r *http.Request) {
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

	place := stampPlacement{
		Page: atoiDefault(r.URL.Query().Get("page"), 0),
		X:    atofDefault(r.URL.Query().Get("x"), 0.62),
		Y:    atofDefault(r.URL.Query().Get("y"), 0.80),
		W:    atofDefault(r.URL.Query().Get("w"), 0.26),
	}

	stamped, err := stampQR(body, place, coverData{
		PublicID:  res.PublicID,
		VerifyURL: s.qrTarget(r, res.PublicID), // QR -> the server address the signer is logged into
	})
	if err != nil {
		s.audit("stamp.apply", c, res.DeviceID, "fail", err.Error())
		writeErr(w, http.StatusUnprocessableEntity,
			"PDF ini tidak bisa diproses untuk penempelan QR (mungkin memakai fitur seperti "+
				"Content Credentials/C2PA, enkripsi, atau formulir yang kompleks). "+
				"Cetak ulang ke PDF (Print → Simpan sebagai PDF) lalu coba lagi.")
		return
	}
	s.audit("stamp.apply", c, res.DeviceID, "ok", res.PublicID)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("X-QR-Stamp", "applied")
	_, _ = w.Write(stamped)
}

type coverData struct {
	PublicID, VerifyURL string
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

// stampQR draws one QR stamp onto pdf at the requested spot and returns the
// new bytes. The page count is unchanged. Any failure is returned so hStamp
// can tell the user the PDF is unsupported.
func stampQR(pdf []byte, p stampPlacement, d coverData) ([]byte, error) {
	conf := model.NewDefaultConfiguration() // ValidationRelaxed

	pageCount, err := pdfcpu.PageCount(bytes.NewReader(pdf), conf)
	if err != nil {
		// Real-world PDFs sometimes carry catalog entries pdfcpu's validator
		// rejects (e.g. a C2PA / Content Credentials manifest). Read without
		// validation, drop the attachment tree, and retry on the clean copy.
		if clean, cerr := sanitizePDF(pdf, conf); cerr == nil {
			if pc, perr := pdfcpu.PageCount(bytes.NewReader(clean), conf); perr == nil {
				pdf, pageCount, err = clean, pc, nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("gagal membaca PDF: %w", err)
		}
	}

	dims, err := pdfcpu.PageDims(bytes.NewReader(pdf), conf)
	if err != nil || len(dims) != pageCount {
		return nil, fmt.Errorf("gagal membaca ukuran halaman: %w", err)
	}

	page := p.Page
	if page < 1 || page > pageCount {
		page = pageCount // default: last page
	}
	pw, ph := dims[page-1].Width, dims[page-1].Height

	// Clamp the fractional box so it always lands fully on the page.
	wf := clampf(p.W, 0.06, 0.9)
	boxW := wf * pw
	boxH := boxW * stampAspect
	if boxH > ph*0.9 {
		boxH = ph * 0.9
		boxW = boxH / stampAspect
	}
	xf := clampf(p.X, 0, 1)
	yf := clampf(p.Y, 0, 1)
	llx := clampf(xf*pw, 0, math.Max(0, pw-boxW))
	// app coordinates have Y growing downward from the top; pdfcpu's origin is
	// bottom-left.
	lly := clampf(ph-yf*ph-boxH, 0, math.Max(0, ph-boxH))

	tmp, err := os.MkdirTemp("", "pqc-stamp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	qrContent := d.VerifyURL
	if qrContent == "" {
		qrContent = d.PublicID
	}
	png, err := buildStampPNG(qrContent, 900)
	if err != nil {
		return nil, fmt.Errorf("menyusun stempel: %w", err)
	}
	pngPath := filepath.Join(tmp, "stamp.png")
	if err := os.WriteFile(pngPath, png, 0o600); err != nil {
		return nil, err
	}

	desc, err := json.Marshal(cpDoc{
		Origin: "LowerLeft",
		Pages: map[string]cpPage{
			strconv.Itoa(page): {Content: cpContent{Image: []cpImage{{
				Src:    filepath.ToSlash(pngPath),
				Pos:    [2]float64{round2(llx), round2(lly)},
				Width:  round2(boxW),
				Height: round2(boxH),
			}}}},
		},
	})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := pdfcpu.Create(bytes.NewReader(pdf), bytes.NewReader(desc), &out, conf); err != nil {
		return nil, fmt.Errorf("menempel QR: %w", err)
	}
	return out.Bytes(), nil
}

// --- pdfcpu "create" JSON (tiny subset: one image on an existing page) ---

type cpImage struct {
	Src    string     `json:"src"`
	Pos    [2]float64 `json:"pos"`
	Width  float64    `json:"width,omitempty"`
	Height float64    `json:"height,omitempty"`
}
type cpContent struct {
	Image []cpImage `json:"image,omitempty"`
}
type cpPage struct {
	Content cpContent `json:"content"`
}
type cpDoc struct {
	Origin string            `json:"origin"`
	Pages  map[string]cpPage `json:"pages"`
}

func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

func atofDefault(s string, def float64) float64 {
	if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return v
	}
	return def
}

func clampf(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
