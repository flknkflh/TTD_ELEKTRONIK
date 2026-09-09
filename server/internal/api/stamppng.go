package api

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	qrcode "github.com/skip2/go-qrcode"
)

// stampAspect is height / width of the QR stamp. It is a bare square QR, so
// 1.0. The frontend uses the same ratio to size its draggable box.
const stampAspect = 1.0

// buildStampPNG renders a bare QR (no frame, no caption) with a small white
// quiet zone so it still scans when dropped onto a coloured area. widthPx
// controls resolution only — the PDF placement scales it to the box the user
// drew.
func buildStampPNG(qrContent string, widthPx int) ([]byte, error) {
	if widthPx < 240 {
		widthPx = 640
	}
	qc, err := qrcode.New(qrContent, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	qc.DisableBorder = true

	margin := widthPx / 16
	side := widthPx - 2*margin
	qrImg := qc.Image(side)

	img := image.NewRGBA(image.Rect(0, 0, widthPx, widthPx))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(margin, margin, margin+side, margin+side), qrImg, qrImg.Bounds().Min, draw.Over)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
