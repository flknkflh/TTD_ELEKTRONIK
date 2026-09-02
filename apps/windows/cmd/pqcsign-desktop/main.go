//go:build windows

// Command pqcsign-desktop is the PQC PDF Sign V1 Windows client
// (Rencana V1 §20). Wails v2 shell; the seven pages (Login, Register device,
// Certificate status, Sign PDF, Verify PDF, History, Security settings) are
// HTML in frontend/ and each button calls one bound App method (app.go),
// which is a thin pass-through to internal/appcore.
//
// Build:  wails build -platform windows/amd64 -clean
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title:                    "PQC PDF Sign",
		Width:                    980,
		Height:                   720,
		MinWidth:                 720,
		MinHeight:                560,
		AssetServer:              &assetserver.Options{Assets: assets},
		OnStartup:                app.startup,
		Bind:                     []any{app},
		EnableDefaultContextMenu: false,
	})
	if err != nil {
		panic(err)
	}
}
