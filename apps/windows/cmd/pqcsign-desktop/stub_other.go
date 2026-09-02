//go:build !windows

// The Wails GUI client is Windows-only (DPAPI, WebView2). This stub keeps the
// package buildable on CI runners so `go build ./...` and `go vet ./...`
// succeed cross-platform.
package main

import "fmt"

func main() {
	fmt.Println("pqcsign-desktop is Windows-only; build with: wails build -platform windows/amd64")
}
