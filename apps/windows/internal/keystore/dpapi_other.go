//go:build !windows

package keystore

import "errors"

// errNoDPAPI keeps the package buildable off Windows (CI, cross-checks). The
// real client only ships for windows/amd64.
var errNoDPAPI = errors.New("keystore: Windows DPAPI is only available on Windows")

func dpapiProtect(in []byte) ([]byte, error)   { return nil, errNoDPAPI }
func dpapiUnprotect(in []byte) ([]byte, error) { return nil, errNoDPAPI }
