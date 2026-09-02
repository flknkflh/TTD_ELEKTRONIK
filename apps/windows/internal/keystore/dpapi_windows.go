//go:build windows

package keystore

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// cryptProtectUIForbidden | cryptProtectLocalMachine=0 -> CurrentUser scope,
// no UI (Rencana V1 §12.1: scope CurrentUser, not LocalMachine).
const cryptProtectUIForbidden = 0x1

var dpapiEntropy = []byte("pqc-pdf-sign/v1/device-key")

func blobFrom(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func toBytes(d windows.DataBlob) []byte {
	if d.Size == 0 || d.Data == nil {
		return nil
	}
	out := make([]byte, d.Size)
	copy(out, unsafe.Slice(d.Data, d.Size))
	return out
}

func dpapiProtect(in []byte) ([]byte, error) {
	inBlob := blobFrom(in)
	entBlob := blobFrom(dpapiEntropy)
	var out windows.DataBlob
	err := windows.CryptProtectData(&inBlob, nil, &entBlob, 0, nil, cryptProtectUIForbidden, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) //nolint:staticcheck
	return toBytes(out), nil
}

func dpapiUnprotect(in []byte) ([]byte, error) {
	inBlob := blobFrom(in)
	entBlob := blobFrom(dpapiEntropy)
	var out windows.DataBlob
	err := windows.CryptUnprotectData(&inBlob, nil, &entBlob, 0, nil, cryptProtectUIForbidden, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) //nolint:staticcheck
	return toBytes(out), nil
}
