//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"example.internal/pqc-pdf-sign/apps/windows/internal/updater"
	wails "github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
)

var updateMu sync.Mutex
var pendingRelease *updater.Release
var stagedRelease *updater.Release
var stagedDirectory string

func (a *App) CheckUpdate() (string, error) {
	if !updateMu.TryLock() {
		return "", errors.New("pembaruan sedang berlangsung")
	}
	defer updateMu.Unlock()
	r, err := updater.Check()
	if err != nil {
		return "", err
	}
	pendingRelease = r
	b, err := json.Marshal(r)
	return string(b), err
}

func (a *App) DownloadUpdate() error {
	if !updateMu.TryLock() {
		return errors.New("pembaruan sedang berlangsung")
	}
	defer updateMu.Unlock()
	r := pendingRelease
	if r == nil {
		return errors.New("tidak ada pembaruan")
	}
	last := -1
	dir, err := updater.DownloadProgress(*r, func(pct int) {
		if pct != last {
			last = pct
			wails.EventsEmit(a.ctx, "update-progress", pct)
		}
	})
	if err != nil {
		return err
	}
	if stagedDirectory != "" {
		_ = os.RemoveAll(stagedDirectory)
	}
	stagedDirectory = dir
	copyRelease := *r
	stagedRelease = &copyRelease
	return nil
}

func (a *App) InstallUpdate() error {
	if !updateMu.TryLock() {
		return errors.New("pembaruan sedang berlangsung")
	}
	defer updateMu.Unlock()
	r, dir := stagedRelease, stagedDirectory
	if r == nil || dir == "" {
		return errors.New("unduh pembaruan terlebih dahulu")
	}
	b, err := os.ReadFile(filepath.Join(dir, "update.exe"))
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if int64(len(b)) != r.Size || hex.EncodeToString(h[:]) != r.SHA256 {
		return errors.New("berkas unduhan berubah; unduh ulang pembaruan")
	}
	target, err := os.Executable()
	if err != nil {
		return err
	}
	// Check write access before quitting (installed under Program Files may need
	// an administrator-managed installation instead).
	probe, err := os.CreateTemp(filepath.Dir(target), ".pqsign-write-check-")
	if err != nil {
		return fmt.Errorf("folder aplikasi tidak dapat ditulis: %w", err)
	}
	probe.Close()
	os.Remove(probe.Name())
	helper := filepath.Join(dir, "helper.exe")
	_ = os.Remove(helper) // allow retry if launching the helper previously failed
	if err = copyUpdateFile(target, helper); err != nil {
		return err
	}
	cmd := exec.Command(helper, "--apply-update", strconv.Itoa(os.Getpid()), target, r.SHA256)
	if err = cmd.Start(); err != nil {
		return err
	}
	wails.Quit(a.ctx)
	return nil
}

func copyUpdateFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	ce := out.Close()
	if err != nil {
		return err
	}
	return ce
}

// Runs a copy of the OLD executable as a helper, never the downloaded binary
// before checksum validation. Wait for the parent, retain a rollback copy,
// replace in place so existing shortcuts and the user's vault keep working.
func applyUpdate() error {
	if len(os.Args) != 5 {
		return errors.New("invalid update arguments")
	}
	pid, err := strconv.Atoi(os.Args[2])
	if err != nil {
		return err
	}
	target := os.Args[3]
	if !filepath.IsAbs(target) || !strings.EqualFold(filepath.Ext(target), ".exe") {
		return errors.New("invalid target")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	stage := filepath.Join(filepath.Dir(self), "update.exe")
	b, err := os.ReadFile(stage)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != os.Args[4] {
		return errors.New("checksum mismatch")
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return err
	}
	// ERROR_INVALID_PARAMETER means the parent has already exited.
	if err == nil {
		defer windows.CloseHandle(handle)
		status, waitErr := windows.WaitForSingleObject(handle, 120000)
		if waitErr != nil {
			return waitErr
		}
		if status != windows.WAIT_OBJECT_0 {
			return errors.New("aplikasi belum ditutup")
		}
	}
	next, err := os.CreateTemp(filepath.Dir(target), ".pqsign-next-*.exe")
	if err != nil {
		return err
	}
	name := next.Name()
	defer os.Remove(name)
	if _, err = next.Write(b); err != nil {
		next.Close()
		return err
	}
	if err = next.Close(); err != nil {
		return err
	}
	backup := target + ".previous"
	// A previous backup belongs to this updater; remove only that exact file.
	if err = os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = os.Rename(target, backup); err != nil {
		return err
	}
	if err = os.Rename(name, target); err != nil {
		os.Rename(backup, target)
		return err
	}
	if err = exec.Command(target).Start(); err != nil {
		os.Remove(target)
		os.Rename(backup, target)
		return err
	}
	os.Remove(stage)
	return nil
}
