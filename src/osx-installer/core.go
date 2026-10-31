package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// installerVersion is shown in the dialog titles; raise it with every change.
const installerVersion = "1.02"

const defaultURL = "https://github.com/ewaldj/mautg/raw/main/OSX_Version/mautg-mac.zip"

// pkgFiles are replaced on install and removed on uninstall; logs and
// mautg-args.txt in the same folder are never touched.
var pkgFiles = []string{"mautg.app", "python-aarch64", "python-x86_64", "mautg.py", "README.md"}

func installURL() string {
	if u := os.Getenv("MAUTG_INSTALL_URL"); u != "" {
		return u
	}
	return defaultURL
}

// userDir / systemDir are the two install locations.
func userDir() string   { h, _ := os.UserHomeDir(); return filepath.Join(h, "Applications", "mautg") }
func systemDir() string { return "/Applications/mautg" }

func installedIn(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "mautg.app", "Contents", "MacOS", "mautg"))
	return err == nil
}

// installFrom unpacks the package zip and copies the package files into dir
// (dir must exist and be writable).
func installFrom(zipFile, dir string) error {
	tmp, err := os.MkdirTemp("", "mautg-inst-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := extractZip(zipFile, tmp, nil); err != nil {
		return err
	}
	for _, n := range []string{filepath.Join("mautg.app", "Contents", "MacOS", "mautg"), "mautg.py"} {
		if fi, err := os.Stat(filepath.Join(tmp, n)); err != nil || fi.IsDir() || fi.Size() == 0 {
			return fmt.Errorf("invalid package: %s missing", n)
		}
	}
	for _, n := range pkgFiles {
		src := filepath.Join(tmp, n)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(dir, n)
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
		if out, err := exec.Command("cp", "-R", src, dst).CombinedOutput(); err != nil {
			return fmt.Errorf("copy %s: %v %s", n, err, out)
		}
	}
	// the downloaded files must not stay quarantined (Gatekeeper); best effort
	exec.Command("xattr", "-dr", "com.apple.quarantine", dir).Run()
	filepath.Walk(filepath.Join(dir, "mautg.app", "Contents", "MacOS"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			os.Chmod(p, 0755)
		}
		return nil
	})
	return nil
}

// uninstall removes the package files of dir; the folder only if nothing else is left.
func uninstall(dir string) error {
	for _, n := range pkgFiles {
		if err := os.RemoveAll(filepath.Join(dir, n)); err != nil {
			return err
		}
	}
	os.Remove(dir)
	return nil
}
