package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Platform independent part of the installer (testable on any OS).

// installerVersion is shown in the title bar; raise it with every change.
const installerVersion = "1.02"

const (
	defaultZipURL = "https://github.com/ewaldj/mautg/raw/main/Windows_Version/mautg-windows.zip"
	zipTopFolder  = "mautg-windows" // folder inside the zip that is stripped on extraction
	maxZipSize    = 400 << 20
)

// zipURL returns the download URL; MAUTG_INSTALL_URL overrides it (tests).
func zipURL() string {
	if u := os.Getenv("MAUTG_INSTALL_URL"); u != "" {
		return u
	}
	return defaultZipURL
}

// downloadFile saves url to dest; progress(done, total) is called while reading (total may be -1).
func downloadFile(url, dest string, progress func(done, total int64)) error {
	c := &http.Client{Timeout: 10 * time.Minute}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mautg-installer")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	var done int64
	last := time.Now()
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			done += int64(n)
			if done > maxZipSize {
				return fmt.Errorf("download too large")
			}
			if progress != nil && time.Since(last) > 150*time.Millisecond {
				progress(done, resp.ContentLength)
				last = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if progress != nil {
		progress(done, resp.ContentLength)
	}
	return nil
}

// extractZip unpacks zipPath into dst, dropping the leading zipTopFolder. Entries that would
// leave dst (zip slip) are refused. progress(i, n) after each entry.
func extractZip(zipPath, dst string, progress func(i, n int)) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("not a valid zip: %v", err)
	}
	defer zr.Close()
	root, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	for i, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		name = strings.TrimPrefix(name, zipTopFolder+"/")
		if name == "" || name == zipTopFolder || strings.HasPrefix(name, "/") {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			return fmt.Errorf("unsafe path in zip: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := writeZipEntry(f, target); err != nil {
			return err
		}
		if progress != nil {
			progress(i+1, len(zr.File))
		}
	}
	return nil
}

func writeZipEntry(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("%s: %v (is mautg still running? close it and try again)", filepath.Base(target), err)
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// installedItems are the program files the installer puts into the folder (and the
// uninstaller removes). The args file and the user's own files stay.
var installedItems = []string{"mautg.exe", "mautg.py", "README-WINDOWS.txt", "mautg-console.log", "uninstall.exe", "python"}

// removeInstalled deletes the program files from dir (errors collected) and the folder
// itself if it is empty afterwards. skip: a base name left alone (the running uninstaller).
func removeInstalled(dir, skip string) []error {
	var errs []error
	for _, n := range installedItems {
		if n == skip {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, n)); err != nil {
			errs = append(errs, err)
		}
	}
	for _, pat := range []string{"*.py.bak", "*.py.new"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, p := range m {
			os.Remove(p)
		}
	}
	os.Remove(dir) // only succeeds if empty
	return errs
}

// psQuote quotes s for a PowerShell single-quoted string.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type shortcut struct{ lnk, target, args, workdir, icon, desc string }

// shortcutScript is a PowerShell script that creates the folders of and the .lnk files.
func shortcutScript(items []shortcut) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop'\n$s = New-Object -ComObject WScript.Shell\n")
	for _, it := range items {
		b.WriteString("New-Item -ItemType Directory -Force -Path " + psQuote(filepath.Dir(it.lnk)) + " | Out-Null\n")
		b.WriteString("$l = $s.CreateShortcut(" + psQuote(it.lnk) + ")\n")
		b.WriteString("$l.TargetPath = " + psQuote(it.target) + "\n")
		b.WriteString("$l.Arguments = " + psQuote(it.args) + "\n")
		b.WriteString("$l.WorkingDirectory = " + psQuote(it.workdir) + "\n")
		b.WriteString("$l.IconLocation = " + psQuote(it.icon) + "\n")
		b.WriteString("$l.Description = " + psQuote(it.desc) + "\n$l.Save()\n")
	}
	return b.String()
}

// pyVersion reads VERSION from a script in dir ("" if missing).
func pyVersion(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	if len(b) > 4000 {
		b = b[:4000]
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "VERSION") {
			if i := strings.IndexAny(l, "'\""); i >= 0 {
				if j := strings.IndexAny(l[i+1:], "'\""); j >= 0 {
					return l[i+1 : i+1+j]
				}
			}
		}
	}
	return ""
}
