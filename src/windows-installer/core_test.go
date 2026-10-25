package main

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeZip(t *testing.T, path string, files map[string]string) {
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	for n, c := range files {
		w, _ := zw.Create(n)
		w.Write([]byte(c))
	}
	zw.Close()
	f.Close()
}

func TestExtractStripsTopFolder(t *testing.T) {
	d := t.TempDir()
	z := filepath.Join(d, "a.zip")
	makeZip(t, z, map[string]string{
		"mautg-windows/mautg.exe": "MZ", "mautg-windows/python/python.exe": "py",
		"mautg-windows/mautg.py": "#!/usr/bin/env python3\nVERSION = '3.99'\n"})
	dst := filepath.Join(d, "out")
	if err := extractZip(z, dst, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"mautg.exe", "python/python.exe", "mautg.py"} {
		if _, err := os.Stat(filepath.Join(dst, filepath.FromSlash(p))); err != nil {
			t.Fatal(p, err)
		}
	}
	if pyVersion(dst, "mautg.py") != "3.99" || pyVersion(dst, "none.py") != "" {
		t.Fatal("version")
	}
}

func TestExtractRefusesZipSlip(t *testing.T) {
	d := t.TempDir()
	z := filepath.Join(d, "evil.zip")
	makeZip(t, z, map[string]string{"mautg-windows/../../evil.txt": "x"})
	dst := filepath.Join(d, "a", "b")
	if err := extractZip(z, dst, nil); err == nil {
		t.Fatal("zip slip accepted")
	}
	if _, err := os.Stat(filepath.Join(d, "evil.txt")); err == nil {
		t.Fatal("file written outside")
	}
	bad := filepath.Join(d, "bad.zip")
	os.WriteFile(bad, []byte("not a zip"), 0644)
	if extractZip(bad, filepath.Join(d, "c"), nil) == nil {
		t.Fatal("garbage accepted")
	}
}

func TestDownloadAndOverwriteKeepsUserFiles(t *testing.T) {
	d := t.TempDir()
	z := filepath.Join(d, "src.zip")
	makeZip(t, z, map[string]string{"mautg-windows/mautg.py": "VERSION = '1'\n", "mautg-windows/mautg.exe": "new"})
	zb, _ := os.ReadFile(z)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok.zip" {
			w.Write(zb)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	dl := filepath.Join(d, "dl.zip")
	var last int64
	if err := downloadFile(srv.URL+"/ok.zip", dl, func(done, total int64) { last = done }); err != nil || last != int64(len(zb)) {
		t.Fatal(err, last)
	}
	if downloadFile(srv.URL+"/missing.zip", filepath.Join(d, "x.zip"), nil) == nil {
		t.Fatal("404 accepted")
	}
	dst := filepath.Join(d, "inst")
	os.MkdirAll(dst, 0755)
	os.WriteFile(filepath.Join(dst, "mautg.exe"), []byte("old"), 0644)
	os.WriteFile(filepath.Join(dst, "mautg-args.txt"), []byte("1.1.1.1\n"), 0644)
	if err := extractZip(dl, dst, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "mautg.exe")); string(b) != "new" {
		t.Fatal("not overwritten")
	}
	if _, err := os.Stat(filepath.Join(dst, "mautg-args.txt")); err != nil {
		t.Fatal("user file lost")
	}
	// uninstall: program files go, user files stay, folder stays
	if errs := removeInstalled(dst, ""); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(filepath.Join(dst, "mautg.exe")); err == nil {
		t.Fatal("exe left")
	}
	if _, err := os.Stat(filepath.Join(dst, "mautg-args.txt")); err != nil {
		t.Fatal("args file removed")
	}
	os.Remove(filepath.Join(dst, "mautg-args.txt"))
	removeInstalled(dst, "")
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("empty folder kept")
	}
}

func TestShortcutScript(t *testing.T) {
	s := shortcutScript([]shortcut{{lnk: `C:\Users\o'neil\mautg\mautg.lnk`, target: `C:\p\mautg.exe`, workdir: `C:\p`, icon: `C:\p\mautg.exe,0`, desc: "d"}})
	if !strings.Contains(s, `'C:\Users\o''neil\mautg\mautg.lnk'`) || !strings.Contains(s, "CreateShortcut") || !strings.Contains(s, "$l.Save()") {
		t.Fatal(s)
	}
}
