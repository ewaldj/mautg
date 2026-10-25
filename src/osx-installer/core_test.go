package main

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pkgZip(t *testing.T) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range map[string]string{
		"mautg-mac/mautg.app/Contents/MacOS/mautg": "#!/bin/sh\n", "mautg-mac/mautg.app/Contents/Info.plist": "p",
		"mautg-mac/mautg.py": "#py", "mautg-mac/README.md": "r"} {
		w, _ := zw.Create(n)
		w.Write([]byte(c))
	}
	zw.Close()
	return buf.Bytes()
}

func TestInstallUninstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mautg")
	os.MkdirAll(dir, 0755)
	os.WriteFile(filepath.Join(dir, "mautg-args.txt"), []byte("keep"), 0644)
	os.WriteFile(filepath.Join(dir, "mautg.py"), []byte("old"), 0644)
	zf := filepath.Join(t.TempDir(), "p.zip")
	os.WriteFile(zf, pkgZip(t), 0644)
	if err := installFrom(zf, dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "mautg.py")); string(b) != "#py" {
		t.Fatal("not replaced")
	}
	if !installedIn(dir) {
		t.Fatal("not installed")
	}
	if err := uninstall(dir); err != nil {
		t.Fatal(err)
	}
	if installedIn(dir) {
		t.Fatal("still installed")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "mautg-args.txt")); string(b) != "keep" {
		t.Fatal("user data removed")
	}
	// invalid package
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("mautg-mac/x.txt")
	w.Write([]byte("x"))
	zw.Close()
	bad := filepath.Join(t.TempDir(), "b.zip")
	os.WriteFile(bad, buf.Bytes(), 0644)
	if installFrom(bad, t.TempDir()) == nil {
		t.Fatal("invalid package accepted")
	}
}

func TestFlow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(pkgZip(t)) }))
	defer srv.Close()
	var steps []string
	var opened, notes []string
	e := env{
		dialog: func(_ context.Context, s spec) (string, error) {
			b := steps[0]
			steps = steps[1:]
			return b, nil
		},
		choose: func(context.Context, string, string, []string) (string, error) { return labelUser, nil },
		toast:  func(string) {}, open: func(s string) { opened = append(opened, s) },
		note:  func(s string) { notes = append(notes, s) },
		admin: func(string) error { t.Fatal("admin not expected"); return nil },
	}
	fetch := func(d string) error { return downloadFile(srv.URL+"/mautg-mac.zip", d, nil) }
	steps = []string{"Install", "Start mautg"}
	flow(e, fetch)
	app := filepath.Join(home, "Applications", "mautg", "mautg.app")
	if len(opened) != 1 || opened[0] != app || !installedIn(userDir()) {
		t.Fatal(opened, notes)
	}
	steps = []string{"Uninstall"}
	flow(e, fetch)
	if installedIn(userDir()) || len(notes) != 1 || !strings.Contains(notes[0], "removed") {
		t.Fatal(notes)
	}
	steps = []string{"Uninstall"}
	flow(e, fetch)
	if len(notes) != 2 || !strings.Contains(notes[1], "not installed") {
		t.Fatal(notes)
	}
	steps = []string{"Cancel"}
	flow(e, fetch)
}

func TestBundledPython(t *testing.T) {
	d := t.TempDir()
	if bundledPython(d) {
		t.Fatal("not bundled")
	}
	os.MkdirAll(filepath.Join(d, "python-aarch64", "bin"), 0755)
	os.WriteFile(filepath.Join(d, "python-aarch64", "bin", "python3"), []byte("x"), 0755)
	if h := hints(d); strings.Contains(h, "python3") {
		t.Fatal(h)
	}
}
