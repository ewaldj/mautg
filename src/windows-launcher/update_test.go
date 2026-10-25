package main

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pyFile(ver string) string {
	return "#!/usr/bin/env python3\n# test script\nVERSION = \"" + ver + "\"\n" + strings.Repeat("# filler line\n", 300)
}

func TestVersionCompare(t *testing.T) {
	for _, c := range []struct {
		r, l string
		want bool
	}{{"1.89", "1.88", true}, {"1.88", "1.88", false}, {"1.9", "1.10", false}, {"1.10", "1.9", true},
		{"2.36", "", true}, {"", "1.1", false}, {"x", "1.1", false}, {"1.88", "1.88.1", false}, {"2.0", "1.99", true}} {
		if got := versionNewer(c.r, c.l); got != c.want {
			t.Fatalf("versionNewer(%q,%q)=%v", c.r, c.l, got)
		}
	}
	m := parseMversions("mautg.py 1.88\r\nother.py 1.14\nbogus\nx.py abc\nmautg-windows 1.00\n")
	if m["mautg.py"] != "1.88" || m["other.py"] != "1.14" || m["mautg-windows"] != "1.00" || len(m) != 3 {
		t.Fatal(m)
	}
}

func serve(t *testing.T, files map[string]string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[strings.TrimPrefix(r.URL.Path, "/")]; ok {
			w.Write([]byte(b))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/"
}

func TestUpdateFlow(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte(pyFile("1.88")), 0644)
	base := serve(t, map[string]string{"mversions": "mautg.py 1.89\n", "mautg.py": pyFile("1.89")})
	u, err := checkUpdate(d, base)
	if err != nil || u == nil || len(u.files) != 1 || u.files[0] != "mautg.py" || u.text() != "new: mautg 1.89" {
		t.Fatal(u, err)
	}
	if err := applyUpdate(d, base, u); err != nil {
		t.Fatal(err)
	}
	if pyVersion(d, "mautg.py") != "1.89" || pyVersion(d, "mautg.py.bak") != "" {
		t.Fatal("swap")
	}
	for _, n := range []string{"mautg.py.new", "mautg.py.bak"} {
		if _, err := os.Stat(filepath.Join(d, n)); err == nil {
			t.Fatal("file left: " + n)
		}
	}
	if u, err := checkUpdate(d, base); u != nil || err != nil { // now current
		t.Fatal(u, err)
	}
}

func TestUpdateRefusesBadDownload(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte(pyFile("1.88")), 0644)
	// announced 1.89, but the download has another VERSION: nothing may change
	base := serve(t, map[string]string{"mversions": "mautg.py 1.89\n", "mautg.py": pyFile("1.80")})
	u, err := checkUpdate(d, base)
	if err != nil || u == nil || len(u.files) != 1 {
		t.Fatal(u, err)
	}
	if err := applyUpdate(d, base, u); err == nil {
		t.Fatal("bad version accepted")
	}
	if pyVersion(d, "mautg.py") != "1.88" {
		t.Fatal("file changed")
	}
	for _, n := range []string{"mautg.py.new", "mautg.py.bak"} {
		if _, err := os.Stat(filepath.Join(d, n)); err == nil {
			t.Fatal("leftover " + n)
		}
	}
	// too small / html error page / http error
	for _, body := range []string{"<html>nope</html>", strings.Repeat("x", 5000)} {
		b := serve(t, map[string]string{"mversions": "mautg.py 1.89\n", "mautg.py": body})
		u, _ := checkUpdate(d, b)
		if applyUpdate(d, b, u) == nil {
			t.Fatal("bad body accepted: " + body[:5])
		}
	}
	b := serve(t, map[string]string{"mversions": "mautg.py 1.89\n"}) // mautg.py -> 404
	u, _ = checkUpdate(d, b)
	if applyUpdate(d, b, u) == nil || pyVersion(d, "mautg.py") != "1.88" {
		t.Fatal("404")
	}
	if _, err := checkUpdate(d, "http://127.0.0.1:1/"); err == nil { // offline
		t.Fatal("offline not reported")
	}
}

func TestUpdateMissingFile(t *testing.T) { // a deleted script is restored
	d := t.TempDir()
	base := serve(t, map[string]string{"mversions": "mautg.py 1.89\n", "mautg.py": pyFile("1.89")})
	u, err := checkUpdate(d, base)
	if err != nil || u == nil || u.files[0] != "mautg.py" {
		t.Fatal(u, err)
	}
	if err := applyUpdate(d, base, u); err != nil || pyVersion(d, "mautg.py") != "1.89" {
		t.Fatal(err)
	}
}

func fakeZip(t *testing.T, omit string) string {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mz := "MZ" + strings.Repeat("x", 1<<20+10)
	files := map[string]string{"mautg-windows/mautg.exe": mz, "mautg-windows/mautg.py": pyFile("1.99"),
		"mautg-windows/python/python.exe": "p"}
	for n, c := range files {
		if strings.HasSuffix(n, omit) && omit != "" {
			continue
		}
		w, _ := zw.Create(n)
		w.Write([]byte(c))
	}
	zw.Close()
	return buf.String()
}

func TestMversionsWindowsLine(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte(pyFile("1.88")), 0644)
	base := serve(t, map[string]string{"mversions": "mautg.py 1.88\nmautg-windows 9.00\n"})
	u, err := checkUpdate(d, base)
	if err != nil || u == nil || !u.full || u.fullV != "9.00" || !strings.Contains(u.text(), "mautg-windows 9.00") {
		t.Fatal(u, err)
	}
	base = serve(t, map[string]string{"mversions": "mautg.py 1.88\nmautg-windows " + launcherVersion + "\n"})
	if u, err := checkUpdate(d, base); u != nil || err != nil {
		t.Fatal(u, err)
	}
}

func TestApplyFull(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte(pyFile("1.88")), 0644)
	os.WriteFile(filepath.Join(d, argsFile), []byte("-port 9000"), 0644)
	base := serve(t, map[string]string{"Windows_Version/mautg-windows.zip": fakeZip(t, "")})
	if err := applyFull(d, base); err != nil {
		t.Fatal(err)
	}
	if pyVersion(d, "mautg.py") != "1.99" {
		t.Fatal("files not replaced")
	}
	if b, _ := os.ReadFile(filepath.Join(d, argsFile)); string(b) != "-port 9000" {
		t.Fatal("user file touched")
	}
	if _, err := os.Stat(filepath.Join(d, "python", "python.exe")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{stagingName, "mautg-windows-download.zip", "mautg.py.bak"} {
		if _, err := os.Stat(filepath.Join(d, n)); err == nil {
			t.Fatal("left: " + n)
		}
	}
	// incomplete package: nothing changes
	d2 := t.TempDir()
	os.WriteFile(filepath.Join(d2, "mautg.py"), []byte(pyFile("1.88")), 0644)
	base = serve(t, map[string]string{"Windows_Version/mautg-windows.zip": fakeZip(t, "python.exe")})
	if applyFull(d2, base) == nil || pyVersion(d2, "mautg.py") != "1.88" {
		t.Fatal("incomplete package accepted")
	}
}

func TestCleanOld(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "python"), 0755)
	for _, n := range []string{"mautg.exe.old", "python/x.dll.old", "keep.py"} {
		os.WriteFile(filepath.Join(d, n), []byte("x"), 0644)
	}
	cleanOld(d)
	for n, want := range map[string]bool{"mautg.exe.old": false, "python/x.dll.old": false, "keep.py": true} {
		if _, err := os.Stat(filepath.Join(d, n)); (err == nil) != want {
			t.Fatal(n)
		}
	}
}
