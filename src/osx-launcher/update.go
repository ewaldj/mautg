package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Update check against the mversions file on GitHub; updates mautg.py.

const defaultUpdateBase = "https://raw.githubusercontent.com/ewaldj/mautg/refs/heads/main/"

// updateFiles are the files the updater maintains (name in mversions == file name).
var updateFiles = []string{"mautg.py"}

// launcherVersion is the version of this launcher package (mversions line "mautg-mac").
// A newer value there means: replace the whole package (launcher, script, python ...).
const launcherVersion = "1.02"

const pkgEntry = "mautg-mac" // name of the package line in mversions
const zipPath = "OSX_Version/mautg-mac.zip"

const (
	updMinSize = 2000    // smaller than this is not a valid script
	updMaxSize = 8 << 20 // larger is refused
)

// updateBase returns the download base URL; MAUTG_UPDATE_BASE overrides it (tests).
func updateBase() string {
	if b := os.Getenv("MAUTG_UPDATE_BASE"); b != "" {
		if !strings.HasSuffix(b, "/") {
			b += "/"
		}
		return b
	}
	return defaultUpdateBase
}

// parseMversions reads lines like "mautg.py 3.84" into name -> version.
func parseMversions(text string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && (strings.HasSuffix(f[0], ".py") || f[0] == pkgEntry) && versionTuple(f[1]) != nil {
			m[f[0]] = f[1]
		}
	}
	return m
}

// versionTuple parses "3.84" into numbers, nil if it is not a version.
func versionTuple(v string) []int {
	if v == "" {
		return nil
	}
	var t []int
	for _, p := range strings.Split(strings.TrimSpace(v), ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		t = append(t, n)
	}
	return t
}

// versionNewer is true if remote is a higher version than local ("" = not installed).
func versionNewer(remote, local string) bool {
	r := versionTuple(remote)
	if r == nil {
		return false
	}
	l := versionTuple(local)
	if l == nil {
		return true
	}
	for i := 0; i < len(r) || i < len(l); i++ {
		var a, b int
		if i < len(r) {
			a = r[i]
		}
		if i < len(l) {
			b = l[i]
		}
		if a != b {
			return a > b
		}
	}
	return false
}

// pyVersion returns VERSION of a script in dir ("" if the file or the line is missing).
func pyVersion(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return scriptVersion(b)
}

// scriptVersion finds the VERSION = '...' line in the first 4000 bytes of a script.
func scriptVersion(b []byte) string {
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

// updInfo is the result of a check: file name -> remote version, only newer ones.
type updInfo struct {
	full  bool              // the whole package is replaced (mautg is older than mversions)
	fullV string            // its version
	files []string          // names in updateFiles order
	vers  map[string]string // name -> remote version
	old   map[string]string // name -> installed version
}

func httpGet(url string, limit int64) ([]byte, error) {
	c := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mautg-launcher")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: too large", url)
	}
	return b, nil
}

// checkUpdate compares the installed scripts in dir with mversions at base.
// Returns nil if everything is current.
func checkUpdate(dir, base string) (*updInfo, error) {
	b, err := httpGet(base+"mversions", 64<<10)
	if err != nil {
		return nil, err
	}
	rem := parseMversions(string(b))
	if len(rem) == 0 {
		return nil, fmt.Errorf("mversions: no versions found")
	}
	u := &updInfo{vers: map[string]string{}, old: map[string]string{}}
	if versionNewer(rem[pkgEntry], launcherVersion) {
		u.full, u.fullV = true, rem[pkgEntry]
		return u, nil
	}
	for _, n := range updateFiles {
		loc := pyVersion(dir, n)
		if versionNewer(rem[n], loc) {
			u.files = append(u.files, n)
			u.vers[n] = rem[n]
			u.old[n] = loc
		}
	}
	if len(u.files) == 0 {
		return nil, nil
	}
	return u, nil
}

// applyUpdate downloads the files of u, verifies them (size, python header, VERSION
// line equal to the announced one) and only then replaces the installed files; the
// previous ones are only kept while swapping (rollback) and deleted afterwards.
// Nothing is changed if any step fails.
// The caller stops mautg.py before and restarts it after.
func applyUpdate(dir, base string, u *updInfo) error {
	data := map[string][]byte{}
	for _, n := range u.files {
		b, err := httpGet(base+n, updMaxSize)
		if err != nil {
			return err
		}
		if len(b) < updMinSize {
			return fmt.Errorf("%s: download too small (%d bytes)", n, len(b))
		}
		head := string(b[:min(len(b), 200)])
		if !strings.HasPrefix(head, "#!") && !strings.Contains(head, "python") && !strings.HasPrefix(head, "\"\"\"") {
			return fmt.Errorf("%s: not a python script", n)
		}
		if v := scriptVersion(b); v != u.vers[n] {
			return fmt.Errorf("%s: version %q in the download, expected %q", n, v, u.vers[n])
		}
		data[n] = b
	}
	// write all temp files first
	var tmps []string
	cleanup := func() {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	for _, n := range u.files {
		t := filepath.Join(dir, n+".new")
		if err := os.WriteFile(t, data[n], 0644); err != nil {
			cleanup()
			return err
		}
		tmps = append(tmps, t)
	}
	// swap; on a failure put the already swapped files back
	var done []string
	for _, n := range u.files {
		cur := filepath.Join(dir, n)
		bak := cur + ".bak"
		hadOld := false
		if _, err := os.Stat(cur); err == nil {
			hadOld = true
			os.Remove(bak)
			if err := os.Rename(cur, bak); err != nil {
				rollback(dir, done)
				cleanup()
				return err
			}
		}
		if err := os.Rename(cur+".new", cur); err != nil {
			if hadOld {
				os.Rename(bak, cur)
			}
			rollback(dir, done)
			cleanup()
			return err
		}
		done = append(done, n)
	}
	for _, n := range updateFiles { // no backup files are left behind (also old ones)
		os.Remove(filepath.Join(dir, n+".bak"))
	}
	return nil
}

func rollback(dir string, names []string) {
	for _, n := range names {
		cur := filepath.Join(dir, n)
		if _, err := os.Stat(cur + ".bak"); err == nil {
			os.Remove(cur)
			os.Rename(cur+".bak", cur)
		}
	}
}

// updText is the short status text for the launcher window.
func (u *updInfo) text() string {
	if u.full {
		return "new: mautg-mac " + u.fullV
	}
	var p []string
	for _, n := range u.files {
		p = append(p, strings.TrimSuffix(n, ".py")+" "+u.vers[n])
	}
	return "new: " + strings.Join(p, ", ")
}

// requiredInPackage must exist in a downloaded package before anything is replaced.
var requiredInPackage = []string{
	filepath.Join("mautg.app", "Contents", "MacOS", "mautg"),
	filepath.Join("mautg.app", "Contents", "MacOS", "mautg-arm64"),
	filepath.Join("mautg.app", "Contents", "MacOS", "mautg-amd64"),
	"mautg.py"}

const stagingName = ".mautg-update"

// applyFull downloads mautg-mac.zip, unpacks it to a staging folder, checks it and
// then moves every file over the installation in dir. A file that is locked (the running
// mautg binary) is renamed to <name>.old first - cleanOld() removes those at
// the next start. Logs and the args file are not part of the package and stay.
func applyFull(dir, base string) error {
	tmp := filepath.Join(dir, "mautg-mac-download.zip")
	defer os.Remove(tmp)
	if err := downloadFile(base+zipPath, tmp, nil); err != nil {
		return err
	}
	stage := filepath.Join(dir, stagingName)
	os.RemoveAll(stage)
	defer os.RemoveAll(stage)
	if err := extractZip(tmp, stage, nil); err != nil {
		return err
	}
	for _, n := range requiredInPackage {
		if fi, err := os.Stat(filepath.Join(stage, n)); err != nil || fi.IsDir() || fi.Size() == 0 {
			return fmt.Errorf("package is incomplete: %s missing", n)
		}
	}
	for _, n := range []string{"mautg-arm64", "mautg-amd64"} {
		b, err := os.ReadFile(filepath.Join(stage, "mautg.app", "Contents", "MacOS", n))
		// 64-bit little-endian Mach-O magic cf fa ed fe
		if err != nil || len(b) < 1<<20 || b[0] != 0xcf || b[1] != 0xfa || b[2] != 0xed || b[3] != 0xfe {
			return fmt.Errorf("package: %s is not a valid program", n)
		}
	}
	return filepath.Walk(stage, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(stage, p)
		if rel == "." {
			return nil
		}
		dst := filepath.Join(dir, rel)
		if fi.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		if os.Rename(p, dst) == nil {
			return nil
		}
		os.Remove(dst + ".old")
		if err := os.Rename(dst, dst+".old"); err != nil {
			return fmt.Errorf("%s is in use: %v", rel, err)
		}
		return os.Rename(p, dst)
	})
}

// cleanOld removes the *.old files a full update left behind.
func cleanOld(dir string) {
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".old") {
			os.Remove(p)
		}
		return nil
	})
}
