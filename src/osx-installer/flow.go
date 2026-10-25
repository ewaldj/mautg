package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type env struct {
	dialog func(ctx context.Context, s spec) (button string, err error)
	choose func(ctx context.Context, title, prompt string, items []string) (string, error)
	toast  func(text string)
	note   func(text string)
	open   func(target string)
	admin  func(shell string) error // run a shell command with administrator rights
}

const (
	labelUser   = "Current user   (~/Applications/mautg)"
	labelSystem = "All users   (/Applications/mautg, asks for the admin password)"
)

func title() string { return "mautg installer (macOS) v" + installerVersion }

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// prepareDir creates dir and makes it writable for the current user.
func prepareDir(e env, dir string, system bool) error {
	if err := os.MkdirAll(dir, 0755); err == nil {
		if f, err := os.CreateTemp(dir, ".w"); err == nil {
			f.Close()
			os.Remove(f.Name())
			return nil
		}
	}
	if !system {
		return fmt.Errorf("cannot write to %s", dir)
	}
	return e.admin(fmt.Sprintf("mkdir -p %s && chown %d:%d %s", shq(dir), os.Getuid(), os.Getgid(), shq(dir)))
}

// bundledPython: the package brings its own Python.
func bundledPython(dir string) bool {
	for _, n := range []string{"python-aarch64", "python-x86_64"} {
		if _, err := os.Stat(filepath.Join(dir, n, "bin", "python3")); err == nil {
			return true
		}
	}
	return false
}

func hints(dir string) string {
	var n []string
	if !bundledPython(dir) && exec.Command("xcode-select", "-p").Run() != nil {
		if _, err := os.Stat("/opt/homebrew/bin/python3"); err != nil {
			if _, err := os.Stat("/usr/local/bin/python3"); err != nil {
				n = append(n, "python3 is missing: run  xcode-select --install")
			}
		}
	}
	if len(n) == 0 {
		return ""
	}
	return "\n\nNote:\n" + strings.Join(n, "\n")
}

// flow runs the installer dialogs.
func flow(e env, fetch func(dest string) error) {
	ctx := context.Background()
	b, err := e.dialog(ctx, spec{title: title(), buttons: []string{"Cancel", "Uninstall", "Install"}, def: 2,
		text: "Installs mautg (web GUI) for macOS.\nThe package is downloaded from GitHub.\n\nwww.jeitler.cc"})
	if err != nil {
		return
	}
	switch b {
	case "Uninstall":
		var gone []string
		for _, d := range []string{userDir(), systemDir()} {
			if installedIn(d) {
				if err := uninstall(d); err != nil {
					e.note("Cannot remove " + d + ":\n" + err.Error())
					return
				}
				gone = append(gone, d)
			}
		}
		if len(gone) == 0 {
			e.note("mautg is not installed.")
		} else {
			e.note("mautg removed from:\n" + strings.Join(gone, "\n") + "\n\nHosts files and logs were kept.")
		}
	case "Install":
		sel, err := e.choose(ctx, title(), "Install for:", []string{labelUser, labelSystem})
		if err != nil || sel == "" {
			return
		}
		dir, system := userDir(), false
		if sel == labelSystem {
			dir, system = systemDir(), true
		}
		if err := prepareDir(e, dir, system); err != nil {
			e.note("Cannot create the folder:\n" + err.Error())
			return
		}
		e.toast("mautg installer: downloading ...")
		tmp := filepath.Join(os.TempDir(), "mautg-mac-download.zip")
		defer os.Remove(tmp)
		if err := fetch(tmp); err != nil {
			e.note("Download failed:\n" + err.Error())
			return
		}
		if err := installFrom(tmp, dir); err != nil {
			e.note("Installation failed:\n" + err.Error())
			return
		}
		b, err := e.dialog(ctx, spec{title: title(), buttons: []string{"Close", "Show folder", "Start mautg"}, def: 2,
			text: "mautg is installed in:\n" + dir + hints(dir)})
		if err != nil {
			return
		}
		switch b {
		case "Show folder":
			e.open(dir)
		case "Start mautg":
			e.open(filepath.Join(dir, "mautg.app"))
		}
	}
}
