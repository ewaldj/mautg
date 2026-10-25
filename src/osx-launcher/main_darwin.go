//go:build darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func osa(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if strings.Contains(errb.String(), "-128") {
			return "", errCancel
		}
		return "", fmt.Errorf("osascript: %v %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func lockInstance(wait bool) (*os.File, bool) {
	f, err := os.OpenFile(filepath.Join(os.TempDir(), fmt.Sprintf("mautg-launcher-%d.lock", os.Getuid())), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, true // cannot lock: do not block the start
	}
	for i := 0; ; i++ {
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			return f, true
		}
		if !wait || i >= 60 { // after an update wait for the old instance to exit
			return nil, false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func main() {
	exe, _ := os.Executable()
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	dir := appDirOf(exe)
	args := os.Args[1:]
	after := len(args) > 0 && args[0] == "--after-update"
	if after {
		args = args[1:]
	}
	e := env{
		open: func(t string) { exec.Command("open", t).Start() },
		toast: func(t string) {
			exec.Command("osascript", "-e", "display notification "+osaStr(t)+" with title "+osaStr("mautg")).Start()
		},
		note: func(t string) {
			osa(context.Background(), dialogScript(spec{title: "mautg", text: t, buttons: []string{"OK"}, def: 0}))
		},
		dialog: func(ctx context.Context, s spec) (string, string, error) {
			out, err := osa(ctx, dialogScript(s))
			if err != nil && err != errCancel && ctx.Err() == nil && s.icon != "" {
				s.icon = ""
				out, err = osa(ctx, dialogScript(s))
			}
			if err != nil {
				return "", "", err
			}
			b, t := parseDialog(out)
			return b, t, nil
		},
		choose: func(ctx context.Context, title, prompt string, items []string) (string, error) {
			out, err := osa(ctx, listScript(title, prompt, items))
			if err != nil {
				return "", err
			}
			return parseList(out), nil
		},
		admin: func(script string) error {
			_, err := osa(context.Background(), osaFront+"do shell script "+osaStr(script)+" with administrator privileges")
			return err
		},
		relaunch: func(a []string) error {
			bundle := filepath.Join(dir, "mautg.app")
			return exec.Command("open", append([]string{"-n", bundle, "--args", "--after-update"}, a...)...).Start()
		},
	}
	if strings.Contains(exe, "/AppTranslocation/") {
		e.note("macOS runs mautg from a protected temporary location.\nMove the mautg folder to e.g. ~/Applications first, or run:\nxattr -dr com.apple.quarantine <mautg folder>")
		return
	}
	lock, ok := lockInstance(after)
	if !ok {
		e.note("mautg is already running.")
		return
	}
	defer lock.Close()
	cleanOld(dir)

	cfg := buildConfig(dir, args, exec.LookPath)
	r := &runner{cfg: cfg}
	a := newApp(e, r, args)
	r.onExit = a.onExit
	if ic := filepath.Join(dir, "mautg.app", "Contents", "Resources", "mautg.icns"); fileExists(ic) {
		a.icon = ic
	}
	go a.checkLoop()
	go a.autoStart()
	// window (Cocoa through JXA); the dialog UI is the fallback if it cannot be shown
	w, err := openWindow(a.title(), a.icon)
	if err == nil && w.waitReady(15*time.Second) {
		a.loopWindow(w)
		w.close()
		return
	}
	if w != nil {
		msg := w.stderr()
		w.close()
		if msg == "" {
			msg = "no window after 15 s"
		}
		os.WriteFile(filepath.Join(dir, "mautg-launcher.log"), []byte("window failed: "+msg+"\n"), 0644)
		if len(msg) > 400 {
			msg = msg[:400]
		}
		e.note("The window could not be shown, dialogs are used instead:\n" + msg)
	}
	a.loopDialogs()
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }
