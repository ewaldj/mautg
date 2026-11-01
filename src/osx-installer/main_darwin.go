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
	"time"
)

// logf writes to stderr and to ~/Library/Logs/mautg-installer.log (nothing is shown
// otherwise when osascript fails).
func logf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, "mautg-installer: "+msg)
	if h, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(h, "Library", "Logs", "mautg-installer.log")
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(f, "%s v%s %s\n", time.Now().Format("2006-01-02 15:04:05"), installerVersion, msg)
			f.Close()
		}
	}
}

func osa(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if strings.Contains(errb.String(), "-128") {
			return "", errCancel
		}
		logf("osascript failed: %v %s", err, strings.TrimSpace(errb.String()))
		return "", fmt.Errorf("%v %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func main() {
	logf("start (%s)", os.Args[0])
	e := env{
		dialog: func(ctx context.Context, s spec) (string, error) {
			out, err := osa(ctx, dialogScript(s))
			if err != nil {
				return "", err
			}
			b, _ := parseDialog(out)
			return b, nil
		},
		choose: func(ctx context.Context, t, p string, items []string) (string, error) {
			out, err := osa(ctx, listScript(t, p, items))
			if err != nil {
				return "", err
			}
			return parseList(out), nil
		},
		toast: func(t string) {
			exec.Command("osascript", "-e", "display notification "+osaStr(t)+" with title "+osaStr("mautg installer")).Start()
		},
		note: func(t string) {
			osa(context.Background(), dialogScript(spec{title: title(), text: t, buttons: []string{"OK"}, def: 0}))
		},
		open: func(t string) { exec.Command("open", t).Start() },
		admin: func(sh string) error {
			_, err := osa(context.Background(), "do shell script "+osaStr(sh)+" with administrator privileges")
			return err
		},
	}
	flow(e, func(dest string) error { return downloadFile(installURL(), dest, nil) })
}
