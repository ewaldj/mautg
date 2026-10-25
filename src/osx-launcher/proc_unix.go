//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// osProc: mautg runs in its own process group, so its children die with it.
type osProc struct{}

func hideWindow(cmd *exec.Cmd)     { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func (p *osProc) attach(*exec.Cmd) {}
func (p *osProc) kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// launchEnv returns the environment for mautg.py. GUI apps get a minimal PATH, so the
// package folder comes first.
func launchEnv(dir string) []string {
	path := dir + ":" + os.Getenv("PATH")
	for _, p := range []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"} {
		if !strings.Contains(":"+path+":", ":"+p+":") {
			path += ":" + p
		}
	}
	return append(os.Environ(), "PATH="+path)
}
