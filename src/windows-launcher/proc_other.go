//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

type osProc struct{}

func hideWindow(cmd *exec.Cmd)     { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func (p *osProc) attach(*exec.Cmd) {}
func (p *osProc) kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func main() {}
