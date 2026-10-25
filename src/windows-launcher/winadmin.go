//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var pIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")

// isElevated: this process runs with an elevated administrator token.
func isElevated() bool { r, _, _ := pIsUserAnAdmin.Call(); return r != 0 }

// quoteArg quotes one command line argument for ShellExecute.
func quoteArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"") {
		return a
	}
	return `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
}

// relaunchElevated starts this program again with "runas" (UAC prompt). The new instance
// waits until this one has exited. false if the user declined the prompt.
func relaunchElevated(args []string) bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	p := []string{"--elevated"}
	for _, a := range args {
		p = append(p, quoteArg(a))
	}
	r, _, _ := pShellExecute.Call(0, uintptr(unsafe.Pointer(u16("runas"))), uintptr(unsafe.Pointer(u16(exe))),
		uintptr(unsafe.Pointer(u16(strings.Join(p, " ")))), 0, 1)
	return r > 32 // <= 32 is an error (also: the prompt was declined)
}

// ensureFirewall (elevated only) replaces the inbound UDP rule of the bundled python.exe.
func ensureFirewall(python string) {
	if python == "" || !isElevated() {
		return
	}
	for _, c := range fwCommands(python) {
		cmd := exec.Command("netsh")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow,
			CmdLine: "netsh " + c}
		cmd.Run() // best effort: the delete fails when there is no rule yet
	}
}
