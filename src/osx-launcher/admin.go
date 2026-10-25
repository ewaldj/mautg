package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Administrator rights help mautg on macOS in two places. mautg itself never runs as
// root (its files would become root-owned); the launcher only runs one setup command
// as administrator, after asking for the password:
//   - net.inet.udp.maxdgram (default 9216): the largest UDP datagram macOS sends. Raised to
//     65535 the sender can use packet sizes up to 65507 bytes (until the next reboot);
//   - application firewall: if it is on, the bundled python is allowed to receive, so
//     macOS does not ask when the receiver starts.

const maxdgramWanted = 65535

const fwTool = "/usr/libexec/ApplicationFirewall/socketfilterfw"

const adminDialogText = "mautg can send larger UDP packets after a one-time setup as administrator:\n\n" +
	"- raises net.inet.udp.maxdgram (macOS default 9216 bytes) until the next reboot\n" +
	"- allows the bundled python in the macOS firewall (only if the firewall is on)\n\n" +
	"mautg itself keeps running as your user. Set it up now? (asks for your password)"

// adminFlagPath is the file whose existence means "do not ask at the start again".
func adminFlagPath() string {
	d, err := os.UserConfigDir()
	if err != nil || d == "" {
		return ""
	}
	return filepath.Join(d, "mautg", "admin-ask-off")
}

// adminAsk is true until the user chose "Never ask".
func adminAsk() bool {
	p := adminFlagPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err != nil
}

func adminAskOff() {
	p := adminFlagPath()
	if p == "" {
		return
	}
	os.MkdirAll(filepath.Dir(p), 0755)
	os.WriteFile(p, []byte("the launcher does not ask for administrator rights at the start\n"), 0644)
}

// shQuote quotes s for /bin/sh.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// adminShell is the command run as administrator. Only the sysctl decides success;
// the firewall part is best effort.
func adminShell(python string) string {
	p := shQuote(python)
	return "sysctl -w net.inet.udp.maxdgram=" + strconv.Itoa(maxdgramWanted) +
		" && { if " + fwTool + " --getglobalstate | grep -q 'State = [12]'; then " +
		fwTool + " --add " + p + "; " + fwTool + " --unblockapp " + p + "; fi; true; }"
}

// maxdgramNow returns net.inet.udp.maxdgram, 0 if it cannot be read.
var maxdgramNow = func() int {
	out, err := exec.Command("sysctl", "-n", "net.inet.udp.maxdgram").Output()
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0
	}
	return n
}

// adminNeeded: the datagram limit can be raised.
func adminNeeded() bool {
	v := maxdgramNow()
	return v > 0 && v < maxdgramWanted
}

// adminText is the status line of the window.
func adminText() string {
	v := maxdgramNow()
	switch {
	case v <= 0:
		return "-"
	case v >= maxdgramWanted:
		return "UDP datagram limit raised"
	}
	return "UDP datagram limit " + strconv.Itoa(v) + " B"
}

// resolvePython follows the python3 link to the real binary (the firewall wants that).
func resolvePython(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
