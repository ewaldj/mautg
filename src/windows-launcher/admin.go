package main

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
)

// Administrator rights help mautg on Windows in two places:
//   - DSCP: Windows ignores IP_TOS on sockets, mautg.py sets the marking with a QoS policy
//     (New-NetQosPolicy), which only an administrator may create;
//   - firewall: an inbound UDP rule for the bundled python.exe avoids the Windows
//     firewall prompt (receiver and OWD sync server).
// The launcher asks at the start whether it should restart as administrator; the answer
// "No" is remembered (the Admin button stays available).

// adminFlagPath is the file whose existence means "do not ask at the start again".
// It lives in the user profile because the program folder may be read-only.
func adminFlagPath() string {
	d, err := os.UserConfigDir()
	if err != nil || d == "" {
		return ""
	}
	return filepath.Join(d, "mautg", "admin-ask-off")
}

// adminAsk is true until the user chose "No" in the start dialog.
func adminAsk() bool {
	p := adminFlagPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err != nil
}

// adminAskOff remembers that the start dialog must not be shown again.
func adminAskOff() {
	p := adminFlagPath()
	if p == "" {
		return
	}
	os.MkdirAll(filepath.Dir(p), 0755)
	os.WriteFile(p, []byte("the launcher does not ask for administrator rights at the start\n"), 0644)
}

const adminDialogText = "mautg works best with administrator rights:\n\n" +
	"- DSCP marking of the sender (Windows ignores DSCP without a QoS policy)\n" +
	"- a firewall rule for UDP, so Windows does not ask when the receiver starts\n\n" +
	"Restart mautg as administrator now?\n\n" +
	"Yes = restart as administrator (UAC prompt)\n" +
	"No = continue without, do not ask again (the Admin button stays)\n" +
	"Cancel = continue without, ask again next time"

// fwRuleName is unique per installation folder, so two copies do not overwrite each other's rule.
func fwRuleName(python string) string {
	h := fnv.New32a()
	h.Write([]byte(strings.ToLower(filepath.Clean(python))))
	return fmt.Sprintf("mautg-python-%08x", h.Sum32())
}

// fwCommands are the netsh command lines (without the program name) that replace the
// inbound UDP rule of this python.exe: delete (ignored if missing), then add.
func fwCommands(python string) []string {
	name := fwRuleName(python)
	return []string{
		fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, name),
		fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=allow program="%s" protocol=UDP profile=any`, name, python),
	}
}
