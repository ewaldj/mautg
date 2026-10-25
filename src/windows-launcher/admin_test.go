package main

import (
	"os"
	"strings"
	"testing"
)

func TestFirewallCommands(t *testing.T) {
	py := `C:\Program Files\mautg\python\python.exe`
	c := fwCommands(py)
	if len(c) != 2 || !strings.HasPrefix(c[0], "advfirewall firewall delete rule name=") ||
		!strings.Contains(c[1], `add rule name="`+fwRuleName(py)+`" dir=in action=allow program="`+py+`" protocol=UDP`) {
		t.Fatal(c)
	}
	if fwRuleName(py) == fwRuleName(`D:\mautg\python\python.exe`) || fwRuleName(py) != fwRuleName(strings.ToLower(py)) {
		t.Fatal("rule name must differ per folder and ignore case")
	}
}

func TestAdminAskFlag(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	if adminFlagPath() == "" || !adminAsk() {
		t.Fatal("must ask at the first start")
	}
	adminAskOff()
	if adminAsk() {
		t.Fatal("must not ask again after No")
	}
	if _, err := os.Stat(adminFlagPath()); err != nil {
		t.Fatal(err)
	}
}
