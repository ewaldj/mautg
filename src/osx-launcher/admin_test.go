package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestAdminShell(t *testing.T) {
	s := adminShell("/Users/o'neil/mautg/python-aarch64/bin/python3.11")
	for _, w := range []string{"sysctl -w net.inet.udp.maxdgram=65535", "--getglobalstate", "State = [12]",
		`--add '/Users/o'\''neil/mautg/python-aarch64/bin/python3.11'`, "--unblockapp"} {
		if !strings.Contains(s, w) {
			t.Fatalf("%q missing in %s", w, s)
		}
	}
	if shQuote("a b") != "'a b'" || shQuote("it's") != `'it'\''s'` {
		t.Fatal("shQuote")
	}
}

func TestAdminAskFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if adminFlagPath() == "" || !adminAsk() {
		t.Fatal("must ask until Never ask")
	}
	adminAskOff()
	if adminAsk() {
		t.Fatal("asked again")
	}
}

func withMaxdgram(v int) func() {
	old := maxdgramNow
	maxdgramNow = func() int { return v }
	return func() { maxdgramNow = old }
}

func TestAdminNeededAndText(t *testing.T) {
	defer withMaxdgram(9216)()
	if !adminNeeded() || adminText() != "UDP datagram limit 9216 B" {
		t.Fatal(adminNeeded(), adminText())
	}
	maxdgramNow = func() int { return 65535 }
	if adminNeeded() || adminText() != "UDP datagram limit raised" {
		t.Fatal("raised value not recognised")
	}
	maxdgramNow = func() int { return 0 } // sysctl missing / not readable: never ask
	if adminNeeded() {
		t.Fatal("asked without a readable value")
	}
}

func TestAdminOfferFlow(t *testing.T) {
	defer withMaxdgram(9216)()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var ran []string
	answer := "Set up"
	e := env{
		dialog: func(ctx context.Context, s spec) (string, string, error) {
			if !strings.Contains(s.text, "maxdgram") || len(s.buttons) != 3 {
				t.Fatal("dialog", s)
			}
			return answer, "", nil
		},
		toast: func(string) {},
		note:  func(string) {},
		admin: func(script string) error { ran = append(ran, script); return nil },
	}
	a := newApp(e, &runner{cfg: config{dir: t.TempDir(), python: "/nonexistent/python3"}}, nil)
	a.adminOffer()
	if len(ran) != 1 || !strings.Contains(ran[0], "maxdgram") {
		t.Fatal(ran)
	}
	answer = "Not now"
	a.adminOffer()
	if len(ran) != 1 || !adminAsk() {
		t.Fatal("Not now must ask again next time")
	}
	answer = "Never ask"
	a.adminOffer()
	a.adminOffer() // no dialog any more (it would fail the test below)
	e.dialog = func(context.Context, spec) (string, string, error) {
		t.Fatal("asked after Never ask")
		return "", "", nil
	}
	a.e = e
	a.adminOffer()
	if adminAsk() || len(ran) != 1 {
		t.Fatal("flag not set")
	}
	// a canceled password dialog is silent, a failure is reported
	var notes []string
	a.e.note = func(s string) { notes = append(notes, s) }
	a.e.admin = func(string) error { return errCancel }
	a.adminSetup()
	a.e.admin = func(string) error { return os.ErrPermission }
	a.adminSetup()
	if len(notes) != 1 || !strings.Contains(notes[0], "failed") {
		t.Fatal(notes)
	}
}
