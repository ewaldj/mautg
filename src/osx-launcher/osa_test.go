package main

import (
	"strings"
	"testing"
)

func TestOsaStr(t *testing.T) {
	if got := osaStr("a\"b\\c\nd"); got != `("a\"b\\c" & linefeed & "d")` {
		t.Fatal(got)
	}
	if osaStr("x") != `("x")` {
		t.Fatal(osaStr("x"))
	}
}

func TestDialogScript(t *testing.T) {
	s := dialogScript(spec{title: "T", text: "hi", buttons: []string{"A", "B", "C"}, def: 2, input: true, answer: "8081"})
	for _, w := range []string{`display dialog ("hi")`, `with title ("T")`, `buttons {("A"), ("B"), ("C")}`, `default button ("C")`, `default answer ("8081")`} {
		if !strings.Contains(s, w) {
			t.Fatal(w, "\n", s)
		}
	}
	if strings.Contains(s, "icon") || !strings.HasPrefix(s, osaFront) {
		t.Fatal(s)
	}
	if !strings.Contains(dialogScript(spec{title: "T", text: "x", buttons: []string{"A"}, icon: "/a b/e.icns"}), `with icon (POSIX file ("/a b/e.icns"))`) {
		t.Fatal("icon")
	}
	if !strings.Contains(listScript("T", "P", []string{"x", "y"}), `default items {("x")}`) {
		t.Fatal("list")
	}
}

func TestParse(t *testing.T) {
	b, x := parseDialog("button returned:Apply, text returned:9090\n")
	if b != "Apply" || x != "9090" {
		t.Fatal(b, x)
	}
	b, x = parseDialog("button returned:Open web GUI\n")
	if b != "Open web GUI" || x != "" {
		t.Fatal(b, x)
	}
	if parseList("false\n") != "" || parseList("Restart\n") != "Restart" {
		t.Fatal("list")
	}
}

func TestAppDirOf(t *testing.T) {
	for in, want := range map[string]string{
		"/Users/u/mautg-mac/mautg.app/Contents/MacOS/mautg-arm64": "/Users/u/mautg-mac",
		"/opt/x/mautg": "/opt/x",
	} {
		if got := appDirOf(in); got != want {
			t.Fatal(in, got)
		}
	}
}
