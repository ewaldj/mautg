package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSplitUser(t *testing.T) {
	cli, n := splitUser([]string{"-bind", "0.0.0.0", "--no-config", "-port", "9000", `a b`})
	if cli != `-bind 0.0.0.0 "a b"` || !n {
		t.Fatalf("%q %v", cli, n)
	}
	cli, n = splitUser([]string{"--port=1"})
	if cli != "" || n {
		t.Fatalf("%q %v", cli, n)
	}
}

func TestSetOptions(t *testing.T) {
	d := t.TempDir()
	r := &runner{cfg: buildConfig(d, nil, func(string) (string, error) { return "", os.ErrNotExist })}
	r.setOptions("-bind 0.0.0.0", true)
	want := []string{"-web", "-bind", "0.0.0.0", "--no-config", "-port", "8081"}
	if !reflect.DeepEqual(r.cfg.args, want) {
		t.Fatalf("%v", r.cfg.args)
	}
	b, _ := os.ReadFile(filepath.Join(d, argsFile))
	if !strings.Contains(string(b), "-bind 0.0.0.0 --no-config\n") {
		t.Fatalf("%q", b)
	}
	// a restart reads the same options back
	c := buildConfig(d, nil, func(string) (string, error) { return "", os.ErrNotExist })
	r2 := &runner{cfg: c}
	if cli, n := r2.optionsText(); cli != "-bind 0.0.0.0" || !n {
		t.Fatalf("%q %v", cli, n)
	}
	r.setOptions("", false)
	b, _ = os.ReadFile(filepath.Join(d, argsFile))
	if strings.Contains(string(b), "bind") || strings.Contains(string(b), "no-config") {
		t.Fatalf("%q", b)
	}
}
