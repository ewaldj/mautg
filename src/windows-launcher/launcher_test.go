package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestArgs(t *testing.T) {
	if g := fieldsLine(`-bind "my host" -ph  -w 2`); !reflect.DeepEqual(g, []string{"-bind", "my host", "-ph", "-w", "2"}) {
		t.Fatal(g)
	}
	if portOf([]string{"-web", "-port", "9000"}, 8081) != 9000 || portOf([]string{"--port=9100"}, 8081) != 9100 || portOf(nil, 8081) != 8081 {
		t.Fatal("port")
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, argsFile), []byte("\xef\xbb\xbf# c\n\n-port 9200 -ph\nignored\n"), 0644)
	c := buildConfig(d, []string{"-w", "3"}, exec.LookPath)
	if c.port != 9200 || c.args[len(c.args)-3] != "3" || c.args[0] != "-web" {
		t.Fatal(c)
	}
}

func up(port int) bool {
	c := http.Client{Timeout: time.Second}
	r, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", port))
	if err != nil {
		return false
	}
	r.Body.Close()
	return true
}

func TestPortConfig(t *testing.T) {
	d := t.TempDir()
	if c := buildConfig(d, nil, exec.LookPath); c.port != 8081 || bindOf(c.args) != "127.0.0.1" || c.args[0] != "-web" || c.args[len(c.args)-1] != "8081" {
		t.Fatal(c.port, c.args)
	}
	af := filepath.Join(d, argsFile)
	os.WriteFile(af, []byte("-port 9200\n"), 0644)
	if c := buildConfig(d, nil, exec.LookPath); c.port != 9200 || c.argsPath != af {
		t.Fatal(c.port)
	}
	// the command line wins over the file
	if c := buildConfig(d, []string{"-port", "9400"}, exec.LookPath); c.port != 9400 {
		t.Fatal(c.port)
	}
	// -bind from the file / command line replaces the launcher default
	os.WriteFile(af, []byte("-bind 0.0.0.0\n"), 0644)
	if c := buildConfig(d, nil, exec.LookPath); bindOf(c.args) != "0.0.0.0" || c.port != 8081 {
		t.Fatal(c.args)
	}
	// persist: the port is replaced in place, other options and comments stay
	os.WriteFile(af, []byte("# my options\n-bind 127.0.0.1 -port 9100  # port\n"), 0644)
	if err := persistPort(af, 9300); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(af); string(b) != "# my options\n-bind 127.0.0.1 -port 9300  # port\n" {
		t.Fatalf("%q", b)
	}
	// persist: appended to the option line; the default port adds nothing
	os.WriteFile(af, []byte("-bind 0.0.0.0\r\n"), 0644)
	persistPort(af, 8081)
	if b, _ := os.ReadFile(af); string(b) != "-bind 0.0.0.0\r\n" {
		t.Fatalf("%q", b)
	}
	persistPort(af, 9001)
	if b, _ := os.ReadFile(af); string(b) != "-bind 0.0.0.0 -port 9001\r\n" {
		t.Fatalf("%q", b)
	}
	// comment-only file: the option line is added at the end
	os.WriteFile(af, []byte("# nothing\n"), 0644)
	persistPort(af, 9002)
	if b, _ := os.ReadFile(af); string(b) != "# nothing\n-port 9002\n" {
		t.Fatalf("%q", b)
	}
	// no file: created for a non-default port only
	os.Remove(af)
	persistPort(af, 8081)
	if _, err := os.Stat(af); err == nil {
		t.Fatal("file created for the default port")
	}
	persistPort(af, 9003)
	if c := buildConfig(d, nil, exec.LookPath); c.port != 9003 {
		t.Fatal("persisted port not read back", c.port)
	}
	if persistPort("", 9004) != nil {
		t.Fatal("empty path")
	}
}

func TestLifecycle(t *testing.T) {
	src := os.Getenv("MAUTG_SRC")
	if src == "" {
		t.Skip("MAUTG_SRC not set")
	}
	d := t.TempDir()
	b, _ := os.ReadFile(src)
	os.WriteFile(filepath.Join(d, "mautg.py"), b, 0644)
	cfg := buildConfig(d, []string{"-port", "18931"}, exec.LookPath)
	if cfg.python == "" {
		t.Skip("no python")
	}
	exits := make(chan bool, 4)
	r := &runner{cfg: cfg, onExit: func(code int, req bool) { exits <- req }}
	wait := func(want bool) {
		for i := 0; i < 100; i++ {
			if up(18931) == want {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("web gui up=%v not reached", !want)
	}
	if err := r.start(); err != nil {
		t.Fatal(err)
	}
	wait(true)
	t0 := time.Now()
	r.stop(4 * time.Second)
	if r.running() || up(18931) || !<-exits {
		t.Fatal("not stopped cleanly")
	}
	t.Logf("clean stop %.2fs", time.Since(t0).Seconds())
	if err := r.restart(); err != nil {
		t.Fatal(err)
	}
	wait(true)
	// restart while running
	if err := r.restart(); err != nil {
		t.Fatal(err)
	}
	wait(true)
	<-exits
	// forced kill path: port unreachable for the exit request
	r.cfg.port = 1
	r.stop(500 * time.Millisecond)
	if r.running() {
		t.Fatal("kill failed")
	}
	<-exits
	if _, err := os.Stat(filepath.Join(d, logName)); err != nil {
		t.Fatal(err)
	}
}

func TestMissing(t *testing.T) {
	r := &runner{cfg: config{dir: t.TempDir()}}
	if r.start() == nil {
		t.Fatal("expected error")
	}
}

func TestPortBusy(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if _, ok := checkPort("127.0.0.1", port).(*portBusyError); !ok {
		t.Fatal("busy port not detected")
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte("x"), 0644)
	cfg := config{dir: d, python: "python3", args: []string{"-bind", "127.0.0.1", "-port", fmt.Sprint(port)}, port: port}
	r := &runner{cfg: cfg}
	if _, ok := r.start().(*portBusyError); !ok || r.running() {
		t.Fatal("start must refuse a busy port")
	}
	l.Close()
	if checkPort("127.0.0.1", port) != nil {
		t.Fatal("free port reported busy")
	}
	if bindOf([]string{"-bind", "0.0.0.0", "--bind=::1"}) != "::1" || bindOf(nil) != "127.0.0.1" {
		t.Fatal("bindOf")
	}
}

func TestReadVersion(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte("#!/usr/bin/env python3\n# x\nVERSION = '3.70'\n"), 0644)
	if v := readVersion(d); v != "3.70" {
		t.Fatal(v)
	}
	if readVersion(t.TempDir()) != "" {
		t.Fatal("missing file")
	}
}

func TestWaitUp(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r := &runner{cfg: config{dir: t.TempDir(), port: port, args: []string{"-bind", "127.0.0.1"}}, cmd: &exec.Cmd{}}
	if r.waitUp(400 * time.Millisecond) {
		t.Fatal("reported up without a server")
	}
	go func() {
		time.Sleep(600 * time.Millisecond)
		if l2, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
			time.Sleep(3 * time.Second)
			l2.Close()
		}
	}()
	t0 := time.Now()
	if !r.waitUp(5*time.Second) || time.Since(t0) < 500*time.Millisecond {
		t.Fatal("server not detected in time")
	}
	r.cmd = nil
	if r.waitUp(5 * time.Second) {
		t.Fatal("waited for a stopped mautg")
	}
}
