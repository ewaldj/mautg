package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake mautg.py: serves /api/command and exits on {"cmd":"exit"}
const fakeMautg = `#!/usr/bin/env python3
VERSION = '9.99'
import sys, http.server, threading
port = int(sys.argv[len(sys.argv) - 1 - sys.argv[::-1].index('-port') + 1])
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
        threading.Thread(target=srv.shutdown).start()
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', port), H)
srv.serve_forever()
`

type script struct {
	mu    sync.Mutex
	steps []string // button / selection per call, in order
	log   []string
	opens []string
	notes []string
}

func (s *script) next() string {
	s.mu.Lock()
	if len(s.steps) == 0 {
		s.mu.Unlock()
		return "Quit mautg"
	}
	v := s.steps[0]
	s.steps = s.steps[1:]
	s.mu.Unlock()
	if v == "More..." {
		time.Sleep(1500 * time.Millisecond) // lets the asynchronous browser open finish
	}
	return v
}

func (s *script) env() env {
	return env{
		dialog: func(ctx context.Context, sp spec) (string, string, error) {
			s.mu.Lock()
			s.log = append(s.log, sp.text)
			s.mu.Unlock()
			v := s.next()
			if strings.Contains(v, "=") { // "Apply=9090": button with text
				p := strings.SplitN(v, "=", 2)
				return p[0], p[1], nil
			}
			return v, "", nil
		},
		choose: func(ctx context.Context, title, prompt string, items []string) (string, error) {
			s.mu.Lock()
			s.log = append(s.log, "LIST "+strings.Join(items, "|"))
			s.mu.Unlock()
			return s.next(), nil
		},
		open:     func(t string) { s.mu.Lock(); s.opens = append(s.opens, t); s.mu.Unlock() },
		toast:    func(string) {},
		note:     func(t string) { s.mu.Lock(); s.notes = append(s.notes, t); s.mu.Unlock() },
		relaunch: func([]string) error { return nil },
	}
}

func TestAppFlow(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte(fakeMautg), 0644)
	t.Setenv("MAUTG_UPDATE_BASE", serveEmpty(t))
	cfg := buildConfig(d, []string{"-port", "18941"}, exec.LookPath)
	r := &runner{cfg: cfg}
	sc := &script{steps: []string{
		"Open web GUI",    // 1 running -> open
		"More...", "Stop", // 2,3 -> stopped
		"More...", "Change port", "Apply=18942", // port change while stopped
		"Start", // start on new port, opens
		"More...", "Restart",
		"Quit mautg",
	}}
	a := newApp(sc.env(), r, nil)
	r.onExit = a.onExit
	a.startWith(cfg.port, false)
	if !r.running() {
		t.Fatal("not started")
	}
	done := make(chan struct{})
	go func() { a.loopDialogs(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("loop does not end")
	}
	if r.running() {
		t.Fatal("still running after Quit")
	}
	if r.getPort() != 18942 {
		t.Fatal("port", r.getPort())
	}
	for i := 0; i < 50 && len(sc.opens) < 2; i++ { // the browser is opened asynchronously, when mautg answers
		time.Sleep(100 * time.Millisecond)
	}
	if len(sc.opens) < 2 || sc.opens[0] != "http://127.0.0.1:18941" || sc.opens[1] != "http://127.0.0.1:18942" {
		t.Fatal(sc.opens)
	}
	if len(sc.notes) != 0 {
		t.Fatal(sc.notes)
	}
	all := strings.Join(sc.log, "\n")
	for _, w := range []string{"Status:  running", "Status:  stopped", "mautg.py v9.99", "LIST Restart|Stop|", "LIST Start|"} {
		if !strings.Contains(all, w) {
			t.Fatalf("%q missing in\n%s", w, all)
		}
	}
}

func TestAppBadPort(t *testing.T) {
	d := t.TempDir()
	r := &runner{cfg: config{dir: d, port: 8081}}
	sc := &script{steps: []string{"Apply=99999"}}
	a := newApp(sc.env(), r, nil)
	a.changePort()
	if len(sc.notes) != 1 || r.getPort() != 8081 {
		t.Fatal(sc.notes, r.getPort())
	}
}

func TestAppExitFromGUIRedraws(t *testing.T) {
	d := t.TempDir()
	r := &runner{cfg: config{dir: d, port: 8081}}
	redraw := make(chan bool, 1)
	e := (&script{}).env()
	n := 0
	e.dialog = func(ctx context.Context, sp spec) (string, string, error) {
		n++
		if n == 1 {
			go func() { time.Sleep(50 * time.Millisecond); a2.onExit(0, false) }()
			<-ctx.Done() // state change must cancel the dialog
			redraw <- true
			return "", "", ctx.Err()
		}
		if !strings.Contains(sp.text, "stopped (exit from web GUI)") {
			t.Error(sp.text)
		}
		return "Quit mautg", "", nil
	}
	a2 = newApp(e, r, nil)
	a2.loopDialogs()
	select {
	case <-redraw:
	default:
		t.Fatal("dialog not redrawn")
	}
}

var a2 *app

func TestPathEnv(t *testing.T) {
	var p string
	for _, e := range launchEnv("/x/mautg") {
		if strings.HasPrefix(e, "PATH=") {
			p = e
		}
	}
	if !strings.HasPrefix(p, "PATH=/x/mautg:") || !strings.Contains(p, "/opt/homebrew/bin") || !strings.Contains(p, "/usr/local/bin") {
		t.Fatal(p)
	}
}

func serveEmpty(t *testing.T) string {
	return serve(t, map[string]string{"mversions": "mautg.py 1.00\n"})
}

// fake osascript: prints events like gui.js does
func fakeOsa(t *testing.T, body string) {
	d := t.TempDir()
	p := filepath.Join(d, "osascript")
	os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755)
	old := osaBin
	osaBin = p
	t.Cleanup(func() { osaBin = old })
}

func TestWindowFlow(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	// ready, start, open, restart on another port, stop, exit (state file is $5)
	fakeOsa(t, `echo ready; sleep 1; echo "start 18951"; sleep 3; echo open; echo "restart 18952"; sleep 3; echo stop; sleep 1; echo exit; sleep 30`)
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mautg.py"), []byte(fakeMautg), 0644)
	t.Setenv("MAUTG_UPDATE_BASE", serveEmpty(t))
	r := &runner{cfg: buildConfig(d, []string{"-port", "18950"}, exec.LookPath)}
	sc := &script{}
	a := newApp(sc.env(), r, nil)
	r.onExit = a.onExit
	w, err := openWindow("t", "")
	if err != nil || !w.waitReady(5*time.Second) {
		t.Fatal(err)
	}
	defer w.close()
	done := make(chan struct{})
	go func() { a.loopWindow(w); close(done) }()
	select {
	case <-done:
	case <-time.After(40 * time.Second):
		t.Fatal("loop does not end")
	}
	if r.running() || r.getPort() != 18952 {
		t.Fatal(r.running(), r.getPort())
	}
	if len(sc.opens) != 1 || sc.opens[0] != "http://127.0.0.1:18951" {
		t.Fatal(sc.opens)
	}
	b, _ := os.ReadFile(w.state)
	if !strings.Contains(string(b), `"port":18952`) {
		t.Fatal(string(b))
	}
}

func TestWindowDiesBeforeReady(t *testing.T) {
	fakeOsa(t, `echo "syntax error" >&2; exit 1`)
	w, err := openWindow("t", "")
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if w.waitReady(5 * time.Second) {
		t.Fatal("ready reported")
	}
	time.Sleep(200 * time.Millisecond)
	if !strings.Contains(w.stderr(), "syntax error") {
		t.Fatal(w.stderr())
	}
}

func TestWindowBadPort(t *testing.T) {
	r := &runner{cfg: config{dir: t.TempDir(), port: 8081}}
	sc := &script{}
	a := newApp(sc.env(), r, nil)
	w := &window{state: filepath.Join(t.TempDir(), "s.json")}
	if a.handle(w, "start abc") || len(sc.notes) != 1 || r.running() {
		t.Fatal(sc.notes)
	}
	if !a.handle(w, "exit") {
		t.Fatal("exit not handled")
	}
}

func TestWaitUp(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r := &runner{cfg: config{dir: t.TempDir(), port: port, args: []string{"-bind", "127.0.0.1"}}, cmd: &exec.Cmd{}}
	a := newApp((&script{}).env(), r, nil)
	if a.waitUp(400 * time.Millisecond) {
		t.Fatal("reported up without a server")
	}
	go func() {
		time.Sleep(600 * time.Millisecond)
		l2, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			time.Sleep(3 * time.Second)
			l2.Close()
		}
	}()
	t0 := time.Now()
	if !a.waitUp(5 * time.Second) {
		t.Fatal("server not detected")
	}
	if time.Since(t0) < 500*time.Millisecond {
		t.Fatal("returned before the server was up")
	}
	r.cmd = nil // not running: stop waiting at once
	if a.waitUp(5 * time.Second) {
		t.Fatal("waited for a stopped mautg")
	}
}
