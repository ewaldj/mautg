package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed gui.js
var guiScript string

// osaBin is the script runner; tests replace it.
var osaBin = "osascript"

// winState is what the window shows (written as JSON, polled by gui.js).
type winState struct {
	Status  string `json:"status"`
	Running bool   `json:"running"`
	Busy    bool   `json:"busy"`
	Upd     string `json:"upd"`
	UpdShow bool   `json:"updShow"`
	Foot    string `json:"foot"`
	Port    int    `json:"port"`
	PortSeq int    `json:"portSeq"`
	Adm     string `json:"adm"`
	AdmShow bool   `json:"admShow"`
	Cli     string `json:"cli"`
	NoCfg   bool   `json:"noCfg"`
}

// window is the Cocoa window run by osascript (JXA); events are the lines it prints.
type window struct {
	cmd    *exec.Cmd
	dir    string
	state  string
	events chan string
	ready  chan struct{}
	done   chan struct{}
	errBuf strings.Builder
	mu     sync.Mutex
	once   sync.Once
}

func openWindow(title, icon string) (*window, error) {
	dir, err := os.MkdirTemp("", "mautg-gui-")
	if err != nil {
		return nil, err
	}
	script := filepath.Join(dir, "gui.js")
	if err := os.WriteFile(script, []byte(guiScript), 0600); err != nil {
		return nil, err
	}
	w := &window{dir: dir, state: filepath.Join(dir, "state.json"),
		events: make(chan string, 32), ready: make(chan struct{}), done: make(chan struct{})}
	os.WriteFile(w.state, []byte("{}"), 0600)
	w.cmd = exec.Command(osaBin, "-l", "JavaScript", script, w.state, title, icon)
	out, err := w.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	errp, _ := w.cmd.StderrPipe()
	if err := w.cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	go func() {
		b, _ := io.ReadAll(io.LimitReader(errp, 8192))
		w.mu.Lock()
		w.errBuf.Write(b)
		w.mu.Unlock()
	}()
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "ready" {
				w.once.Do(func() { close(w.ready) })
				continue
			}
			if strings.HasPrefix(l, "error ") { // JavaScript error from gui.js
				w.mu.Lock()
				w.errBuf.WriteString(l + "\n")
				w.mu.Unlock()
				continue
			}
			if l != "" {
				w.events <- l
			}
		}
	}()
	go func() {
		w.cmd.Wait()
		close(w.done)
	}()
	return w, nil
}

func (w *window) stderr() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.TrimSpace(w.errBuf.String())
}

// waitReady waits until the window is shown; false if the process ended before.
func (w *window) waitReady(d time.Duration) bool {
	select {
	case <-w.ready:
		return true
	case <-w.done:
		return false
	case <-time.After(d):
		return false
	}
}

func (w *window) setState(s winState) {
	b, _ := json.Marshal(s)
	tmp := w.state + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		os.Rename(tmp, w.state)
	}
}

func (w *window) close() {
	if w.cmd.Process != nil {
		w.cmd.Process.Kill()
	}
	os.RemoveAll(w.dir)
}

// ---- app side ----

func (a *app) snapshot(busy string) winState {
	ver := readVersion(a.run.cfg.dir)
	if ver != "" {
		ver = " v" + ver
	}
	a.mu.Lock()
	upd, show, seq := a.updText, a.upd != nil && !a.updBusy, a.portSeq
	a.mu.Unlock()
	s := winState{Status: a.status(), Running: a.run.running(), Upd: upd, UpdShow: show,
		Foot: "mautg.py" + ver + "  -", Port: a.run.getPort(), PortSeq: seq,
		Adm: adminText(), AdmShow: a.e.admin != nil && adminNeeded()}
	s.Cli, s.NoCfg = a.run.optionsText()
	if busy != "" {
		s.Status, s.Busy = busy, true
	}
	return s
}

func (a *app) push(w *window, busy string) { w.setState(a.snapshot(busy)) }

// handle executes one window event; true = quit.
func (a *app) handle(w *window, ev string) bool {
	// "start <port> <0|1> <cli options ...>": the CLI text keeps its blanks
	f := strings.SplitN(strings.TrimSpace(ev), " ", 4)
	if len(f) == 0 || f[0] == "" {
		return false
	}
	port := func() int {
		if len(f) > 1 {
			if n := parsePort(f[1]); n != 0 {
				return n
			}
		}
		a.e.note("The port must be a number from 1 to 65535.")
		return 0
	}
	opts := func() {
		if len(f) > 2 {
			cli := ""
			if len(f) > 3 {
				cli = f[3]
			}
			a.run.setOptions(cli, f[2] == "1")
		}
	}
	switch f[0] {
	case "start":
		if n := port(); n != 0 && !a.run.running() {
			a.push(w, "starting ...")
			opts()
			a.startWith(n, false)
			a.bumpPort()
		}
	case "restart":
		if n := port(); n != 0 {
			a.push(w, "restarting ...")
			opts()
			a.startWith(n, true)
			a.bumpPort()
		}
	case "stop":
		a.push(w, "stopping ...")
		a.run.stop(4 * time.Second)
	case "open":
		if a.run.running() {
			a.openGUI()
		}
	case "log":
		a.e.open(filepath.Join(a.run.cfg.dir, logName))
	case "link":
		a.e.open("https://www.jeitler.cc")
	case "admin":
		a.push(w, "admin setup ...")
		a.adminSetup()
	case "update":
		a.push(w, "updating ...")
		if a.doUpdate() {
			return true
		}
	case "exit":
		return true
	}
	return false
}

// bumpPort makes the window show the port that is really used.
func (a *app) bumpPort() {
	a.mu.Lock()
	a.portSeq++
	a.mu.Unlock()
}

// loopWindow runs until Exit / window closed. false = the window died before it was shown.
func (a *app) loopWindow(w *window) {
	a.push(w, "")
	for {
		select {
		case ev := <-w.events:
			quit := a.handle(w, ev)
			if quit {
				a.mu.Lock()
				a.quit = true
				a.mu.Unlock()
				a.push(w, "exiting ...")
				a.run.stop(4 * time.Second)
				return
			}
			a.push(w, "")
		case <-a.poke:
			a.push(w, "")
		case <-w.done: // window process ended
			a.run.stop(4 * time.Second)
			return
		}
	}
}

func (w *window) String() string { return fmt.Sprint("window ", w.dir) }
