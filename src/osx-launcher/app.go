package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// app is the dialog based user interface; env hides osascript / open so it can be tested.
type env struct {
	dialog   func(ctx context.Context, s spec) (button, text string, err error)
	choose   func(ctx context.Context, title, prompt string, items []string) (string, error)
	open     func(target string)
	toast    func(text string)         // short non-blocking notification
	note     func(text string)         // modal information
	relaunch func(args []string) error // start the new package after a full update
	admin    func(script string) error // run a shell command as administrator (password dialog)
}

type app struct {
	e    env
	run  *runner
	args []string // launcher arguments (for the restart after a full update)
	ver  string   // text of the mautg.py version

	mu       sync.Mutex
	lastExit string
	upd      *updInfo
	updText  string
	updBusy  bool
	quit     bool
	poke     chan struct{}
	icon     string
	portSeq  int
}

func newApp(e env, r *runner, args []string) *app {
	return &app{e: e, run: r, args: args, updText: "checking ...", poke: make(chan struct{}, 1)}
}

func (a *app) wake() {
	select {
	case a.poke <- struct{}{}:
	default:
	}
}

func (a *app) title() string { return "mautg (macOS) v" + launcherVersion }

func (a *app) status() string {
	a.mu.Lock()
	le := a.lastExit
	a.mu.Unlock()
	switch {
	case a.run.running():
		return fmt.Sprintf("running  -  http://127.0.0.1:%d", a.run.getPort())
	case le != "":
		return le
	}
	return "stopped"
}

func (a *app) mainSpec() spec {
	a.mu.Lock()
	u := a.updText
	a.mu.Unlock()
	ver := readVersion(a.run.cfg.dir)
	if ver != "" {
		ver = " v" + ver
	}
	s := spec{title: a.title(), icon: a.icon,
		text: "Status:  " + a.status() + "\nWeb port:  " + fmt.Sprint(a.run.getPort()) +
			"\nUpdate:  " + u + "\n\nmautg.py" + ver + "  -  www.jeitler.cc"}
	if a.run.running() {
		s.buttons = []string{"Quit mautg", "More...", "Open web GUI"}
	} else {
		s.buttons = []string{"Quit mautg", "More...", "Start"}
	}
	s.def = 2
	return s
}

// startWith applies the port and starts mautg (blocking, a few ms).
func (a *app) startWith(n int, stopFirst bool) {
	if stopFirst {
		a.run.stop(4 * time.Second)
	}
	a.run.setPort(n)
	persistPort(a.run.cfg.argsPath, n)
	a.mu.Lock()
	a.lastExit = ""
	a.mu.Unlock()
	if err := a.run.start(); err != nil {
		a.mu.Lock()
		a.lastExit = "stopped"
		a.mu.Unlock()
		a.e.note(err.Error())
	}
}

// waitUp waits until the web GUI answers (mautg needs a moment to start); false on timeout
// or if mautg has stopped meanwhile.
func (a *app) waitUp(max time.Duration) bool {
	host := bindOf(a.run.cfg.args)
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(a.run.getPort()))
	for end := time.Now().Add(max); time.Now().Before(end); time.Sleep(150 * time.Millisecond) {
		if !a.run.running() {
			return false
		}
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// openWhenUp opens the browser as soon as the web GUI is reachable (no error page).
func (a *app) openWhenUp() {
	if a.waitUp(30 * time.Second) {
		a.openGUI()
	}
}

func (a *app) openGUI() { a.e.open(fmt.Sprintf("http://127.0.0.1:%d", a.run.getPort())) }

// adminSetup runs the one-time setup as administrator (password dialog) and restarts
// mautg if it is running, so it sees the new limit.
func (a *app) adminSetup() {
	if a.e.admin == nil {
		return
	}
	err := a.e.admin(adminShell(resolvePython(a.run.cfg.python)))
	switch {
	case err == errCancel:
		return
	case err != nil:
		a.e.note("The administrator setup failed:\n" + err.Error())
		return
	}
	a.e.toast("mautg: UDP datagram limit raised")
	if a.run.running() {
		a.startWith(a.run.getPort(), true)
	}
	a.wake()
}

// adminOffer asks once per start (until "Never ask") whether the setup should be run.
func (a *app) adminOffer() {
	if a.e.admin == nil || !adminNeeded() || !adminAsk() {
		return
	}
	b, _, err := a.e.dialog(context.Background(), spec{title: a.title(), text: adminDialogText,
		buttons: []string{"Not now", "Never ask", "Set up"}, def: 2, icon: a.icon})
	if err != nil {
		return
	}
	switch b {
	case "Set up":
		a.adminSetup()
	case "Never ask":
		adminAskOff()
	}
}

func (a *app) autoStart() {
	a.adminOffer()
	a.startWith(a.run.getPort(), false)
	go a.openWhenUp()
	a.wake()
}

// onExit is called by the runner when mautg.py has ended.
func (a *app) onExit(code int, requested bool) {
	if !requested {
		a.mu.Lock()
		if code == 0 {
			a.lastExit = "stopped (exit from web GUI)"
		} else {
			a.lastExit = fmt.Sprintf("stopped unexpectedly (exit code %d)", code)
		}
		a.mu.Unlock()
		if code != 0 {
			go a.e.note(fmt.Sprintf("mautg stopped unexpectedly (exit code %d).\nIf the port is in use, choose another one under More... / Change port.\nSee the console log for details.", code))
		}
	}
	a.wake()
}

func (a *app) setUpd(txt string, info *updInfo, busy bool) {
	a.mu.Lock()
	a.updText, a.upd, a.updBusy = txt, info, busy
	a.mu.Unlock()
	a.wake()
}

func (a *app) checkNow() {
	info, err := checkUpdate(a.run.cfg.dir, updateBase())
	switch {
	case err != nil:
		a.setUpd("check failed (offline?)", nil, false)
	case info == nil:
		a.setUpd("up to date", nil, false)
	default:
		a.setUpd(info.text(), info, false)
	}
}

// checkLoop checks GitHub shortly after the start and then every 6 hours.
func (a *app) checkLoop() {
	time.Sleep(3 * time.Second)
	for {
		a.mu.Lock()
		skip := a.updBusy || a.upd != nil || a.quit
		a.mu.Unlock()
		if !skip {
			a.checkNow()
		}
		time.Sleep(6 * time.Hour)
	}
}

// doUpdate stops mautg, replaces the files, restarts. true = this launcher must exit.
func (a *app) doUpdate() bool {
	a.mu.Lock()
	info := a.upd
	a.mu.Unlock()
	if info == nil {
		return false
	}
	a.setUpd("updating ...", info, true)
	a.e.toast("mautg: updating ...")
	was := a.run.running()
	if was {
		a.run.stop(4 * time.Second)
	}
	dir := a.run.cfg.dir
	if info.full {
		if err := applyFull(dir, updateBase()); err != nil {
			a.setUpd("update failed", info, false)
			a.e.note("Update failed:\n" + err.Error())
		} else if err := a.e.relaunch(a.args); err != nil {
			a.e.note("Updated, but restart failed - please start mautg again:\n" + err.Error())
			return true
		} else {
			return true
		}
	} else if err := applyUpdate(dir, updateBase(), info); err != nil {
		a.setUpd("update failed", info, false)
		a.e.note("Update failed - nothing was changed:\n" + err.Error())
	} else {
		a.setUpd("updated", nil, false)
		a.e.note("Updated: " + info.text()[5:])
	}
	if was {
		a.startWith(a.run.getPort(), false)
	}
	return false
}

func (a *app) changePort() {
	cur := a.run.getPort()
	b, t, err := a.e.dialog(context.Background(), spec{title: a.title(), text: "Web port (1-65535):",
		buttons: []string{"Cancel", "Apply"}, def: 1, input: true, answer: fmt.Sprint(cur), icon: a.icon})
	if err != nil || b != "Apply" {
		return
	}
	n := parsePort(t)
	if n == 0 {
		a.e.note("The port must be a number from 1 to 65535.")
		return
	}
	if a.run.running() {
		a.startWith(n, true)
	} else {
		a.run.setPort(n)
		persistPort(a.run.cfg.argsPath, n)
	}
}

func (a *app) more() bool {
	var items []string
	if a.run.running() {
		items = []string{"Restart", "Stop"}
	} else {
		items = []string{"Start"}
	}
	items = append(items, "Change port", "Console log", "Check for updates")
	if a.e.admin != nil && adminNeeded() {
		items = append(items, "Admin setup")
	}
	a.mu.Lock()
	if a.upd != nil && !a.updBusy {
		items = append([]string{"Update now (" + a.upd.text()[5:] + ")"}, items...)
	}
	a.mu.Unlock()
	sel, err := a.e.choose(context.Background(), a.title(), "Action:", items)
	if err != nil || sel == "" {
		return false
	}
	switch {
	case sel == "Restart":
		a.startWith(a.run.getPort(), true)
	case sel == "Stop":
		a.run.stop(4 * time.Second)
	case sel == "Start":
		a.startWith(a.run.getPort(), false)
		go a.openWhenUp()
	case sel == "Change port":
		a.changePort()
	case sel == "Admin setup":
		a.adminSetup()
	case sel == "Console log":
		a.e.open(filepath.Join(a.run.cfg.dir, logName))
	case sel == "Check for updates":
		a.setUpd("checking ...", nil, false)
		a.checkNow()
	default: // Update now
		return a.doUpdate()
	}
	return false
}

// loop shows the main dialog until Quit; it is redrawn when the state changes.
func (a *app) loopDialogs() {
	fails := 0
	for {
		select {
		case <-a.poke:
		default:
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-a.poke:
				cancel()
			case <-ctx.Done():
			}
		}()
		btn, _, err := a.e.dialog(ctx, a.mainSpec())
		redraw := ctx.Err() != nil
		cancel()
		if redraw {
			fails = 0
			continue
		}
		if err == errCancel { // Esc: show the dialog again, Quit is explicit
			continue
		}
		if err != nil {
			if fails++; fails >= 3 {
				fmt.Fprintln(os.Stderr, "dialog failed:", err)
				break
			}
			continue
		}
		fails = 0
		switch btn {
		case "Quit mautg":
			a.mu.Lock()
			a.quit = true
			a.mu.Unlock()
			a.e.toast("mautg: stopping ...")
			a.run.stop(4 * time.Second)
			return
		case "Open web GUI":
			a.openGUI()
		case "Start":
			a.startWith(a.run.getPort(), false)
			go a.openWhenUp()
		case "More...":
			if a.more() {
				return
			}
		}
	}
	a.run.stop(4 * time.Second)
}

// appDirOf returns the folder that holds mautg.py: for .../X/mautg.app/Contents/MacOS/<bin>
// it is X, otherwise the folder of the binary.
func appDirOf(exe string) string {
	d := filepath.Dir(exe)
	if filepath.Base(d) == "MacOS" && filepath.Base(filepath.Dir(d)) == "Contents" &&
		strings.HasSuffix(filepath.Dir(filepath.Dir(d)), ".app") {
		return filepath.Dir(filepath.Dir(filepath.Dir(d)))
	}
	return d
}
