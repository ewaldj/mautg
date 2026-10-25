package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// runner starts, stops and restarts the mautg.py process.
type runner struct {
	cfg     config
	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{} // closed when the current process has exited
	proc    osProc        // platform part (job object)
	onExit  func(code int, requested bool)
	stopReq bool
	runPort int // port of the running process
}

func (r *runner) running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

func (r *runner) start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		return nil
	}
	if r.cfg.python == "" {
		return fmt.Errorf("python3 not found - reinstall the package (bundled python-* folder missing) or install python3")
	}
	if err := checkPort(bindOf(r.cfg.args), r.cfg.port); err != nil {
		return err
	}
	script := filepath.Join(r.cfg.dir, "mautg.py")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("mautg.py not found next to the launcher")
	}
	logf, err := os.Create(filepath.Join(r.cfg.dir, logName))
	if err != nil {
		return err
	}
	args := append([]string{"-X", "utf8", script}, r.cfg.args...)
	cmd := exec.Command(r.cfg.python, args...)
	cmd.Dir = r.cfg.dir
	cmd.Env = append(launchEnv(r.cfg.dir), "PYTHONUTF8=1", "PYTHONUNBUFFERED=1")
	cmd.Stdout, cmd.Stderr = logf, logf
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		logf.Close()
		return err
	}
	r.proc.attach(cmd) // children die with the job
	done := make(chan struct{})
	r.cmd, r.done, r.stopReq, r.runPort = cmd, done, false, r.cfg.port
	go func() {
		err := cmd.Wait()
		logf.Close()
		code := 0
		if err != nil {
			code = -1
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			}
		}
		r.mu.Lock()
		req := r.stopReq
		r.cmd = nil
		r.mu.Unlock()
		close(done)
		if r.onExit != nil {
			r.onExit(code, req)
		}
	}()
	return nil
}

// stop asks mautg to exit through its web api (clean log close), then kills the
// process tree after 'grace'.
func (r *runner) stop(grace time.Duration) {
	r.mu.Lock()
	cmd, done, port := r.cmd, r.done, r.runPort
	if cmd != nil {
		r.stopReq = true
	}
	r.mu.Unlock()
	if cmd == nil {
		return
	}
	c := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/command", port)
	if req, err := http.NewRequest("POST", url, bytes.NewBufferString(`{"cmd":"exit","value":"","data":{}}`)); err == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "mautg") // mautg refuses POSTs without it (403)
		if resp, err := c.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	select {
	case <-done:
		return
	case <-time.After(grace):
	}
	r.proc.kill(cmd)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

// setPort changes the web gui port for the next start.
func (r *runner) setPort(p int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg.args = append(append([]string{}, r.cfg.args...), "-port", strconv.Itoa(p))
	r.cfg.port = p
}

func (r *runner) getPort() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.port
}

func (r *runner) restart() error {
	r.stop(4 * time.Second)
	return r.start()
}
