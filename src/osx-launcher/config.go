package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const (
	defaultPort = 8081
	argsFile    = "mautg-args.txt"
	logName     = "mautg-console.log"
)

// config describes how mautg.py is started.
type config struct {
	dir      string   // folder of the launcher (working dir of mautg)
	python   string   // python interpreter path, or "" if none found
	args     []string // arguments for mautg.py (after the script name)
	port     int      // web gui port (for the browser and the stop request)
	argsPath string   // mautg-args.txt (holds the port after a change)
	user     []string // options of the user (file + command line, without the fixed ones)
}

// fieldsLine splits one line of options on blanks; a double-quoted part stays together.
func fieldsLine(s string) []string {
	var out []string
	var cur strings.Builder
	inq, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inq, has = !inq, true
		case (r == ' ' || r == '\t') && !inq:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

// readArgsFile returns the options of the first non-empty, non-comment line.
func readArgsFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(l, string(rune(0xFEFF))))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		return fieldsLine(l)
	}
	return nil
}

// portOf returns the value of the last -port/--port option, or def.
func portOf(args []string, def int) int {
	p := def
	for i := 0; i < len(args); i++ {
		a := args[i]
		v := ""
		switch {
		case (a == "-port" || a == "--port") && i+1 < len(args):
			v = args[i+1]
		case strings.HasPrefix(a, "--port="):
			v = a[len("--port="):]
		}
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			p = n
		}
	}
	return p
}

// findPython prefers the bundled python-<arch>/bin/python3 (or python/bin/python3), then python3 / python on PATH.
func findPython(dir string, lookPath func(string) (string, error)) string {
	for _, c := range []string{
		filepath.Join(dir, pyArchDir(), "bin", "python3"),
		filepath.Join(dir, "python", "bin", "python3"),
	} {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	for _, n := range []string{"python3", "python"} {
		if p, err := lookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// hasOpt: the option (either spelling) is present in args.
func hasOpt(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n || strings.HasPrefix(a, n+"=") {
				return true
			}
		}
	}
	return false
}

// buildConfig: the web port (and -bind) come from the command line / mautg-args.txt,
// else 8081 / 127.0.0.1. The port is always passed explicitly (it wins in mautg.py).
func buildConfig(dir string, cli []string, lookPath func(string) (string, error)) config {
	argsPath := filepath.Join(dir, argsFile)
	user := append(readArgsFile(argsPath), cli...)
	args, port := composeArgs(user)
	return config{dir: dir, python: findPython(dir, lookPath), args: args, port: port, argsPath: argsPath, user: user}
}

// composeArgs: -web, the default -bind, the user options and the explicit -port.
func composeArgs(user []string) ([]string, int) {
	port := portOf(user, defaultPort)
	args := []string{"-web"}
	if !hasOpt(user, "-bind", "--bind") {
		args = append(args, "-bind", "127.0.0.1")
	}
	args = append(args, user...)
	args = append(args, "-port", strconv.Itoa(port))
	return args, port
}

var portTokRe = regexp.MustCompile(`(-port|--port)(\s+|=)\d+`)

// persistPort stores the port in mautg-args.txt (the first option line: an existing
// -port is replaced, else it is appended; without a file one is created). Nothing is
// written for the default port when the file has no -port yet.
func persistPort(path string, port int) error {
	if path == "" {
		return nil
	}
	tok := "-port " + strconv.Itoa(port)
	b, err := os.ReadFile(path)
	if err != nil {
		if port == defaultPort {
			return nil
		}
		return os.WriteFile(path, []byte("# options for mautg.py, one line\n"+tok+"\n"), 0644)
	}
	lines := strings.Split(string(b), "\n")
	for i, raw := range lines {
		t := strings.TrimSpace(strings.TrimPrefix(raw, string(rune(0xFEFF))))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		switch {
		case portTokRe.MatchString(raw):
			lines[i] = portTokRe.ReplaceAllString(raw, "${1} "+strconv.Itoa(port))
		case port == defaultPort:
			return nil
		default:
			cr := ""
			if strings.HasSuffix(raw, "\r") {
				cr = "\r"
			}
			lines[i] = strings.TrimRight(raw, " \t\r") + " " + tok + cr
		}
		return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
	}
	if port == defaultPort {
		return nil
	}
	return os.WriteFile(path, []byte(strings.TrimRight(string(b), "\r\n")+"\n"+tok+"\n"), 0644)
}

// parsePort accepts 1..65535.
func parsePort(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// bindOf returns the value of the last -bind/--bind option, default 127.0.0.1.
func bindOf(args []string) string {
	b := "127.0.0.1"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-bind" || a == "--bind") && i+1 < len(args):
			b = args[i+1]
		case strings.HasPrefix(a, "--bind="):
			b = a[len("--bind="):]
		}
	}
	return b
}

// portBusyError: the web gui port cannot be bound.
type portBusyError struct{ port int }

func (e *portBusyError) Error() string {
	return fmt.Sprintf("Port %d is already in use. Please enter another port and press Start.", e.port)
}

// checkPort tries to bind the port the way mautg will; nil if it is free.
func checkPort(bind string, port int) error {
	l, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return &portBusyError{port}
	}
	l.Close()
	return nil
}

// readVersion returns VERSION from mautg.py ("" if not found).
func readVersion(dir string) string { return pyVersion(dir, "mautg.py") }

// pyArchDir is the folder of the bundled Python for this CPU.
func pyArchDir() string {
	if runtime.GOARCH == "arm64" {
		return "python-aarch64"
	}
	return "python-x86_64"
}
