package main

import (
	"os"
	"strconv"
	"strings"
)

// noConfigOpt starts mautg without reading ~/.mau/config.json (checkbox "Disable Def-Config").
const noConfigOpt = "--no-config"

// joinFields is the inverse of fieldsLine: a token with blanks is put in double quotes.
func joinFields(a []string) string {
	out := make([]string, len(a))
	for i, t := range a {
		if strings.ContainsAny(t, " \t") {
			t = `"` + t + `"`
		}
		out[i] = t
	}
	return strings.Join(out, " ")
}

// splitUser separates the options of the launcher window from the free CLI options:
// -port N / --port N / --port=N belong to the port field, --no-config to the checkbox.
func splitUser(user []string) (cli string, noCfg bool) {
	var rest []string
	for i := 0; i < len(user); i++ {
		a := user[i]
		switch {
		case a == noConfigOpt:
			noCfg = true
		case a == "-port" || a == "--port":
			i++ // its value
		case strings.HasPrefix(a, "--port="):
		default:
			rest = append(rest, a)
		}
	}
	return joinFields(rest), noCfg
}

// writeOptions stores the option line of mautg-args.txt (comment lines are kept, the
// first option line is replaced). Nothing is created for an all-default setup.
func writeOptions(path string, user []string, port int) error {
	if path == "" {
		return nil
	}
	line := joinFields(user)
	if port != defaultPort {
		if line != "" {
			line += " "
		}
		line += "-port " + strconv.Itoa(port)
	}
	var keep []string
	b, err := os.ReadFile(path)
	if err != nil {
		if line == "" {
			return nil
		}
		keep = []string{"# options for mautg.py, one line"}
	} else {
		for _, l := range strings.Split(strings.TrimRight(string(b), "\r\n"), "\n") {
			t := strings.TrimSpace(strings.TrimPrefix(l, string(rune(0xFEFF))))
			if t == "" || strings.HasPrefix(t, "#") {
				keep = append(keep, strings.TrimRight(l, "\r"))
			}
		}
	}
	if line != "" {
		keep = append(keep, line)
	}
	return os.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0644)
}

// setOptions applies the window options (free CLI text + Def-Config checkbox) for the next
// start and stores them in mautg-args.txt together with the current port.
func (r *runner) setOptions(cliText string, noCfg bool) {
	cli, n2 := splitUser(fieldsLine(cliText))
	user := fieldsLine(cli)
	if noCfg || n2 {
		user = append(user, noConfigOpt)
	}
	r.mu.Lock()
	port := r.cfg.port
	args, _ := composeArgs(user)
	args[len(args)-1] = strconv.Itoa(port) // composeArgs ends with -port <n>
	r.cfg.args, r.cfg.user = args, user
	path := r.cfg.argsPath
	r.mu.Unlock()
	writeOptions(path, user, port)
}

// optionsText returns what the window shows: the CLI text and the checkbox state.
func (r *runner) optionsText() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return splitUser(r.cfg.user)
}
