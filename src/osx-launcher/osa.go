package main

import (
	"errors"
	"strings"
)

// Helpers for AppleScript dialogs (osascript). Pure string handling, testable anywhere.

// osaFront brings the dialog in front of other windows.
const osaFront = "tell current application to activate\n"

var errCancel = errors.New("canceled")

// osaStr returns an AppleScript expression for s (newlines become linefeed).
func osaStr(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	parts := strings.Split(s, "\n")
	for i, p := range parts {
		p = strings.ReplaceAll(p, `\`, `\\`)
		p = strings.ReplaceAll(p, `"`, `\"`)
		parts[i] = `"` + p + `"`
	}
	return "(" + strings.Join(parts, " & linefeed & ") + ")"
}

func osaList(items []string) string {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = osaStr(it)
	}
	return "{" + strings.Join(q, ", ") + "}"
}

// spec describes one dialog.
type spec struct {
	title, text string
	buttons     []string // at most 3, left to right
	def         int      // index of the default button
	answer      string   // non-empty: text input with this default
	input       bool
	icon        string // POSIX path of an .icns file, optional
}

func dialogScript(s spec) string {
	var b strings.Builder
	b.WriteString(osaFront + "display dialog " + osaStr(s.text) + " with title " + osaStr(s.title))
	b.WriteString(" buttons " + osaList(s.buttons))
	if s.def >= 0 && s.def < len(s.buttons) {
		b.WriteString(" default button " + osaStr(s.buttons[s.def]))
	}
	if s.input {
		b.WriteString(" default answer " + osaStr(s.answer))
	}
	if s.icon != "" {
		b.WriteString(" with icon (POSIX file " + osaStr(s.icon) + ")")
	}
	return b.String()
}

func listScript(title, prompt string, items []string) string {
	return osaFront + "choose from list " + osaList(items) + " with title " + osaStr(title) +
		" with prompt " + osaStr(prompt) + " default items {" + osaStr(items[0]) + "}"
}

// parseDialog reads "button returned:X, text returned:Y".
func parseDialog(out string) (button, text string) {
	out = strings.TrimRight(out, "\r\n")
	const bk, tk = "button returned:", ", text returned:"
	i := strings.Index(out, bk)
	if i < 0 {
		return "", ""
	}
	rest := out[i+len(bk):]
	if j := strings.Index(rest, tk); j >= 0 {
		return rest[:j], rest[j+len(tk):]
	}
	return strings.TrimSuffix(rest, ","), ""
}

// parseList: the chosen item, "" if "false" (canceled).
func parseList(out string) string {
	out = strings.TrimRight(out, "\r\n")
	if out == "false" {
		return ""
	}
	return out
}
