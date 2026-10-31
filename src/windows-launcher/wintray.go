//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")

	pRegisterClassEx  = user32.NewProc("RegisterClassExW")
	pCreateWindowEx   = user32.NewProc("CreateWindowExW")
	pDefWindowProc    = user32.NewProc("DefWindowProcW")
	pGetMessage       = user32.NewProc("GetMessageW")
	pTranslateMessage = user32.NewProc("TranslateMessage")
	pDispatchMessage  = user32.NewProc("DispatchMessageW")
	pPostMessage      = user32.NewProc("PostMessageW")
	pPostQuitMessage  = user32.NewProc("PostQuitMessage")
	pDestroyWindow    = user32.NewProc("DestroyWindow")
	pSetForegroundWin = user32.NewProc("SetForegroundWindow")
	pLoadIcon         = user32.NewProc("LoadIconW")
	pLoadCursor       = user32.NewProc("LoadCursorW")
	pMessageBox       = user32.NewProc("MessageBoxW")
	pIsDialogMessage  = user32.NewProc("IsDialogMessageW")
	pGetWindowText    = user32.NewProc("GetWindowTextW")
	pSetWindowText    = user32.NewProc("SetWindowTextW")
	pSendMessage      = user32.NewProc("SendMessageW")
	pSetFocus         = user32.NewProc("SetFocus")
	pEnableWindow     = user32.NewProc("EnableWindow")
	pShowWindow       = user32.NewProc("ShowWindow")
	pLoadImage        = user32.NewProc("LoadImageW")
	pBeginPaint       = user32.NewProc("BeginPaint")
	pEndPaint         = user32.NewProc("EndPaint")
	pGetSysColor      = user32.NewProc("GetSysColor")
	pGetSysColorBrush = user32.NewProc("GetSysColorBrush")
	pCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	pSelectObject     = gdi32.NewProc("SelectObject")
	pDeleteObject     = gdi32.NewProc("DeleteObject")
	pEllipse          = gdi32.NewProc("Ellipse")
	pCreatePen        = gdi32.NewProc("CreatePen")
	pSetTextColor     = gdi32.NewProc("SetTextColor")
	pSetBkColor       = gdi32.NewProc("SetBkColor")
	pGetStockObject   = gdi32.NewProc("GetStockObject")
	pShellExecute     = shell32.NewProc("ShellExecuteW")
	pDrawIconEx       = user32.NewProc("DrawIconEx")
	pGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	pCreateMutex      = kernel32.NewProc("CreateMutexW")
	pCreateJob        = kernel32.NewProc("CreateJobObjectW")
	pSetInfoJob       = kernel32.NewProc("SetInformationJobObject")
	pAssignJob        = kernel32.NewProc("AssignProcessToJobObject")
	pTerminateJob     = kernel32.NewProc("TerminateJobObject")
	pOpenProcess      = kernel32.NewProc("OpenProcess")
	pCloseHandle      = kernel32.NewProc("CloseHandle")
	pGetLastError     = kernel32.NewProc("GetLastError")
)

const (
	wmCommand = 0x0111
	wmClose   = 0x0010
	wmApp     = 0x8000

	createNoWindow = 0x08000000
)

// ---- process part (hidden window, job object, children die with python) ----

type osProc struct{ job uintptr }

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

func (p *osProc) attach(cmd *exec.Cmd) {
	job, _, _ := pCreateJob.Call(0, 0)
	if job == 0 {
		return
	}
	var info [144]byte                             // JOBOBJECT_EXTENDED_LIMIT_INFORMATION (x64)
	*(*uint32)(unsafe.Pointer(&info[16])) = 0x2000 // KILL_ON_JOB_CLOSE
	pSetInfoJob.Call(job, 9, uintptr(unsafe.Pointer(&info[0])), uintptr(len(info)))
	h, _, _ := pOpenProcess.Call(0x1F0FFF, 0, uintptr(cmd.Process.Pid))
	if h != 0 {
		pAssignJob.Call(job, h)
		pCloseHandle.Call(h)
	}
	p.job = job
}

func (p *osProc) kill(cmd *exec.Cmd) {
	if p.job != 0 {
		pTerminateJob.Call(p.job, 1)
		pCloseHandle.Call(p.job)
		p.job = 0
	}
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}

// ---- main window ----

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  uintptr
	lpszClassName uintptr
	hIconSm       uintptr
}

type point struct{ x, y int32 }

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func msgBox(text string, flags uintptr) {
	pMessageBox.Call(hwndMain, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16("mautg"))), flags)
}

// msgBoxRet shows a message box (no owner window yet) and returns the pressed button.
func msgBoxRet(text string, flags uintptr) int {
	r, _, _ := pMessageBox.Call(hwndMain, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16("mautg"))), flags)
	return int(r)
}

func adminTag() string {
	if isElevated() {
		return " [admin]"
	}
	return ""
}

func rightsText() string {
	if isElevated() {
		return "administrator (DSCP, firewall rule)"
	}
	return "standard user (no DSCP marking)"
}

func openTarget(what string) {
	pShellExecute.Call(0, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(what))), 0, 0, 1)
}

const (
	idEdit    = 101
	idStart   = 11
	idStop    = 12
	idRestart = 13
	idOpen    = 14
	idLog     = 15
	idExit    = 16
	idLink    = 17
	idUpdate  = 18
	idAdmin   = 19
	idNoCfg   = 20
	idCli     = 102

	wmState  = wmApp + 2
	wmNotify = wmApp + 3
	wmFinish = wmApp + 4
	wmUpdate = wmApp + 5
	wmFoot   = wmApp + 6
)

var (
	hwndMain, hStatus, hEdit, hLink uintptr
	hCli, hNoCfg, hSmall            uintptr
	hUpdTxt, hFoot, hRights         uintptr
	updMu                           sync.Mutex
	updNow                          *updInfo // newer files on GitHub, nil = current
	updText                         = "checking ..."
	updBusy                         bool
	btn                             = map[uintptr]uintptr{}
	run                             *runner
	noteMu                          sync.Mutex
	note                            string // message to show on the UI thread
	noteFlags                       uintptr
	lastExit                        string
	closing                         bool
)

// drawPaw paints the mautg paw (same ellipses as the web GUI favicon, 24x24 grid).
func drawPaw(hdc uintptr, x, y int, k float64) {
	brush, _, _ := pCreateSolidBrush.Call(0x00343B4A) // #4a3b34 (BGR)
	pen, _, _ := pCreatePen.Call(5, 0, 0)             // PS_NULL
	ob, _, _ := pSelectObject.Call(hdc, brush)
	op, _, _ := pSelectObject.Call(hdc, pen)
	for _, e := range [][4]float64{{12, 16.5, 5.4, 4.3}, {5.2, 10.5, 2.5, 3.1}, {18.8, 10.5, 2.5, 3.1}, {8.9, 5.6, 2.4, 3.1}, {15.1, 5.6, 2.4, 3.1}} {
		l, t := int(float64(x)+(e[0]-e[2])*k*1.0), int(float64(y)+(e[1]-e[3])*k*1.0)
		r, b := int(float64(x)+(e[0]+e[2])*k*1.0)+1, int(float64(y)+(e[1]+e[3])*k*1.0)+1
		pEllipse.Call(hdc, uintptr(l), uintptr(t), uintptr(r), uintptr(b))
	}
	pSelectObject.Call(hdc, ob)
	pSelectObject.Call(hdc, op)
	pDeleteObject.Call(brush)
	pDeleteObject.Call(pen)
}

func setText(h uintptr, s string) { pSetWindowText.Call(h, uintptr(unsafe.Pointer(u16(s)))) }

func getText(h uintptr) string {
	n, _, _ := pSendMessage.Call(h, 0x0E, 0, 0) // WM_GETTEXTLENGTH
	buf := make([]uint16, int(n)+2)
	pGetWindowText.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}

// optionsFromWindow reads the CLI options field and the Def-Config checkbox (UI thread).
func optionsFromWindow() (string, bool) {
	c, _, _ := pSendMessage.Call(hNoCfg, 0xF0, 0, 0) // BM_GETCHECK
	return getText(hCli), c == 1
}

func enable(id uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pEnableWindow.Call(btn[id], v)
}

// refresh shows the real state of the runner (UI thread only).
func refresh() {
	running := run.running()
	if running {
		setText(hStatus, fmt.Sprintf("running  -  http://127.0.0.1:%d", run.getPort()))
	} else if lastExit != "" {
		setText(hStatus, lastExit)
	} else {
		setText(hStatus, "stopped")
	}
	enable(idStart, !running)
	enable(idStop, running)
	enable(idRestart, running)
	enable(idOpen, running)
	pEnableWindow.Call(hEdit, 1)
}

func busy(s string) {
	setText(hStatus, s)
	for _, id := range []uintptr{idStart, idStop, idRestart, idOpen} {
		enable(id, false)
	}
}

func postNote(s string, flags uintptr) {
	noteMu.Lock()
	note, noteFlags = s, flags
	noteMu.Unlock()
	pPostMessage.Call(hwndMain, wmNotify, 0, 0)
}

// portFromField validates the port field; 0 and a message box if invalid.
func portFromField() int {
	n := parsePort(getText(hEdit))
	if n == 0 {
		msgBox("The port must be a number from 1 to 65535.", 0x30)
		pSetFocus.Call(hEdit)
	}
	return n
}

// startWith applies the port field and starts mautg (background thread).
func startWith(n int, stopFirst bool) {
	if stopFirst {
		run.stop(4 * time.Second)
	}
	run.setPort(n)
	persistPort(run.cfg.argsPath, n)
	lastExit = ""
	if err := run.start(); err != nil {
		lastExit = "stopped"
		postNote(err.Error(), 0x30)
	}
	pPostMessage.Call(hwndMain, wmState, 0, 0)
}

// showUpdate applies the update state to the window (UI thread only).
func showUpdate() {
	updMu.Lock()
	txt, have, busyNow := updText, updNow != nil, updBusy
	updMu.Unlock()
	setText(hUpdTxt, txt)
	if have && !busyNow {
		pShowWindow.Call(btn[idUpdate], 5)
	} else {
		pShowWindow.Call(btn[idUpdate], 0)
	}
}

func setUpdState(txt string, info *updInfo, busyNow bool) {
	updMu.Lock()
	updText, updNow, updBusy = txt, info, busyNow
	updMu.Unlock()
	pPostMessage.Call(hwndMain, wmUpdate, 0, 0)
}

// checkLoop checks GitHub shortly after the start and then every 6 hours.
func checkLoop() {
	time.Sleep(3 * time.Second)
	for {
		updMu.Lock()
		skip := updBusy || updNow != nil
		updMu.Unlock()
		if !skip && !closing {
			info, err := checkUpdate(run.cfg.dir, updateBase())
			switch {
			case err != nil:
				setUpdState("check failed (offline?)", nil, false)
			case info == nil:
				setUpdState("up to date", nil, false)
			default:
				setUpdState(info.text(), info, false)
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

// doUpdate stops mautg, replaces the scripts, restarts mautg if it was running.
func doUpdate() {
	updMu.Lock()
	info := updNow
	updMu.Unlock()
	if info == nil {
		return
	}
	setUpdState("updating ...", info, true)
	wasRunning := run.running()
	if wasRunning {
		run.stop(4 * time.Second)
	}
	if info.full {
		if err := applyFull(run.cfg.dir, updateBase()); err != nil {
			setUpdState("update failed", info, false)
			postNote("Update failed:\n"+err.Error(), 0x30)
			pPostMessage.Call(hwndMain, wmFoot, 0, 0)
			if wasRunning {
				startWith(run.getPort(), false)
			} else {
				pPostMessage.Call(hwndMain, wmState, 0, 0)
			}
			return
		}
		// start the new launcher, it waits for this instance to exit
		exe := filepath.Join(run.cfg.dir, "mautg.exe")
		args := append([]string{"--after-update"}, os.Args[1:]...)
		if err := exec.Command(exe, args...).Start(); err != nil {
			postNote("Updated, but restart failed - please start mautg.exe manually:\n"+err.Error(), 0x30)
		}
		closing = true
		pPostMessage.Call(hwndMain, wmFinish, 0, 0)
		return
	}
	err := applyUpdate(run.cfg.dir, updateBase(), info)
	if err != nil {
		setUpdState("update failed", info, false)
		postNote("Update failed - nothing was changed:\n"+err.Error(), 0x30)
	} else {
		setUpdState("updated", nil, false)
		postNote("Updated: "+info.text()[5:]+"", 0x40)
	}
	pPostMessage.Call(hwndMain, wmFoot, 0, 0)
	if wasRunning {
		startWith(run.getPort(), false)
	} else {
		pPostMessage.Call(hwndMain, wmState, 0, 0)
	}
}

func wndProc(hwnd, m, wp, lp uintptr) uintptr {
	switch uint32(m) {
	case wmCommand:
		switch wp & 0xFFFF {
		case 1, idStart: // 1 = Enter (IDOK)
			if closing || run.running() {
				return 0
			}
			if n := portFromField(); n != 0 {
				busy("starting ...")
				cli, nc := optionsFromWindow()
				go func() { run.setOptions(cli, nc); startWith(n, false) }()
			}
		case idRestart:
			if n := portFromField(); n != 0 {
				busy("restarting ...")
				cli, nc := optionsFromWindow()
				go func() { run.setOptions(cli, nc); startWith(n, true) }()
			}
		case idStop:
			busy("stopping ...")
			go func() { run.stop(4 * time.Second); pPostMessage.Call(hwnd, wmState, 0, 0) }()
		case idOpen:
			openTarget(fmt.Sprintf("http://127.0.0.1:%d", run.getPort()))
		case idLog:
			openTarget(filepath.Join(run.cfg.dir, logName))
		case idUpdate:
			go doUpdate()
		case idAdmin:
			go func() {
				if relaunchElevated(os.Args[1:]) {
					pPostMessage.Call(hwnd, wmClose, 0, 0) // stops mautg, then the new instance starts
				}
			}()
		case idLink:
			openTarget("https://www.jeitler.cc")
		case idExit:
			pPostMessage.Call(hwnd, wmClose, 0, 0)
		}
		return 0
	case wmState:
		if !closing {
			refresh()
		}
		return 0
	case wmUpdate:
		if !closing {
			showUpdate()
		}
		return 0
	case wmFoot:
		if v := readVersion(run.cfg.dir); v != "" {
			setText(hFoot, "mautg.py v"+v+"  -")
		}
		return 0
	case wmNotify:
		noteMu.Lock()
		s, fl := note, noteFlags
		note = ""
		noteMu.Unlock()
		if s != "" {
			msgBox(s, fl)
		}
		return 0
	case wmClose:
		if closing {
			return 0
		}
		closing = true
		busy("exiting ...")
		go func() {
			run.stop(4 * time.Second)
			pPostMessage.Call(hwnd, wmFinish, 0, 0)
		}()
		return 0
	case wmFinish:
		pDestroyWindow.Call(hwnd)
		return 0
	case 0x000F: // WM_PAINT
		var ps [72]byte // PAINTSTRUCT (x64)
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps[0])))
		pDrawIconEx.Call(hdc, 14, 328, hSmall, 16, 16, 0, 0, 3) // the app icon, same as on macOS
		pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps[0])))
		return 0
	case 0x0138: // WM_CTLCOLORSTATIC
		if lp == hLink {
			col, _, _ := pGetSysColor.Call(15)
			pSetTextColor.Call(wp, 0x00CC6600) // link blue (BGR)
			pSetBkColor.Call(wp, col)
			br, _, _ := pGetSysColorBrush.Call(15)
			return br
		}
	case 0x0082: // WM_NCDESTROY
		pPostQuitMessage.Call(0)
	}
	r, _, _ := pDefWindowProc.Call(hwnd, m, wp, lp)
	return r
}

func main() {
	runtime.LockOSThread()
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)

	// one instance per user session
	args := os.Args[1:]
	after := len(args) > 0 && (args[0] == "--after-update" || args[0] == "--elevated")
	if after {
		args = args[1:]
	}
	var h, e uintptr
	for i := 0; ; i++ {
		h, _, _ = pCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(u16("Local\\mautgLauncher"))))
		e, _, _ = pGetLastError.Call()
		if h != 0 && e != 183 {
			break
		}
		if !after || i >= 60 { // after an update wait for the old instance to exit
			msgBox("mautg is already running.", 0x40)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	cleanOld(dir)

	cfg := buildConfig(dir, args, exec.LookPath)
	if !isElevated() && adminAsk() {
		switch msgBoxRet(adminDialogText, 0x23) { // MB_YESNOCANCEL | MB_ICONQUESTION
		case 6: // Yes
			if relaunchElevated(args) {
				return // the new instance waits for this one to exit
			}
		case 7: // No
			adminAskOff()
		}
	}
	run = &runner{cfg: cfg}
	run.onExit = func(code int, requested bool) {
		if !requested && code == 0 {
			// clean exit, e.g. EXIT in the web GUI - information only
			lastExit = "stopped (exit from web GUI)"
			postNote("mautg was stopped (EXIT in the web GUI).", 0x40)
		} else if !requested {
			lastExit = fmt.Sprintf("stopped unexpectedly (exit code %d)", code)
			postNote(fmt.Sprintf("mautg stopped unexpectedly (exit code %d).\nIf the port is in use, enter another port and press Start.\nSee the console log for details.", code), 0x30)
		}
		pPostMessage.Call(hwndMain, wmState, 0, 0)
	}

	inst, _, _ := pGetModuleHandle.Call(0)
	icon, _, _ := pLoadIcon.Call(inst, 1) // embedded EP logo (resource id 1)
	if icon == 0 {
		icon, _, _ = pLoadIcon.Call(0, 32512) // IDI_APPLICATION
	}
	small, _, _ := pLoadImage.Call(inst, 1, 1, 16, 16, 0)
	if small == 0 {
		small = icon
	}
	hSmall = small
	cur, _, _ := pLoadCursor.Call(0, 32512)
	cls := u16("mautgLauncherWnd")
	wc := wndClassEx{
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     inst,
		hIcon:         icon,
		hIconSm:       small,
		hCursor:       cur,
		hbrBackground: 16, // COLOR_BTNFACE + 1
		lpszClassName: uintptr(unsafe.Pointer(cls)),
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	if r, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		msgBox("cannot register window class", 0x10)
		return
	}
	// WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX (fixed size), WS_EX_CONTROLPARENT
	hwndMain, _, _ = pCreateWindowEx.Call(0x10000, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(u16("mautg (Windows) v"+launcherVersion+adminTag()))),
		0x00C00000|0x00080000|0x00020000, 200, 200, 380, 410, 0, 0, inst, 0)
	if hwndMain == 0 {
		msgBox("cannot create window", 0x10)
		return
	}
	font, _, _ := pGetStockObject.Call(17) // DEFAULT_GUI_FONT
	mk := func(class, text string, style uintptr, x, y, w, h, id uintptr) uintptr {
		// WS_CHILD|WS_VISIBLE
		hw, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))),
			0x50000000|style, x, y, w, h, hwndMain, id, inst, 0)
		pSendMessage.Call(hw, 0x30, font, 1) // WM_SETFONT
		return hw
	}
	const tab = 0x00010000
	mk("STATIC", "Status:", 0, 14, 16, 60, 18, 0)
	hStatus = mk("STATIC", "starting ...", 0, 78, 16, 280, 18, 0)
	mk("STATIC", "Web port:", 0, 14, 48, 60, 18, 0)
	// WS_BORDER | ES_NUMBER
	hEdit = mk("EDIT", fmt.Sprint(cfg.port), tab|0x00800000|0x2000, 78, 44, 70, 22, idEdit)
	pSendMessage.Call(hEdit, 0xC5, 5, 0) // EM_LIMITTEXT
	mk("STATIC", "applied with Start / Restart", 0, 158, 48, 200, 18, 0)
	btn[idStart] = mk("BUTTON", "Start", tab|1, 14, 84, 108, 28, idStart) // BS_DEFPUSHBUTTON
	btn[idStop] = mk("BUTTON", "Stop", tab, 134, 84, 108, 28, idStop)
	btn[idRestart] = mk("BUTTON", "Restart", tab, 254, 84, 108, 28, idRestart)
	btn[idOpen] = mk("BUTTON", "Open web GUI", tab, 14, 124, 108, 28, idOpen)
	btn[idLog] = mk("BUTTON", "Console log", tab, 134, 124, 108, 28, idLog)
	btn[idExit] = mk("BUTTON", "Exit", tab, 254, 124, 108, 28, idExit)

	// options (same as the macOS launcher): Def-Config checkbox and free CLI options
	hNoCfg = mk("BUTTON", "Disable Def-Config", tab|3, 14, 166, 260, 20, idNoCfg) // BS_AUTOCHECKBOX
	mk("STATIC", "CLI options:", 0, 14, 204, 74, 18, 0)
	hCli = mk("EDIT", "", tab|0x00800000|0x80, 90, 200, 270, 22, idCli) // WS_BORDER | ES_AUTOHSCROLL
	cliText, noCfg := run.optionsText()
	setText(hCli, cliText)
	if noCfg {
		pSendMessage.Call(hNoCfg, 0xF1, 1, 0) // BM_SETCHECK
	}

	mk("STATIC", "Rights:", 0, 14, 240, 60, 18, 0)
	hRights = mk("STATIC", rightsText(), 0, 78, 240, 170, 18, 0)
	btn[idAdmin] = mk("BUTTON", "Admin", tab, 254, 234, 108, 28, idAdmin)
	if isElevated() {
		pShowWindow.Call(btn[idAdmin], 0) // already administrator
	}

	mk("STATIC", "Update:", 0, 14, 280, 60, 18, 0)
	hUpdTxt = mk("STATIC", updText, 0, 78, 280, 170, 18, 0)
	btn[idUpdate] = mk("BUTTON", "Update", tab, 254, 274, 108, 28, idUpdate)
	pShowWindow.Call(btn[idUpdate], 0)         // appears only when GitHub has a newer version
	mk("STATIC", "", 0x10, 14, 316, 340, 2, 0) // SS_ETCHEDHORZ separator
	ver := readVersion(dir)
	if ver != "" {
		ver = " v" + ver
	}
	foot := "mautg.py" + ver + "  -"
	hFoot = mk("STATIC", foot, 0, 40, 330, 8*uintptr(len(foot)), 18, 0)
	hLink = mk("STATIC", "www.jeitler.cc", 0x100, 40+8*uintptr(len(foot))+4, 330, 110, 18, idLink) // SS_NOTIFY

	pShowWindow.Call(hwndMain, 1)
	pSetForegroundWin.Call(hwndMain)

	go checkLoop()
	go func() { // auto start; a busy port is reported, the user can pick another
		ensureFirewall(cfg.python) // administrator only: inbound UDP rule for python.exe
		startWith(cfg.port, false)
		if run.waitUp(30 * time.Second) { // open the browser when mautg answers
			openTarget(fmt.Sprintf("http://127.0.0.1:%d", run.getPort()))
		}
	}()

	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if d, _, _ := pIsDialogMessage.Call(hwndMain, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}
