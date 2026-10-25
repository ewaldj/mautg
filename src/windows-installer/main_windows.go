//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
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
	pIsUserAnAdmin    = shell32.NewProc("IsUserAnAdmin")
	pGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmCommand  = 0x0111
	wmClose    = 0x0010
	wmApp      = 0x8000
	wmProgress = wmApp + 1
	wmDone     = wmApp + 2

	bmGetCheck = 0x00F0
	bmSetCheck = 0x00F1

	createNoWindow = 0x08000000
)

const (
	idUser    = 21
	idAll     = 22
	idDir     = 23
	idDesktop = 24
	idStart   = 25
	idInstall = 1 // IDOK, default button
	idCancel  = 2
	idLink    = 27

	appName   = "mautg"
	uninstKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\mautg`
)

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

var (
	hwndMain, hStatus, hDir, hLink uintptr
	ctl                            = map[uintptr]uintptr{}
	progMu                         sync.Mutex
	progText                       string
	installing                     bool
	uninstallMode                  bool
	lastErr                        error
	startAfter                     string // path to start when the window closes after success
)

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func msgBox(text string, flags uintptr) uintptr {
	r, _, _ := pMessageBox.Call(hwndMain, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16("mautg installer"))), flags)
	return r
}

func openTarget(what, dir string) {
	var d uintptr
	if dir != "" {
		d = uintptr(unsafe.Pointer(u16(dir)))
	}
	pShellExecute.Call(0, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(what))), 0, d, 1)
}

func isAdmin() bool { r, _, _ := pIsUserAnAdmin.Call(); return r != 0 }

func setText(h uintptr, s string) { pSetWindowText.Call(h, uintptr(unsafe.Pointer(u16(s)))) }

func getText(h uintptr) string {
	buf := make([]uint16, 520)
	pGetWindowText.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}

func checked(id uintptr) bool { r, _, _ := pSendMessage.Call(ctl[id], bmGetCheck, 0, 0); return r == 1 }

func setCheck(id uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pSendMessage.Call(ctl[id], bmSetCheck, v, 0)
}

func enable(id uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pEnableWindow.Call(ctl[id], v)
}

func progress(s string) {
	progMu.Lock()
	progText = s
	progMu.Unlock()
	pPostMessage.Call(hwndMain, wmProgress, 0, 0)
}

// ---- folders ----

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func defaultDir(all bool) string {
	if all {
		return filepath.Join(env("ProgramFiles", `C:\Program Files`), appName)
	}
	return filepath.Join(env("LOCALAPPDATA", filepath.Join(env("USERPROFILE", `C:\`), "AppData", "Local")), "Programs", appName)
}

func startMenuDir(all bool) string {
	if all {
		return filepath.Join(env("ProgramData", `C:\ProgramData`), `Microsoft\Windows\Start Menu\Programs`, appName)
	}
	return filepath.Join(env("APPDATA", ""), `Microsoft\Windows\Start Menu\Programs`, appName)
}

func desktopDir(all bool) string {
	if all {
		return filepath.Join(env("PUBLIC", `C:\Users\Public`), "Desktop")
	}
	return filepath.Join(env("USERPROFILE", ""), "Desktop")
}

func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

func runPS(script string) error {
	f, err := os.CreateTemp("", "mautg-inst-*.ps1")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// UTF-8 with BOM so PowerShell reads non-ASCII paths correctly
	f.WriteString(string(rune(0xFEFF)) + script)
	f.Close()
	out, err := hidden(exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f.Name())).CombinedOutput()
	if err != nil {
		return fmt.Errorf("shortcut creation failed: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func regAdd(root string, args ...string) error {
	a := append([]string{"add", root + `\` + uninstKey, "/f"}, args...)
	out, err := hidden(exec.Command("reg.exe", a...)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("registry: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0755)
}

// ---- install ----

type options struct {
	all, desktop, start bool
	dir                 string
}

func install(o options) error {
	root := "HKCU"
	if o.all {
		root = "HKLM"
	}
	tmp := filepath.Join(os.TempDir(), "mautg-windows-download.zip")
	defer os.Remove(tmp)
	progress("downloading ...")
	err := downloadFile(zipURL(), tmp, func(done, total int64) {
		if total > 0 {
			progress(fmt.Sprintf("downloading ... %.1f / %.1f MB", float64(done)/1048576, float64(total)/1048576))
		} else {
			progress(fmt.Sprintf("downloading ... %.1f MB", float64(done)/1048576))
		}
	})
	if err != nil {
		return err
	}
	progress("installing files ...")
	if err := extractZip(tmp, o.dir, func(i, n int) {
		if i%20 == 0 {
			progress(fmt.Sprintf("installing files ... %d / %d", i, n))
		}
	}); err != nil {
		return err
	}
	exe, _ := os.Executable()
	if err := copyFile(exe, filepath.Join(o.dir, "uninstall.exe")); err != nil {
		return err
	}
	if o.all { // mautg writes its console log and mautg-args.txt into its folder: let normal users do that
		hidden(exec.Command("icacls.exe", o.dir, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q")).Run()
	}
	progress("creating shortcuts ...")
	target := filepath.Join(o.dir, "mautg.exe")
	sm := startMenuDir(o.all)
	items := []shortcut{
		{filepath.Join(sm, "mautg.lnk"), target, "", o.dir, target + ",0", "mautg - ICMP reachability monitor"},
		{filepath.Join(sm, "Uninstall mautg.lnk"), filepath.Join(o.dir, "uninstall.exe"), uninstArgs(o.all), o.dir, target + ",0", "Remove mautg"},
	}
	if o.desktop {
		items = append(items, shortcut{filepath.Join(desktopDir(o.all), "mautg.lnk"), target, "", o.dir, target + ",0", "mautg - ICMP reachability monitor"})
	}
	if err := runPS(shortcutScript(items)); err != nil {
		return err
	}
	progress("registering ...")
	ver := pyVersion(o.dir, "mautg.py")
	un := fmt.Sprintf(`"%s" %s`, filepath.Join(o.dir, "uninstall.exe"), uninstArgs(o.all))
	for _, kv := range [][]string{
		{"DisplayName", "mautg"}, {"DisplayVersion", ver}, {"Publisher", "Ewald Jeitler"},
		{"InstallLocation", o.dir}, {"DisplayIcon", target + ",0"}, {"UninstallString", un},
		{"URLInfoAbout", "https://www.jeitler.cc"},
	} {
		if err := regAdd(root, "/v", kv[0], "/t", "REG_SZ", "/d", kv[1]); err != nil {
			return err
		}
	}
	for _, n := range []string{"NoModify", "NoRepair"} {
		regAdd(root, "/v", n, "/t", "REG_DWORD", "/d", "1")
	}
	if o.start {
		startAfter = target
	}
	return nil
}

func uninstArgs(all bool) string {
	if all {
		return "/uninstall /allusers"
	}
	return "/uninstall"
}

func uninstall(all bool) error {
	root := "HKCU"
	if all {
		root = "HKLM"
	}
	dir := filepath.Dir(mustExe())
	progress("removing ...")
	if errs := removeInstalled(dir, "uninstall.exe"); len(errs) > 0 {
		return fmt.Errorf("%v\n(is mautg still running? close it and try again)", errs[0])
	}
	os.RemoveAll(startMenuDir(all))
	os.Remove(filepath.Join(desktopDir(all), "mautg.lnk"))
	hidden(exec.Command("reg.exe", "delete", root+`\`+uninstKey, "/f")).Run()
	// uninstall.exe cannot delete itself while running: a hidden cmd does it after exit
	hidden(exec.Command("cmd.exe", "/c", fmt.Sprintf(`ping -n 3 127.0.0.1 >nul & del /f /q "%s" & rmdir "%s"`, mustExe(), dir))).Start()
	return nil
}

func mustExe() string { e, _ := os.Executable(); return e }

// ---- window ----

func drawPaw(hdc uintptr, x, y int, k float64) {
	brush, _, _ := pCreateSolidBrush.Call(0x00343B4A) // #4a3b34 (BGR)
	pen, _, _ := pCreatePen.Call(5, 0, 0)             // PS_NULL
	ob, _, _ := pSelectObject.Call(hdc, brush)
	op, _, _ := pSelectObject.Call(hdc, pen)
	for _, e := range [][4]float64{{12, 16.5, 5.4, 4.3}, {5.2, 10.5, 2.5, 3.1}, {18.8, 10.5, 2.5, 3.1}, {8.9, 5.6, 2.4, 3.1}, {15.1, 5.6, 2.4, 3.1}} {
		l, t := int(float64(x)+(e[0]-e[2])*k), int(float64(y)+(e[1]-e[3])*k)
		r, b := int(float64(x)+(e[0]+e[2])*k)+1, int(float64(y)+(e[1]+e[3])*k)+1
		pEllipse.Call(hdc, uintptr(l), uintptr(t), uintptr(r), uintptr(b))
	}
	pSelectObject.Call(hdc, ob)
	pSelectObject.Call(hdc, op)
	pDeleteObject.Call(brush)
	pDeleteObject.Call(pen)
}

func gather() options {
	return options{all: checked(idAll), desktop: checked(idDesktop), start: checked(idStart), dir: strings.TrimSpace(getText(hDir))}
}

func setBusy(b bool) {
	installing = b
	for _, id := range []uintptr{idUser, idAll, idDir, idDesktop, idStart, idInstall} {
		enable(id, !b)
	}
}

func beginInstall() {
	o := gather()
	if o.dir == "" || !filepath.IsAbs(o.dir) {
		msgBox("Please enter a full folder path, e.g. "+defaultDir(false), 0x30)
		return
	}
	if o.all && !isAdmin() { // restart elevated with the same choices
		args := []string{"/go", "/allusers", "/dir", `"` + o.dir + `"`}
		if o.desktop {
			args = append(args, "/desktop")
		}
		if o.start {
			args = append(args, "/start")
		}
		pShellExecute.Call(0, uintptr(unsafe.Pointer(u16("runas"))), uintptr(unsafe.Pointer(u16(mustExe()))),
			uintptr(unsafe.Pointer(u16(strings.Join(args, " ")))), 0, 1)
		pPostMessage.Call(hwndMain, wmClose, 0, 0)
		return
	}
	setBusy(true)
	go func() {
		lastErr = install(o)
		pPostMessage.Call(hwndMain, wmDone, 0, 0)
	}()
}

func wndProc(hwnd, m, wp, lp uintptr) uintptr {
	switch uint32(m) {
	case wmCommand:
		switch wp & 0xFFFF {
		case idInstall:
			if !installing && !uninstallMode {
				beginInstall()
			}
		case idCancel:
			if !installing {
				pPostMessage.Call(hwnd, wmClose, 0, 0)
			}
		case idUser, idAll:
			cur := getText(hDir)
			if cur == defaultDir(false) || cur == defaultDir(true) {
				setText(hDir, defaultDir(wp&0xFFFF == idAll))
			}
		case idLink:
			openTarget("https://www.jeitler.cc", "")
		}
		return 0
	case wmProgress:
		progMu.Lock()
		s := progText
		progMu.Unlock()
		setText(hStatus, s)
		return 0
	case wmDone:
		if uninstallMode {
			if lastErr != nil {
				msgBox("Uninstall failed:\n"+lastErr.Error(), 0x10)
			} else {
				msgBox("mautg was removed.\nYour mautg-args.txt in the folder was not touched.", 0x40)
			}
			pDestroyWindow.Call(hwnd)
			return 0
		}
		setBusy(false)
		if lastErr != nil {
			setText(hStatus, "failed")
			msgBox("Installation failed:\n"+lastErr.Error(), 0x10)
			return 0
		}
		setText(hStatus, "done")
		msgBox("mautg is installed.\nStart menu: mautg", 0x40)
		if startAfter != "" {
			if isAdmin() { // do not run mautg elevated: let explorer start it as the normal user
				exec.Command("explorer.exe", startAfter).Start()
			} else {
				openTarget(startAfter, filepath.Dir(startAfter))
			}
		}
		pDestroyWindow.Call(hwnd)
		return 0
	case wmClose:
		if installing {
			return 0
		}
		pDestroyWindow.Call(hwnd)
		return 0
	case 0x000F: // WM_PAINT
		var ps [72]byte
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps[0])))
		drawPaw(hdc, 16, 12, 1.5)
		drawPaw(hdc, 16, 314, 0.8)
		pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps[0])))
		return 0
	case 0x0138: // WM_CTLCOLORSTATIC
		if lp == hLink {
			col, _, _ := pGetSysColor.Call(15)
			pSetTextColor.Call(wp, 0x00CC6600)
			pSetBkColor.Call(wp, col)
			br, _, _ := pGetSysColorBrush.Call(15)
			return br
		}
	case 0x0082:
		pPostQuitMessage.Call(0)
	}
	r, _, _ := pDefWindowProc.Call(hwnd, m, wp, lp)
	return r
}

func main() {
	runtime.LockOSThread()
	var o options
	var goNow bool
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "/uninstall":
			uninstallMode = true
		case "/allusers":
			o.all = true
		case "/desktop":
			o.desktop = true
		case "/start":
			o.start = true
		case "/go":
			goNow = true
		case "/dir":
			if i+1 < len(args) {
				i++
				o.dir = args[i]
			}
		}
	}
	if !goNow {
		o.start, o.desktop = true, false
	}
	if o.dir == "" {
		o.dir = defaultDir(o.all)
	}
	if uninstallMode && !strings.EqualFold(filepath.Base(mustExe()), "uninstall.exe") {
		msgBox("Please use the uninstall entry: Start menu > mautg > Uninstall mautg,\nor Settings > Apps.", 0x30)
		return
	}
	if uninstallMode && o.all && !isAdmin() { // machine wide install: needs admin
		pShellExecute.Call(0, uintptr(unsafe.Pointer(u16("runas"))), uintptr(unsafe.Pointer(u16(mustExe()))),
			uintptr(unsafe.Pointer(u16("/uninstall /allusers"))), 0, 1)
		return
	}
	if uninstallMode { // run from a temp copy is not needed: the uninstaller deletes itself last
		if msgBox("Remove mautg from this computer?\n\n"+filepath.Dir(mustExe())+"\n\nHosts files and logs in that folder are kept.", 0x24) != 6 {
			return
		}
	}

	inst, _, _ := pGetModuleHandle.Call(0)
	icon, _, _ := pLoadIcon.Call(inst, 1)
	if icon == 0 {
		icon, _, _ = pLoadIcon.Call(0, 32512)
	}
	small, _, _ := pLoadImage.Call(inst, 1, 1, 16, 16, 0)
	if small == 0 {
		small = icon
	}
	cur, _, _ := pLoadCursor.Call(0, 32512)
	cls := u16("mautgInstallerWnd")
	wc := wndClassEx{lpfnWndProc: syscall.NewCallback(wndProc), hInstance: inst, hIcon: icon, hIconSm: small,
		hCursor: cur, hbrBackground: 16, lpszClassName: uintptr(unsafe.Pointer(cls))}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	if r, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return
	}
	title := "mautg installer v" + installerVersion
	if uninstallMode {
		title = "mautg uninstall v" + installerVersion
	}
	hwndMain, _, _ = pCreateWindowEx.Call(0x10000, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(u16(title))),
		0x00C00000|0x00080000|0x00020000, 240, 200, 440, 380, 0, 0, inst, 0)
	if hwndMain == 0 {
		return
	}
	font, _, _ := pGetStockObject.Call(17)
	mk := func(class, text string, style uintptr, x, y, w, h, id uintptr) uintptr {
		hw, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))),
			0x50000000|style, x, y, w, h, hwndMain, id, inst, 0)
		pSendMessage.Call(hw, 0x30, font, 1)
		return hw
	}
	const tab, group = 0x00010000, 0x00020000
	mk("STATIC", "mautg - ICMP reachability monitor", 0, 64, 16, 340, 18, 0)
	if uninstallMode {
		mk("STATIC", "Removing mautg ...", 0, 64, 38, 340, 18, 0)
		hStatus = mk("STATIC", "", 0, 14, 90, 400, 18, 0)
	} else {
		mk("STATIC", "Downloads mautg-windows.zip from GitHub and installs it.", 0, 64, 38, 360, 18, 0)
		ctl[idUser] = mk("BUTTON", "Only for me (no admin rights needed)", tab|group|9, 14, 84, 400, 20, idUser)
		ctl[idAll] = mk("BUTTON", "All users (Program Files, asks for admin rights)", tab|9, 14, 106, 400, 20, idAll)
		mk("STATIC", "Folder:", 0, 14, 142, 48, 18, 0)
		hDir = mk("EDIT", o.dir, tab|0x00800000|0x80, 66, 138, 348, 22, idDir)
		ctl[idDir] = hDir
		ctl[idDesktop] = mk("BUTTON", "Desktop shortcut", tab|3, 14, 174, 400, 20, idDesktop)
		ctl[idStart] = mk("BUTTON", "Start mautg after the installation", tab|3, 14, 196, 400, 20, idStart)
		mk("STATIC", "Start menu entry and uninstall (Settings > Apps) are created.", 0, 14, 224, 400, 18, 0)
		hStatus = mk("STATIC", "", 0, 14, 250, 400, 18, 0)
		ctl[idInstall] = mk("BUTTON", "Install", tab|1, 14, 276, 120, 28, idInstall)
		ctl[idCancel] = mk("BUTTON", "Cancel", tab, 294, 276, 120, 28, idCancel)
		setCheck(idUser, !o.all)
		setCheck(idAll, o.all)
		setCheck(idDesktop, o.desktop)
		setCheck(idStart, o.start)
	}
	foot := "mautg installer  -"
	mk("STATIC", foot, 0, 40, 318, 8*uintptr(len(foot)), 18, 0)
	hLink = mk("STATIC", "www.jeitler.cc", 0x100, 40+8*uintptr(len(foot))+4, 318, 110, 18, idLink)
	if uninstallMode { // hide the empty installer area, start removing
		go func() { lastErr = uninstall(o.all); pPostMessage.Call(hwndMain, wmDone, 0, 0) }()
	}
	pShowWindow.Call(hwndMain, 1)
	pSetForegroundWin.Call(hwndMain)
	if goNow && !uninstallMode { // elevated restart: install right away
		pPostMessage.Call(hwndMain, wmCommand, idInstall, 0)
	}

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
