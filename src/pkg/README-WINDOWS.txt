mautg - portable Windows folder (web GUI), launcher version in the title bar

ALPHA: hardly tested, reduced function compared to Linux (no kernel RX timestamps, no RX-drop detection, lower maximum pps, DSCP only as administrator).

Start
  Double-click mautg.exe. A small window opens (no console window); mautg runs in the
  background and the web GUI opens in the browser (http://127.0.0.1:8081).

Window
  Status line, "Web port" field and the buttons
  Start / Stop / Restart     mautg is asked to exit cleanly first, then ended
  Web port field             1-65535, default 8081; a changed value is written to
                             mautg-args.txt when you press Start / Restart.
                             If the port is already in use, a message asks for another
                             port; mautg is not started.
  Open web GUI               opens the browser (also automatic after the start)
  Console log                mautg-console.log (output of the last start, errors)
  Rights / Admin             shows whether the launcher runs as administrator; the Admin
                             button restarts it as administrator (UAC prompt)
  Update                     checks mversions on GitHub at start and every 6 hours; the
                             Update button appears if mautg.py is newer (replaced) or if
                             "mautg-windows" is newer (full update, mautg.exe restarts)
  Exit (or close the window) stops mautg and quits

Administrator rights
  Windows ignores DSCP set on a socket. As administrator mautg.py creates a QoS policy
  (New-NetQosPolicy, UDP, destination ip + port, this python.exe only) for every sender
  stream with a DSCP value; the policy is removed again when mautg ends. The launcher
  also adds an inbound UDP rule for the bundled python.exe to the Windows firewall, so
  no firewall prompt appears when the receiver starts.
  At the first start the launcher asks whether it should restart as administrator;
  "No" is remembered (%APPDATA%\mautg\admin-ask-off, delete it to be asked again).

Contents
  mautg.exe       launcher window (built with Go, no dependencies)
  mautg.py        traffic generator / receiver (web GUI mode)
  python\         Python "embeddable package" (Windows x86-64); without it python.exe
                  from PATH is used

Options
  Extra mautg options: one line in mautg-args.txt (optional), e.g.
      -bind 0.0.0.0 -port 9000
  or as arguments of mautg.exe. Default: -web -bind 127.0.0.1 -port 8081.
  The console log is stored in this folder; the mautg config is in %USERPROFILE%\.mau.

Notes
  - The web GUI listens on 127.0.0.1 only; add "-bind 0.0.0.0" to mautg-args.txt to
    reach it from the network (no authentication).
  - Windows limits: delay is stamped in user space (no kernel RX timestamps), no RX-drop detection, lower maximum packet rate. DSCP and MC/UC/BC at the receiver are read with WSARecvMsg.
  - -wv / -wvc and the terminal (TUI) mode are not available through the launcher.
