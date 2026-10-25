# mautg for Windows

Web GUI version of [mautg](https://github.com/ewaldj/mautg) for Windows 10/11 (x64).
Python is bundled, nothing else has to be installed. A small launcher window controls mautg
(Start / Stop / Restart, web port, Open web GUI, Console log, Admin, Update, Exit); the browser opens as soon as mautg answers.

## Download

| Variant | File | Use |
|---|---|---|
| Installer | [mautg-installer.exe](https://github.com/ewaldj/mautg/raw/main/Windows_Version/mautg-installer.exe) | Downloads the package, installs it, creates Start menu / desktop shortcuts and an uninstaller |
| Portable | [mautg-windows.zip](https://github.com/ewaldj/mautg/raw/main/Windows_Version/mautg-windows.zip) | Unzip anywhere and run `mautg.exe` |

## Installer

1. Run `mautg-installer.exe`.
2. Choose per user or all users (admin rights are requested for all users) and press Install.
3. Start mautg from the Start menu. Uninstall via Windows Apps or `uninstall.exe`.

## Portable

1. Unzip `mautg-windows.zip`.
2. Run `mautg.exe`. The web GUI opens at http://127.0.0.1:8081.

## Administrator rights

Windows ignores DSCP set on a socket. As administrator mautg creates a QoS policy per sender stream with a DSCP value
(removed again at exit) and the launcher adds an inbound UDP firewall rule for the bundled `python.exe`.
At start the launcher asks whether to restart as administrator (UAC); "No" is remembered
(`%APPDATA%\mautg\admin-ask-off`), the Admin button restarts it any time.

## Update

`mautg.exe` checks `mversions` on GitHub at start and every 6 hours. If a newer version exists, an Update button appears:
`mautg.py` is replaced, or the whole package if `mautg-windows` is newer.

## Notes

- The web GUI listens on 127.0.0.1 only; add `-bind 0.0.0.0` to `mautg-args.txt` to reach it from the network (no authentication).
- Limits: no kernel RX timestamps, no MC/UC/BC and RX-drop detection (no `recvmsg`), lower maximum pps.
- Terminal (TUI) mode and `-wv` / `-wvc` are not available through the launcher.
- Details: `README-WINDOWS.txt` in the zip, main project: [mautg](https://github.com/ewaldj/mautg), <https://www.jeitler.cc>
