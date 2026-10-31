# mautg for macOS

Web GUI version of [mautg](https://github.com/ewaldj/mautg) for macOS 10.13+ (Apple Silicon and Intel).
A small launcher app (`mautg.app`) starts mautg in the background, opens the web GUI and shows a window with
Start / Stop / Restart / port / Open web GUI / Console log / Admin setup / Update. Same functions as the Windows version.
Python 3.11 (Apple Silicon and Intel) is included.

## Options

The window has the checkbox **Disable Def-Config** (start without `~/.mau/config.json`, option `--no-config`) and the field **CLI options** (any mautg options, e.g. `-bind 0.0.0.0`). Both are applied with Start / Restart and stored in `mautg-args.txt` next to the program.

> **Alpha status:** hardly tested, reduced function compared to the Linux version (see the main [README](https://github.com/ewaldj/mautg#platform-status)). Expect bugs.
> macOS: no kernel RX timestamps (user-space delay), no per-socket drop counter, no DF bit, TCP algorithm system-wide, TCP window / queue values missing.

## Download

| Variant | File | Use |
|---|---|---|
| Installer | [mautg-installer-mac.zip](https://github.com/ewaldj/mautg/raw/main/OSX_Version/mautg-installer-mac.zip) | Unzip, open `mautg-installer.app`: downloads the package and installs it for the current user or all users |
| Portable | [mautg-mac.zip](https://github.com/ewaldj/mautg/raw/main/OSX_Version/mautg-mac.zip) | Unzip anywhere and open `mautg.app` |

## First start (apps are not notarized)

macOS blocks downloaded apps from unknown developers. Either right-click the app, choose Open
(macOS 15: System Settings / Privacy & Security / Open Anyway), or run once in Terminal:

```sh
xattr -dr com.apple.quarantine mautg-installer.app   # or the mautg-mac folder
```

The installer removes the flag from the installed files itself.

## Installer

1. Open `mautg-installer.app`, press Install.
2. Choose Current user (`~/Applications/mautg`) or All users (`/Applications/mautg`, asks for the admin password).
3. Start mautg from the last dialog. Uninstall: open the installer again and press Uninstall.

## Admin setup (optional)

mautg always runs as your user. The launcher can raise `net.inet.udp.maxdgram` to 65535 (default 9216 limits large packets; until the next reboot)
and, if the macOS firewall is on, allow the bundled Python. This asks for the administrator password; asked once at first start, "Never ask" is remembered
(`~/Library/Application Support/mautg/admin-ask-off`).

## Update

The launcher checks `mversions` on GitHub at start and every 6 hours. If `mautg.py` is newer, the Update button replaces it;
if `mautg-mac` is newer, the whole package is replaced.

## Notes

- The web GUI listens on 127.0.0.1 only; add `-bind 0.0.0.0` to `mautg-args.txt` to reach it from the network.
- Terminal mode: run `mautg.py` directly in Terminal.
- Details: <https://www.jeitler.cc>
