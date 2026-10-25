# mautg for macOS

Web GUI version of mautg. Start `mautg.app`: mautg runs in the background, the web GUI opens in the browser as soon as
mautg answers (http://127.0.0.1:8081) and a small window controls it (same as the Windows version):
Status, web port, Start / Stop / Restart, Open web GUI, Console log, Admin setup, Exit and an Update
button when GitHub has a newer version.

- Python 3.11 for Apple Silicon and Intel is included (`python-aarch64`, `python-x86_64`); a system `python3` is only a fallback.
- Options: one line in `mautg-args.txt` next to `mautg.py`, e.g. `-bind 0.0.0.0 -port 9000` (default `-web -bind 127.0.0.1 -port 8081`).
- Console log: `mautg-console.log`; the mautg config is in `~/.mau`.
- Admin setup: macOS sends UDP datagrams up to `net.inet.udp.maxdgram` (default 9216 bytes). The launcher raises it to 65535
  (until the next reboot) and, if the macOS firewall is on, allows the bundled python. It asks for the administrator
  password; mautg itself always runs as your user. The first start asks once, "Never ask" is remembered.
- Terminal mode: run `mautg.py` directly in Terminal.
- Not notarized: right-click the app and choose Open, or run `xattr -dr com.apple.quarantine <mautg-mac folder>` once.
