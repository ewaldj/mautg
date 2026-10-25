#!/bin/bash
# Builds the Windows and macOS packages into ../release (Windows_Version/, OSX_Version/).
# Needs: go (cross compiles, no Windows / Mac required), zip. The Python runtimes are taken
# from runtime/ (windows/python, mac/python-aarch64, mac/python-x86_64).
# Usage: src/build.sh   (run the Go tests first with: src/build.sh test)
set -eu
S="$(cd "$(dirname "$0")" && pwd)"
P="$(dirname "$S")"
R="$P/release"
export CGO_ENABLED=0

if [ "${1:-}" = "test" ]; then
  for d in windows-launcher windows-installer osx-launcher osx-installer; do
    (cd "$S/$d" && MAUTG_SRC="$P/mautg.py" go test -count=1 .)
  done
  exit 0
fi

command -v go  >/dev/null || { echo "go not found"; exit 1; }
command -v zip >/dev/null || { echo "zip not found"; exit 1; }
for d in runtime/windows/python runtime/mac/python-aarch64 runtime/mac/python-x86_64; do
  [ -d "$S/$d" ] || { echo "missing $S/$d"; exit 1; }
done
[ -f "$P/mautg.py" ] || { echo "missing $P/mautg.py"; exit 1; }

constval() { sed -n "s/^const $2 *= *\"\\(.*\\)\".*/\\1/p" "$1" | head -1; }
SCRIPT_V="$(sed -n 's/^VERSION *= *"\(.*\)".*/\1/p' "$P/mautg.py" | head -1)"
WIN_V="$(constval "$S/windows-launcher/update.go" launcherVersion)"
MAC_V="$(constval "$S/osx-launcher/update.go" launcherVersion)"
WINST_V="$(constval "$S/windows-installer/core.go" installerVersion)"
MACST_V="$(constval "$S/osx-installer/core.go" installerVersion)"
echo "mautg.py $SCRIPT_V, windows launcher $WIN_V, mac launcher $MAC_V, installers $WINST_V / $MACST_V"

B="$(mktemp -d)"
trap 'rm -rf "$B"' EXIT
mkdir -p "$R/Windows_Version" "$R/OSX_Version"
LD="-s -w"

# ---------------- Windows ----------------
W="$B/win/mautg-windows"
mkdir -p "$W"
(cd "$S/windows-launcher"  && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui $LD" -o "$W/mautg.exe" .)
(cd "$S/windows-installer" && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui $LD" -o "$R/Windows_Version/mautg-installer.exe" .)
cp -p "$P/mautg.py" "$W/mautg.py"
cp -p "$S/pkg/README-WINDOWS.txt" "$W/"
cp -a "$S/runtime/windows/python" "$W/python"
rm -f "$R/Windows_Version/mautg-windows.zip"
(cd "$B/win" && zip -qr -X "$R/Windows_Version/mautg-windows.zip" mautg-windows)

# ---------------- macOS ----------------
plist() { # name version id displayname exe icon
cat <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDisplayName</key>
	<string>$4</string>
	<key>CFBundleExecutable</key>
	<string>$5</string>
	<key>CFBundleIconFile</key>
	<string>$6</string>
	<key>CFBundleIdentifier</key>
	<string>$3</string>
	<key>CFBundleName</key>
	<string>$4</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$2</string>
	<key>CFBundleVersion</key>
	<string>$2</string>
	<key>LSArchitecturePriority</key>
	<array>
		<string>arm64</string>
		<string>x86_64</string>
	</array>
	<key>LSMinimumSystemVersion</key>
	<string>10.13</string>
	<key>LSRequiresNativeExecution</key>
	<true/>
$7	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
PL
}
picker() { # name
cat <<SH
#!/bin/sh
# pick the program for this CPU
d=\$(dirname "\$0")
case "\$(uname -m)" in
  arm64) exec "\$d/$1-arm64" "\$@" ;;
  *)     exec "\$d/$1-amd64" "\$@" ;;
esac
SH
}
mkapp() { # srcdir name outdir
  local src="$1" name="$2" out="$3"
  mkdir -p "$out/Contents/MacOS" "$out/Contents/Resources"
  for a in arm64 amd64; do
    (cd "$src" && GOOS=darwin GOARCH=$a go build -trimpath -ldflags "$LD" -o "$out/Contents/MacOS/$name-$a" .)
  done
  picker "$name" > "$out/Contents/MacOS/$name"
  chmod 755 "$out/Contents/MacOS/"*
  cp -p "$S/osx-launcher/res/mautg.icns" "$out/Contents/Resources/mautg.icns"
}

M="$B/mac/mautg-mac"
mkdir -p "$M"
mkapp "$S/osx-launcher" mautg "$M/mautg.app"
plist mautg "$MAC_V" cc.jeitler.mautg mautg mautg mautg "	<key>LSUIElement</key>
	<true/>
" > "$M/mautg.app/Contents/Info.plist"
cp -p "$P/mautg.py" "$M/mautg.py"
cp -p "$S/pkg/README-MAC.md" "$M/README.md"
cp -a "$S/runtime/mac/python-aarch64" "$S/runtime/mac/python-x86_64" "$M/"
rm -f "$R/OSX_Version/mautg-mac.zip"
(cd "$B/mac" && zip -qry -X "$R/OSX_Version/mautg-mac.zip" mautg-mac)

I="$B/macinst"
mkdir -p "$I"
mkapp "$S/osx-installer" mautg-installer "$I/mautg-installer.app"
plist "mautg installer" "$MACST_V" cc.jeitler.mautg-installer "mautg installer" mautg-installer mautg "" > "$I/mautg-installer.app/Contents/Info.plist"
rm -f "$R/OSX_Version/mautg-installer-mac.zip"
(cd "$I" && zip -qry -X "$R/OSX_Version/mautg-installer-mac.zip" mautg-installer.app)

# ---------------- versions file for the launchers' update check ----------------
printf 'mautg.py %s\nmautg-windows %s\nmautg-mac %s\n' "$SCRIPT_V" "$WIN_V" "$MAC_V" > "$P/mversions"
ls -la "$R/Windows_Version" "$R/OSX_Version"
echo "mversions:"; cat "$P/mversions"
