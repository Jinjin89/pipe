#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Cross-builds the desktop packages into dist/ (no cgo, from any Linux box).
set -euo pipefail
umask 022

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo"
if [[ ${PIPE_OFFLINE:-} == 1 ]]; then
  export PATH=/usr/local/go/bin:/root/go/bin:$PATH GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
  export GOCACHE="${GOCACHE:-/tmp/pipe-gocache}"
fi
export GOFLAGS="${GOFLAGS:--mod=mod}" CGO_ENABLED=0

tags=with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0
base_ldflags='-s -w -checklinkname=0'
version=$(sed -n 's/.*Version = "\(.*\)".*/\1/p' internal/version/version.go)
dist=$repo/dist
work=$(mktemp -d "${TMPDIR:-/tmp}/pipe-package.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
rm -rf -- "$dist"
mkdir -p -- "$dist"

# build GOOS GOARCH OUTPUT [extra ldflags]
build() {
  local goos=$1 goarch=$2 out=$3 extra=${4:-}
  GOOS=$goos GOARCH=$goarch go build -p 2 -trimpath -tags "$tags" \
    -ldflags "$base_ldflags $extra" -o "$out" ./cmd/pipe
}

readme() {
  cat >"$1" <<'TXT'
Pipe

Run "./pipe app --install-desktop-entry" once. Pipe then appears in your
application menu. You can also start it any time with "./pipe app".

The same program is the command line tool: "./pipe run --help".
TXT
}

# --- Linux
for arch in amd64 arm64; do
  d=$work/linux-$arch
  mkdir -p "$d"
  build linux "$arch" "$d/pipe"
  readme "$d/README.txt"
  tar --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' -C "$d" \
    -czf "$dist/pipe-linux-$arch.tar.gz" pipe README.txt
done

# --- Windows
d=$work/windows
mkdir -p "$d"
build windows amd64 "$d/pipe-cli.exe"
build windows amd64 "$d/Pipe.exe" '-H=windowsgui -X main.defaultCommand=app'
cat >"$d/README.txt" <<'TXT'
Pipe

Double-click Pipe.exe to open the app.

pipe-cli.exe is the same program for the command line, for example:
  pipe-cli.exe run --help
TXT

# --- macOS
for arch in arm64 amd64; do
  d=$work/macos-$arch
  app=$d/Pipe.app/Contents
  mkdir -p "$app/MacOS" "$app/Resources"
  build darwin "$arch" "$app/MacOS/Pipe" '-X main.defaultCommand=app'
  build darwin "$arch" "$d/pipe"
  cp packaging/icons/pipe.icns "$app/Resources/Pipe.icns"
  cat >"$app/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>Pipe</string>
	<key>CFBundleDisplayName</key><string>Pipe</string>
	<key>CFBundleIdentifier</key><string>io.pipe.app</string>
	<key>CFBundleExecutable</key><string>Pipe</string>
	<key>CFBundleIconFile</key><string>Pipe.icns</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleVersion</key><string>$version</string>
	<key>CFBundleShortVersionString</key><string>$version</string>
	<key>LSMinimumSystemVersion</key><string>11.0</string>
	<key>LSUIElement</key><true/>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
done

# Zip with python so Unix modes (0755 for executables) survive.
zip_dir() { # zip_dir SRCDIR OUT.zip
  python3 -I - "$1" "$2" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(src):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, src)
            info = zipfile.ZipInfo(rel, date_time=(2026, 1, 1, 0, 0, 0))
            exe = rel.startswith("Pipe.app/Contents/MacOS/") or rel in ("pipe", "pipe.exe", "Pipe.exe")
            info.external_attr = ((0o100755 if exe else 0o100644) << 16)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(path, "rb") as f:
                z.writestr(info, f.read())
PY
}

zip_dir "$work/windows" "$dist/pipe-windows-amd64.zip"
for arch in arm64 amd64; do
  zip_dir "$work/macos-$arch" "$dist/pipe-macos-$arch.zip"
done

ls -l -- "$dist"
