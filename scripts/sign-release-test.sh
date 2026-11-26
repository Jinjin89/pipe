#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Run with the repository's Go build lock. All signing inputs are generated here.
set -euo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/pipe-signing-test.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture"/{dist,binaries,repo/scripts,repo/internal/{version,update},repo/android/app}
copy=$fixture/repo
cp scripts/sign-release.sh scripts/verify-desktop-archive.py "$copy/scripts/"
cp internal/version/version.go "$copy/internal/version/"
cp internal/update/manifest.go "$copy/internal/update/"
cp android/app/build.gradle.kts "$copy/android/app/"
version=$(sed -n 's/.*Version = "\([^"]*\)".*/\1/p' internal/version/version.go)
version_code=$(sed -n 's/.*versionCode = \([0-9][0-9]*\)$/\1/p' android/app/build.gradle.kts)
build_tools=$(sed -n 's/.*buildToolsVersion = "\([^"]*\)".*/\1/p' android/app/build.gradle.kts)
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/opt/android-sdk}}"
tools=$ANDROID_HOME/build-tools/$build_tools
platform=$ANDROID_HOME/platforms/android-36/android.jar

export PIPE_SIGNING_KEY="$fixture/ed25519.pem"
export PIPE_ANDROID_RELEASE_STORE="$fixture/android.p12"
export PIPE_ANDROID_RELEASE_PASSWORD_FILE="$fixture/android.password"
export PIPE_ANDROID_RELEASE_ALIAS=pipe
openssl genpkey -algorithm Ed25519 -out "$PIPE_SIGNING_KEY"
openssl pkey -in "$PIPE_SIGNING_KEY" -pubout -outform DER > "$fixture/public.der"
python3 -I - "$fixture/public.der" "$copy/internal/update/manifest.go" <<'PY'
import base64
import pathlib
import re
import sys

key, source = map(pathlib.Path, sys.argv[1:])
public = base64.b64encode(key.read_bytes()[-32:]).decode()
source.write_text(re.sub(r'(releasePublicKey\s*=\s*")[^"]+', lambda m: m[1] + public, source.read_text()))
PY
printf '%s\n' pipe-fixture-password > "$PIPE_ANDROID_RELEASE_PASSWORD_FILE"
keytool="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"
"$keytool" -genkeypair -keystore "$PIPE_ANDROID_RELEASE_STORE" -storetype PKCS12 \
  -alias "$PIPE_ANDROID_RELEASE_ALIAS" -storepass:file "$PIPE_ANDROID_RELEASE_PASSWORD_FILE" \
  -keyalg RSA -keysize 2048 -validity 2 -dname 'CN=Pipe Release Fixture' -noprompt

cat > "$fixture/AndroidManifest.xml" <<XML
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="io.pipe.app" android:versionCode="$version_code" android:versionName="$version">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="36" />
    <application android:label="Pipe fixture" />
</manifest>
XML
for abi in arm64-v8a x86_64; do
  "$tools/aapt" package -f -M "$fixture/AndroidManifest.xml" -I "$platform" -F "$fixture/unsigned.apk"
  python3 -I - "$fixture/unsigned.apk" "$abi" <<'PY'
import sys
import zipfile
with zipfile.ZipFile(sys.argv[1], "a", compression=zipfile.ZIP_DEFLATED) as apk:
    apk.writestr(f"lib/{sys.argv[2]}/libgojni.so", b"fixture native library")
PY
  "$tools/zipalign" -f 4 "$fixture/unsigned.apk" "$fixture/aligned.apk"
  "$tools/apksigner" sign --ks "$PIPE_ANDROID_RELEASE_STORE" --ks-key-alias "$PIPE_ANDROID_RELEASE_ALIAS" \
    --ks-pass "file:$PIPE_ANDROID_RELEASE_PASSWORD_FILE" \
    --out "$fixture/dist/pipe-android-${abi%-v8a}.apk" "$fixture/aligned.apk"
done

build() {
  local os=$1 abi=$2 ver=$3 out=$4
  cat > "$fixture/main.go" <<GO
package main
var identity = "\x00pipe-desktop-release-v1 $os $abi $ver\x00"
func main() { println(identity) }
GO
  GOOS=$os GOARCH=$abi go build -p 2 -trimpath -buildvcs=false \
    -tags with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0 \
    -ldflags '-s -w -checklinkname=0' -o "$fixture/binaries/$out" "$fixture/main.go"
}
for pair in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do
  build "${pair%-*}" "${pair##*-}" "$version" "$pair"
done
build linux amd64 0.0.1 "$version-stale"

python3 -I - "$fixture" "$version" <<'PY'
import io
import pathlib
import plistlib
import shutil
import stat
import sys
import tarfile
import zipfile

work, version = pathlib.Path(sys.argv[1]), sys.argv[2]
dist, bins = work / "dist", work / "binaries"
for abi in ("amd64", "arm64"):
    with tarfile.open(dist / f"pipe-linux-{abi}.tar.gz", "w:gz") as archive:
        archive.add(bins / f"linux-{abi}", arcname="pipe")
        readme = tarfile.TarInfo("README.txt")
        readme.size = len(b"fixture")
        archive.addfile(readme, io.BytesIO(b"fixture"))
    with zipfile.ZipFile(dist / f"pipe-macos-{abi}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(bins / f"darwin-{abi}", "pipe")
        archive.writestr("Pipe.app/", b"")
        archive.write(bins / f"darwin-{abi}", "Pipe.app/Contents/MacOS/Pipe")
        archive.writestr("Pipe.app/Contents/Info.plist", plistlib.dumps({
            "CFBundleExecutable": "Pipe", "CFBundleVersion": version, "CFBundleShortVersionString": version,
        }))
        archive.writestr("Pipe.app/Contents/Resources/Pipe.icns", b"icns")
with zipfile.ZipFile(dist / "pipe-windows-amd64.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for name in ("pipe-cli.exe", "Pipe.exe"):
        archive.write(bins / "windows-amd64", name)
    archive.writestr("README.txt", b"fixture")

for name, binary, extra, kind in (
    ("wrong-arch", "linux-arm64", "", None),
    ("stale-version", f"{version}-stale", "", None),
    ("tar-traversal", "linux-amd64", "../README.txt", tarfile.REGTYPE),
    ("tar-hardlink", "linux-amd64", "docs/link", tarfile.LNKTYPE),
    ("tar-extra-file", "linux-amd64", "extra.bin", tarfile.REGTYPE),
):
    trial = work / name
    shutil.copytree(dist, trial)
    with tarfile.open(trial / "pipe-linux-amd64.tar.gz", "w:gz") as archive:
        archive.add(bins / binary, arcname="pipe")
        readme = tarfile.TarInfo("README.txt")
        readme.size = len(b"fixture")
        archive.addfile(readme, io.BytesIO(b"fixture"))
        if extra:
            entry = tarfile.TarInfo(extra)
            entry.type = kind
            if kind == tarfile.LNKTYPE:
                entry.linkname = "pipe"
            elif kind == tarfile.REGTYPE:
                entry.size = len(b"extra")
            archive.addfile(entry, io.BytesIO(b"extra") if kind == tarfile.REGTYPE else None)

for name, platform, extra, mode in (
    ("macos-case-collision", "macos", "pipe.app/contents/macos/pipe", stat.S_IFREG),
    ("windows-case-slash-collision", "windows", "README.TXT", stat.S_IFREG),
    ("zip-symlink", "macos", "docs/link", stat.S_IFLNK),
    ("zip-traversal", "windows", "docs/../README.txt", stat.S_IFREG),
    ("zip-extra-file", "windows", "extra.dll", stat.S_IFREG),
):
    trial = work / name
    shutil.copytree(dist, trial)
    with zipfile.ZipFile(trial / f"pipe-{platform}-amd64.zip", "a") as archive:
        entry = zipfile.ZipInfo(extra)
        entry.create_system = 3
        entry.external_attr = (mode | 0o644) << 16
        archive.writestr(entry, b"fixture")
PY

signer=$copy/scripts/sign-release.sh
"$signer" "$fixture/dist"
openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$fixture/public.der" \
  -in "$fixture/dist/SHA256SUMS" -sigfile "$fixture/dist/SHA256SUMS.sig"
result=0
for invalid in wrong-arch stale-version tar-traversal tar-hardlink tar-extra-file macos-case-collision \
  windows-case-slash-collision zip-symlink zip-traversal zip-extra-file; do
  if "$signer" "$fixture/$invalid" || [[ -e $fixture/$invalid/SHA256SUMS.sig ]]; then
    printf 'Signed an invalid %s archive.\n' "$invalid" >&2
    result=1
  fi
done
(( result == 0 ))
printf 'PASS release signer validates archive platform, version, and entry paths and types\n'
