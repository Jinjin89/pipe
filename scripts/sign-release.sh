#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Sign the final archives and production-signed APK splits together.
set -euo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
dist=${1:-$repo/dist}

fail() { printf '%s\n' "$1" >&2; exit 1; }

if (( $# > 1 )); then
  fail "Usage: PIPE_SIGNING_KEY=<Ed25519 PEM> $0 [release directory]"
fi
key=${PIPE_SIGNING_KEY:-}
[[ -n $key && -r $key ]] || fail 'Release signing requires PIPE_SIGNING_KEY pointing to the production Ed25519 PEM.'

store=${PIPE_ANDROID_RELEASE_STORE:-$HOME/.config/pipe/android-release.p12}
password_file=${PIPE_ANDROID_RELEASE_PASSWORD_FILE:-$store.password}
alias=${PIPE_ANDROID_RELEASE_ALIAS:-pipe}
[[ -s $store && -s $password_file ]] || fail 'Release signing requires the existing Android release signer.'
[[ -d $dist ]] || fail 'The release directory does not exist.'

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}
build_tools=$(sed -n 's/.*buildToolsVersion = "\([^"]*\)".*/\1/p' "$repo/android/app/build.gradle.kts")
tools=$sdk/build-tools/$build_tools
version=$(sed -n 's/.*Version = "\([^"]*\)".*/\1/p' "$repo/internal/version/version.go")
code=$(sed -n 's/.*versionCode = \([0-9][0-9]*\)$/\1/p' "$repo/android/app/build.gradle.kts")
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([a-z][a-z0-9-]*)(\.[a-z0-9-]+)*)?$ ]] ||
  fail 'The release version is invalid.'
channel=${BASH_REMATCH[5]:-stable}

work=$(mktemp -d "${TMPDIR:-/tmp}/pipe-sign-release.XXXXXX")
chmod 700 "$work"
trap 'rm -rf -- "$work"' EXIT

public=$(sed -n 's/^[[:space:]]*releasePublicKey[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$repo/internal/update/manifest.go")
openssl pkey -in "$key" -pubout -out "$work/public.pem"
actual=$(openssl pkey -pubin -in "$work/public.pem" -outform DER | openssl base64 -A)
[[ $actual == "MCowBQYDK2VwAyEA$public" ]] || fail 'The Ed25519 signer does not match the public key built into Pipe.'

keytool="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"
android_digest=$("$keytool" -exportcert -keystore "$store" -storepass:file "$password_file" -alias "$alias" |
  openssl dgst -sha256 -r)
android_digest=${android_digest%% *}

verify_apk() {
  local path=$1 abi=$2 certs badging
  certs=$("$tools/apksigner" verify --min-sdk-version 26 --print-certs "$path")
  if [[ $certs == *'CN=Android Debug'* ]] ||
    [[ $(sed -n 's/^Signer #[0-9]* certificate SHA-256 digest: //p' <<< "$certs") != "$android_digest" ]]; then
    fail "Wrong release signer for ${path##*/}."
  fi
  badging=$("$tools/aapt" dump badging "$path")
  if [[ $badging != *"package: name='io.pipe.app' versionCode='$code' versionName='$version'"* ||
        $badging == *'application-debuggable'* ]] ||
    [[ $(sed -n "s/^native-code: '\([^']*\)'[[:space:]]*$/\1/p" <<< "$badging") != "$abi" ]]; then
    fail "Wrong package, version or ABI for ${path##*/}."
  fi
}

entry() {
  local os=$1 abi=$2 name=$3 asset=$dist/$3 snapshot=$work/$3 size digest
  [[ -f $asset && ! -L $asset ]] || fail "Missing final release file $name."
  size=$(wc -c < "$asset")
  (( size > 0 && size <= 268435456 )) || fail "Invalid length for $name."
  cp -P -- "$asset" "$snapshot"
  if [[ ! -f $snapshot || -L $snapshot ]] || (( $(wc -c < "$snapshot") != size )); then
    fail "Release file $name changed while being read."
  fi
  case $os in
    android) verify_apk "$snapshot" "$abi" ;;
    linux|darwin|windows) python3 -I "$repo/scripts/verify-desktop-archive.py" "$snapshot" "$os" "$abi" "$version" ;;
  esac
  digest=$(openssl dgst -sha256 -r < "$snapshot")
  rm -- "$snapshot"
  printf '%s %s %s %d %s\n' "$os" "$abi" "$name" "$size" "${digest%% *}"
}

{
  printf 'pipe-sha256sums-v1\nversion %s\nchannel %s\n' "$version" "$channel"
  entry linux amd64 pipe-linux-amd64.tar.gz
  entry linux arm64 pipe-linux-arm64.tar.gz
  entry darwin amd64 pipe-macos-amd64.zip
  entry darwin arm64 pipe-macos-arm64.zip
  entry windows amd64 pipe-windows-amd64.zip
  entry android arm64-v8a pipe-android-arm64.apk
  entry android x86_64 pipe-android-x86_64.apk
} > "$work/SHA256SUMS"
openssl pkeyutl -sign -rawin -inkey "$key" -in "$work/SHA256SUMS" -out "$work/SHA256SUMS.sig"
openssl pkeyutl -verify -rawin -pubin -inkey "$work/public.pem" \
  -in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null
chmod 0644 "$work/SHA256SUMS" "$work/SHA256SUMS.sig"
mv -f -- "$work/SHA256SUMS" "$dist/SHA256SUMS"
mv -f -- "$work/SHA256SUMS.sig" "$dist/SHA256SUMS.sig"
printf 'Verified release manifest and signature for %s\n' "$version"
