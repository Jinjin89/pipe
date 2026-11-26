#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
umask 077

bind_only=0
gradle_only=0
debug_only=0
for arg in "$@"; do
  case $arg in
    --bind-only) bind_only=1 ;;
    --gradle-only) gradle_only=1 ;;
    --debug) debug_only=1 ;;
    *) printf 'Usage: %s [--bind-only|--gradle-only] [--debug]\n' "$0" >&2; exit 2 ;;
  esac
done
if (( bind_only && gradle_only )); then
  printf 'Choose one of --bind-only and --gradle-only.\n' >&2
  exit 2
fi

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo"
sdk_default=$HOME/Android/Sdk
gradle_home_default=$HOME/.gradle
android_user_default=$HOME/.android
gradle_default=gradle
gradle_args=(--no-daemon --stacktrace -p android)
if [[ ${PIPE_OFFLINE:-} == 1 ]]; then
  export PATH=/usr/local/go/bin:/root/go/bin:$PATH GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
  export GOCACHE="${GOCACHE:-/tmp/pipe-gocache}" GOMODCACHE="${GOMODCACHE:-/root/go/pkg/mod}"
  export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
  sdk_default=/opt/android-sdk
  gradle_home_default=/tmp/pipe-gradle-home
  android_user_default=/tmp/pipe-android-user
  gradle_default=/opt/gradle/bin/gradle
  gradle_args=(--offline "${gradle_args[@]}")
fi
export GOFLAGS="${GOFLAGS:--mod=mod}"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$sdk_default}}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/28.2.13676358}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$gradle_home_default}"
export ANDROID_USER_HOME="${ANDROID_USER_HOME:-$android_user_default}"
gradle="${GRADLE:-$gradle_default}"
keytool="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"

if (( !bind_only && !debug_only )); then
  export PIPE_ANDROID_RELEASE_STORE="${PIPE_ANDROID_RELEASE_STORE:-$HOME/.config/pipe/android-release.p12}"
  export PIPE_ANDROID_RELEASE_PASSWORD_FILE="${PIPE_ANDROID_RELEASE_PASSWORD_FILE:-$PIPE_ANDROID_RELEASE_STORE.password}"
  export PIPE_ANDROID_RELEASE_ALIAS="${PIPE_ANDROID_RELEASE_ALIAS:-pipe}"
  if [[ ! -s $PIPE_ANDROID_RELEASE_STORE || ! -s $PIPE_ANDROID_RELEASE_PASSWORD_FILE ]]; then
    printf 'Release signing requires the existing keystore and password file. Use --debug for a local debug build.\n' >&2
    exit 1
  fi
  if [[ $(stat -c '%a' -- "$PIPE_ANDROID_RELEASE_PASSWORD_FILE") != 600 ]]; then
    printf 'The release signing password file must have mode 0600.\n' >&2
    exit 1
  fi
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/pipe-android-build.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
export TMPDIR="$work/tmp"
mkdir -p "$TMPDIR"
tags=with_gvisor,with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0

bind() {
  PIPE_ANDROID_TAGS=$1 PATH="$work/bin:$PATH" gomobile bind \
    -target=android/arm64,android/amd64 -androidapi 26 -trimpath -tags "$1" \
    -ldflags '-s -w -checklinkname=0' -o "$2" ./mobile
}

if (( !gradle_only )); then
  PIPE_ANDROID_GO=$(command -v go)
  GOMODCACHE=${GOMODCACHE:-$("$PIPE_ANDROID_GO" env GOMODCACHE)}
  export PIPE_ANDROID_GO PIPE_ANDROID_REPO="$repo" GOMODCACHE
  export GOPATH="$work/gopath"
  mkdir -p "$GOPATH/pkg/gomobile" "$work/bin" "$ANDROID_USER_HOME" android/app/libs

  # The offline cache can omit modules that the Android build never imports.
  cat > "$work/bin/go" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${PIPE_OFFLINE:-} == 1 && $PWD == "$PIPE_ANDROID_REPO" && ${1:-} == list && ${2:-} == -m && ${*: -1} == all ]]; then
  dependencies=$("$PIPE_ANDROID_GO" list -deps -tags "$PIPE_ANDROID_TAGS" \
    -f '{{with .Module}}{{.Path}}{{end}}' ./mobile)
  mapfile -t modules < <(printf '%s\n' "$dependencies" golang.org/x/mobile | sed '/^$/d' | sort -u)
  exec "$PIPE_ANDROID_GO" list -m -json "${modules[@]}"
fi
if [[ ${1:-} == build && $PWD == "$TMPDIR"/gomobile-work-*/src-android-* ]]; then
  exec "$PIPE_ANDROID_GO" build -p 2 -buildvcs=false "${@:2}"
fi
exec "$PIPE_ANDROID_GO" "$@"
SH
  chmod +x "$work/bin/go"
  if (( !debug_only )); then
    bind "$tags" android/app/libs/pipe.aar
  fi
  bind "$tags,pipe_debug" android/app/libs/pipe-debug.aar
fi
if (( bind_only )); then
  exit 0
fi
archives=(android/app/libs/pipe-debug.aar)
if (( !debug_only )); then
  archives+=(android/app/libs/pipe.aar)
fi
for archive in "${archives[@]}"; do
  if [[ ! -s $archive ]]; then
    printf 'Missing binding %s. Run %s --bind-only first.\n' "$archive" "$0" >&2
    exit 1
  fi
done

mkdir -p "$GRADLE_USER_HOME"
debug_store="$GRADLE_USER_HOME/pipe-debug.keystore"
if [[ ! -f $debug_store ]]; then
  "$keytool" -genkeypair -keystore "$debug_store" -storetype JKS \
    -alias androiddebugkey -storepass android -keypass android -keyalg RSA -keysize 2048 \
    -validity 10000 -dname 'CN=Android Debug,O=Android,C=US' -noprompt
fi

if [[ ${PIPE_OFFLINE:-} == 1 ]]; then
  mkdir -p "$work/java-home"
  export GRADLE_OPTS="${GRADLE_OPTS:-} -Duser.home=$work/java-home"
fi
tasks=(assembleDebug)
if (( !debug_only )); then
  tasks+=(assembleRelease)
fi
"$gradle" "${gradle_args[@]}" "${tasks[@]}"

apk_dir=android/app/build/outputs/apk
shopt -s nullglob
debug_apks=("$apk_dir"/debug/*.apk)
if (( ${#debug_apks[@]} != 2 )); then
  printf 'Expected separate arm64 and x86_64 debug APKs.\n' >&2
  exit 1
fi
stat -c '%n %s bytes' "${debug_apks[@]}"
if (( debug_only )); then
  exit 0
fi

arm64_release=("$apk_dir"/release/*arm64-v8a-release.apk)
x86_release=("$apk_dir"/release/*x86_64-release.apk)
if (( ${#arm64_release[@]} != 1 || ${#x86_release[@]} != 1 )); then
  printf 'Expected separate arm64 and x86_64 signed release APKs.\n' >&2
  exit 1
fi
if (( $(stat -c '%s' "${arm64_release[0]}") > 20000000 )); then
  printf 'The arm64 release APK is missing or exceeds 20 MB.\n' >&2
  exit 1
fi
dist=${PIPE_RELEASE_DIR:-$repo/dist}
mkdir -p -- "$dist"
install -m 0644 -- "${arm64_release[0]}" "$dist/pipe-android-arm64.apk"
install -m 0644 -- "${x86_release[0]}" "$dist/pipe-android-x86_64.apk"
stat -c '%n %s bytes' "$dist"/pipe-android-{arm64,x86_64}.apk
