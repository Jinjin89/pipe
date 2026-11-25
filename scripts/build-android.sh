#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
umask 077

case ${1:-} in
  ""|--bind-only|--gradle-only) ;;
  *) printf 'Usage: %s [--bind-only|--gradle-only]\n' "$0" >&2; exit 2 ;;
esac

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

if [[ ${1:-} != --gradle-only ]]; then
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
  exec "$PIPE_ANDROID_GO" build -buildvcs=false "${@:2}"
fi
exec "$PIPE_ANDROID_GO" "$@"
SH
  chmod +x "$work/bin/go"
  bind "$tags" android/app/libs/pipe.aar
  bind "$tags,pipe_debug" android/app/libs/pipe-debug.aar
fi
if [[ ${1:-} == --bind-only ]]; then
  exit 0
fi
for archive in android/app/libs/pipe.aar android/app/libs/pipe-debug.aar; do
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

prepare_release_signing() {
  local store password_file
  store=$(realpath -m -- "${PIPE_ANDROID_RELEASE_STORE:-$HOME/.config/pipe/android-release.p12}")
  password_file=$(realpath -m -- "${PIPE_ANDROID_RELEASE_PASSWORD_FILE:-$store.password}")
  if [[ $store == "$repo" || $store == "$repo/"* ||
        $password_file == "$repo" || $password_file == "$repo/"* ||
        $password_file == "$store" || $password_file == "$store.lock" ]]; then
    printf 'Choose distinct release signing files outside the repository.\n' >&2
    return 1
  fi
  export PIPE_ANDROID_RELEASE_STORE="$store" PIPE_ANDROID_RELEASE_PASSWORD_FILE="$password_file"
  export PIPE_ANDROID_RELEASE_ALIAS="${PIPE_ANDROID_RELEASE_ALIAS:-pipe}"
  mkdir -p -- "$(dirname -- "$store")" "$(dirname -- "$password_file")"

  (
    flock -x 9
    if [[ ! -e $store && ! -e $password_file ]]; then
      python3 -c 'import secrets; print(secrets.token_hex(24))' > "$work/release.password"
      "$keytool" -genkeypair -keystore "$work/release.p12" -storetype PKCS12 \
        -alias "$PIPE_ANDROID_RELEASE_ALIAS" -storepass:file "$work/release.password" \
        -keyalg RSA -keysize 2048 -validity 3650 -dname 'CN=Pipe Beta' -noprompt

      local staged_store= staged_password=
      trap 'rm -f -- "${staged_store:-}" "${staged_password:-}"' EXIT
      staged_store=$(mktemp "$store.XXXXXX")
      staged_password=$(mktemp "$password_file.XXXXXX")
      cat "$work/release.p12" > "$staged_store"
      cat "$work/release.password" > "$staged_password"
      mv -T -- "$staged_password" "$password_file"
      if ! mv -T -- "$staged_store" "$store"; then
        rm -f -- "$password_file"
        exit 1
      fi
    fi
    if [[ ! -f $store || ! -f $password_file || ! -s $password_file ]]; then
      printf 'Release signing requires both the existing keystore and its password file.\n' >&2
      exit 1
    fi
    if [[ $(stat -c '%a' -- "$password_file") != 600 ]]; then
      printf 'The release signing password file must have mode 0600.\n' >&2
      exit 1
    fi
  ) 9>> "$store.lock"
}

prepare_release_signing

if [[ ${PIPE_OFFLINE:-} == 1 ]]; then
  mkdir -p "$work/java-home"
  export GRADLE_OPTS="${GRADLE_OPTS:-} -Duser.home=$work/java-home"
fi
"$gradle" "${gradle_args[@]}" assembleDebug
"$gradle" "${gradle_args[@]}" assembleRelease

apk_dir=android/app/build/outputs/apk
shopt -s nullglob
debug_apks=("$apk_dir"/debug/*.apk)
release_apks=("$apk_dir"/release/*.apk)
if (( ${#debug_apks[@]} != 2 || ${#release_apks[@]} != 2 )); then
  printf 'Expected separate arm64 and x86_64 APKs for each build type.\n' >&2
  exit 1
fi
for apk in "${debug_apks[@]}" "${release_apks[@]}"; do
  stat -c '%n %s bytes' "$apk"
done
arm64_release=("$apk_dir"/release/*arm64-v8a*.apk)
if (( ${#arm64_release[@]} != 1 )) || (( $(stat -c '%s' "${arm64_release[0]}") > 20000000 )); then
  printf 'The arm64 release APK is missing or exceeds 20 MB.\n' >&2
  exit 1
fi
