#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
work=$(mktemp -d /tmp/pipe-update-policy.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
java=${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}/bin/java
kotlin_lib=/opt/gradle/lib
stdlib=$kotlin_lib/kotlin-stdlib-2.4.21.jar
platform=${ANDROID_HOME:-/opt/android-sdk}/platforms/android-36/android.jar
sources=android/app/src/main/java/io/pipe/app

"$java" -Xmx256m -cp "$kotlin_lib/*" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -classpath "$stdlib:$platform" -d "$work" \
  "$sources/SecretClipboard.kt" "$sources/UpdateInstaller.kt" android/test/UpdatePolicyTest.kt
"$java" -cp "$work:$stdlib:$platform" io.pipe.app.UpdatePolicyTestKt
