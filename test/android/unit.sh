#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
work=$(mktemp -d /tmp/pipe-android-unit.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
java=${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}/bin/java
kotlin_lib=/opt/gradle/lib
stdlib=$kotlin_lib/kotlin-stdlib-2.4.21.jar
platform=${ANDROID_HOME:-/opt/android-sdk}/platforms/android-36/android.jar

"$java" -Xmx256m -cp "$kotlin_lib/*" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -classpath "$stdlib:$platform" -d "$work" \
  android/app/src/main/java/io/pipe/app/AndroidNetworks.kt test/android/NetworkChangesTest.kt
"$java" -cp "$work:$stdlib:$platform" io.pipe.app.NetworkChangesTestKt
printf 'PASS Android default-network changes\n'
