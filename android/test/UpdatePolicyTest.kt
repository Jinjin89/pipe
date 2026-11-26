// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.content.pm.PackageInstaller
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

fun main() {
    for (api in 26..28) check(!canCopySecret(api))
    for (api in listOf(29, 32, 33, 36)) check(canCopySecret(api))
    val clip = SecretClip("pipe", "dummy seed", 30_000L)
    check(clip.matches("pipe", "dummy seed"))
    check(!clip.matches("pipe", "user's new clipboard value"))
    check(!clip.matches("another clip", "dummy seed"))
    check(!clip.matches(null, "dummy seed"))

    check(trustedSigningIdentity(setOf("current"), setOf("current"), emptyList()))
    check(!trustedSigningIdentity(setOf("current"), setOf("other"), emptyList()))
    check(trustedSigningIdentity(setOf("current"), setOf("rotated"), listOf("current", "rotated")))
    check(!trustedSigningIdentity(setOf("rotated"), setOf("current"), listOf("current")))
    check(!trustedSigningIdentity(setOf("current"), setOf("other"), listOf("other", "current")))
    check(!trustedSigningIdentity(setOf("current", "second"), setOf("current"), emptyList()))

    val apk = Files.createTempFile("pipe-apk-abi-", ".apk").toFile()
    try {
        fun setLibraries(vararg names: String) {
            ZipOutputStream(apk.outputStream()).use { zip ->
                for (name in names) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(42)
                    zip.closeEntry()
                }
            }
        }
        setLibraries("lib/x86_64/libgojni.so")
        check(correctApkAbi(apk, "x86_64"))
        check(!correctApkAbi(apk, "arm64-v8a"))
        setLibraries("lib/x86_64/libgojni.so", "lib/arm64-v8a/extra.so")
        check(!correctApkAbi(apk, "x86_64"))
    } finally {
        apk.delete()
    }

    UpdateInstallResult.begin()
    check(UpdateInstallResult.busy)
    UpdateInstallResult.finish(installResultText(PackageInstaller.STATUS_FAILURE_ABORTED))
    check(!UpdateInstallResult.busy)
    check(UpdateInstallResult.message == "Installation cancelled.")
    check(UpdateInstallResult.takeApproval() == null)
    println("PASS Android clipboard identity, APK signer and ABI policy, and installer decline")
}
