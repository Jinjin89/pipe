// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.util.zip.ZipFile

internal fun updateAbi(): String = Build.SUPPORTED_ABIS.firstOrNull { it == "arm64-v8a" || it == "x86_64" }.orEmpty()

internal fun <T> trustedSigningIdentity(installed: Set<T>, offered: Set<T>, lineage: List<T>): Boolean {
    if (installed.isEmpty() || offered.isEmpty()) return false
    if (installed == offered) return true
    return installed.size == 1 && offered.size == 1 && lineage.lastOrNull() == offered.single() &&
        installed.single() in lineage.dropLast(1)
}

internal fun correctApkAbi(file: File, abi: String): Boolean {
    if (abi != "arm64-v8a" && abi != "x86_64") return false
    return ZipFile(file).use { apk ->
        val libraries = apk.entries().asSequence()
            .filter { !it.isDirectory && it.name.startsWith("lib/") }
            .map { it.name }
            .toList()
        libraries.count { it == "lib/$abi/libgojni.so" } == 1 && libraries.all { it.startsWith("lib/$abi/") }
    }
}

@Suppress("DEPRECATION")
private fun PackageInfo.code(): Long =
    if (Build.VERSION.SDK_INT >= 28) longVersionCode else versionCode.toLong()

@Suppress("DEPRECATION")
private fun signedByInstalledApp(installed: PackageInfo, offered: PackageInfo): Boolean {
    if (Build.VERSION.SDK_INT >= 28) {
        val current = installed.signingInfo ?: return false
        val next = offered.signingInfo ?: return false
        val lineage = if (next.hasMultipleSigners()) emptyList() else next.signingCertificateHistory.orEmpty().toList()
        return trustedSigningIdentity(current.apkContentsSigners.orEmpty().toSet(), next.apkContentsSigners.orEmpty().toSet(), lineage)
    }
    val signers = installed.signatures.orEmpty().toSet()
    return signers.isNotEmpty() && signers == offered.signatures.orEmpty().toSet()
}

internal class UpdateInstallException(message: String) : Exception(message)

@Suppress("DEPRECATION")
internal fun submitVerifiedApk(context: Context, file: File, version: String, abi: String) {
    val packages = context.packageManager
    if (!packages.canRequestPackageInstalls()) throw UpdateInstallException("Allow Pipe to install updates in Android settings.")
    val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
    val current = packages.getPackageInfo(context.packageName, flags)
    val apk = packages.getPackageArchiveInfo(file.absolutePath, flags)
        ?: throw UpdateInstallException("Android could not read the verified APK.")
    if (apk.packageName != context.packageName || apk.versionName != version || apk.code() <= current.code()) {
        throw UpdateInstallException("The APK does not update this installed version of Pipe.")
    }
    if (!correctApkAbi(file, abi)) throw UpdateInstallException("The APK does not match this device's CPU.")
    if (!signedByInstalledApp(current, apk)) throw UpdateInstallException("The APK signer does not match the installed app.")

    val installer = packages.packageInstaller
    val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
        setAppPackageName(context.packageName)
        setSize(file.length())
        if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
    }
    val id = installer.createSession(params)
    var committed = false
    try {
        installer.openSession(id).use { session ->
            session.openWrite("base.apk", 0, file.length()).use { output ->
                file.inputStream().use { source -> source.copyTo(output) }
                session.fsync(output)
            }
            val result = PendingIntent.getBroadcast(
                context, id, Intent(context, UpdateInstallReceiver::class.java).setAction(UpdateInstallReceiver.ACTION),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            session.commit(result.intentSender)
            committed = true
        }
    } finally {
        if (!committed) runCatching { installer.abandonSession(id) }
    }
}

internal object UpdateInstallResult {
    var busy = false
        private set
    var preparing = false
        private set
    var message = ""
        private set
    var changed: (() -> Unit)? = null
    private var approval: Intent? = null

    fun begin() {
        busy = true
        preparing = true
        message = "Preparing Android installer…"
        changed?.invoke()
    }

    fun approve(intent: Intent) {
        busy = true
        preparing = false
        approval = intent
        message = "Waiting for Android approval…"
        changed?.invoke()
    }

    fun cancelPreparation(text: String) {
        if (!preparing) return
        finish(text)
    }

    fun finish(text: String) {
        busy = false
        preparing = false
        approval = null
        message = text
        changed?.invoke()
    }

    fun takeApproval(): Intent? = approval.also { approval = null }
}

internal fun installResultText(status: Int): String = when (status) {
    PackageInstaller.STATUS_SUCCESS -> "Update installed."
    PackageInstaller.STATUS_FAILURE_ABORTED -> "Installation cancelled."
    else -> "Android could not install the update."
}

class UpdateInstallReceiver : BroadcastReceiver() {
    @Suppress("DEPRECATION")
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            val approval = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            else intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
            if (approval == null) UpdateInstallResult.finish("Android could not open the installer.")
            else UpdateInstallResult.approve(approval)
        } else {
            UpdateInstallResult.finish(installResultText(status))
        }
    }

    companion object {
        const val ACTION = "io.pipe.app.UPDATE_INSTALL_STATUS"
    }
}
