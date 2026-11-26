// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import java.security.MessageDigest
import java.util.UUID

internal const val PIPE_CLIP_TTL = 30_000L

internal fun canCopySecret(api: Int) = api >= 29

internal class SecretClip(private val id: String, value: String, val expiresAt: Long) {
    private val fingerprint = digest(value)

    fun matches(marker: String?, value: String?): Boolean =
        marker == id && value != null && MessageDigest.isEqual(fingerprint, digest(value))

    private fun digest(value: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
}

internal object SecretClipboard {
    private const val MARKER = "io.pipe.app.secret_clip"
    private val ui = Handler(Looper.getMainLooper())
    private var owned: SecretClip? = null

    val supported get() = canCopySecret(Build.VERSION.SDK_INT)

    fun copy(context: Context, label: String, value: String): Boolean {
        if (!supported || value.isEmpty()) return false
        val token = UUID.randomUUID().toString()
        val clip = ClipData.newPlainText(label, value)
        clip.description.extras = PersistableBundle().apply {
            putString(MARKER, token)
            if (Build.VERSION.SDK_INT >= 33) putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
        val manager = context.getSystemService(ClipboardManager::class.java)
        if (runCatching { manager.setPrimaryClip(clip) }.isFailure) return false
        owned = SecretClip(token, value, SystemClock.elapsedRealtime() + PIPE_CLIP_TTL)
        val app = context.applicationContext
        ui.postDelayed({ clearExpired(app) }, PIPE_CLIP_TTL)
        return true
    }

    fun clearExpired(context: Context) {
        val expected = owned ?: return
        if (SystemClock.elapsedRealtime() < expected.expiresAt) return
        val manager = context.getSystemService(ClipboardManager::class.java)
        // Android 10+ may hide the clipboard while the app lacks focus.
        val clip = runCatching { manager.primaryClip }.getOrNull() ?: return
        owned = null
        if (clip.itemCount == 1 && expected.matches(
                clip.description.extras?.getString(MARKER), clip.getItemAt(0).text?.toString()
            )
        ) {
            runCatching { manager.clearPrimaryClip() }
        }
    }
}
