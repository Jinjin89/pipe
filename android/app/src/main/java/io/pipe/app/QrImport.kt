// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import mobile.Mobile
import kotlin.math.sqrt

internal const val MAX_QR_SIDE = 1280
internal const val MAX_QR_PIXELS = 2 * 1024 * 1024

internal fun decodeQrFromUri(context: Context, uri: Uri): String {
    val resolver = context.contentResolver
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    // With inJustDecodeBounds, decodeStream returns null and only fills bounds.
    try {
        val stream = resolver.openInputStream(uri) ?: return ""
        stream.use { BitmapFactory.decodeStream(it, null, bounds) }
    } catch (_: Throwable) {
        return ""
    }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return ""

    var sample = 1
    var sw = bounds.outWidth
    var sh = bounds.outHeight
    while (maxOf(sw, sh) > MAX_QR_SIDE || sw.toLong() * sh.toLong() > MAX_QR_PIXELS) {
        sample *= 2
        sw = (sw + 1) / 2
        sh = (sh + 1) / 2
    }

    var bitmap = try {
        val opts = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        resolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) }
    } catch (_: Throwable) {
        null
    } ?: return ""

    return try {
        if (maxOf(bitmap.width, bitmap.height) > MAX_QR_SIDE ||
            bitmap.width.toLong() * bitmap.height.toLong() > MAX_QR_PIXELS
        ) {
            val scale = minOf(
                MAX_QR_SIDE.toDouble() / maxOf(bitmap.width, bitmap.height),
                sqrt(MAX_QR_PIXELS.toDouble() / (bitmap.width.toDouble() * bitmap.height.toDouble())),
            )
            val nw = maxOf(1, (bitmap.width * scale).toInt())
            val nh = maxOf(1, (bitmap.height * scale).toInt())
            val scaled = Bitmap.createScaledBitmap(bitmap, nw, nh, true)
            if (scaled !== bitmap) {
                bitmap.recycle()
                bitmap = scaled
            }
        }
        val w = bitmap.width
        val h = bitmap.height
        if (w <= 0 || h <= 0 || w.toLong() * h.toLong() > MAX_QR_PIXELS) return ""
        val pixels = IntArray(w * h)
        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
        val gray = ByteArray(w * h)
        for (i in pixels.indices) {
            val px = pixels[i]
            val a = (px ushr 24) and 0xff
            val r = (px ushr 16) and 0xff
            val g = (px ushr 8) and 0xff
            val b = px and 0xff
            val y = (77 * r + 150 * g + 29 * b) ushr 8
            gray[i] = if (a == 255) y.toByte() else ((y * a + 255 * (255 - a)) / 255).toByte()
        }
        Mobile.decodeQR(gray, w.toLong(), h.toLong(), w.toLong())
    } catch (_: Throwable) {
        ""
    } finally {
        bitmap.recycle()
    }
}
