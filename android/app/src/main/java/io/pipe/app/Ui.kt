// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.os.Build
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import java.util.Locale

internal const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
internal const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

internal fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density + 0.5f).toInt()
internal fun Context.c(id: Int): Int = getColor(id)

internal fun Context.shape(fill: Int, radius: Int, stroke: Int = 0): GradientDrawable =
    GradientDrawable().apply {
        setColor(fill)
        cornerRadius = dp(radius).toFloat()
        if (stroke != 0) setStroke(dp(1), stroke)
    }

internal fun Context.pressable(fill: Int, radius: Int, stroke: Int = 0): Drawable =
    RippleDrawable(ColorStateList.valueOf(c(R.color.ripple)), shape(fill, radius, stroke), shape(-1, radius))

internal fun Context.text(value: CharSequence, size: Float = 15f, color: Int = c(R.color.text), bold: Boolean = false) =
    QuietText(this).apply {
        text = value
        textSize = size
        setTextColor(color)
        if (bold) typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
    }

internal fun Context.pill(value: String, fg: Int, bg: Int): TextView =
    text(value, 12f, fg, true).apply {
        setPadding(dp(10), dp(4), dp(10), dp(4))
        background = shape(bg, 20)
        gravity = Gravity.CENTER
        maxLines = 1
    }

internal fun Context.card(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    setPadding(dp(16), dp(14), dp(16), dp(16))
    background = shape(c(R.color.surface), 14, c(R.color.border))
}

internal fun Context.button(label: String, primary: Boolean = false, danger: Boolean = false): Button =
    Button(this).apply {
        text = label
        isAllCaps = false
        stateListAnimator = null
        textSize = 14f
        minHeight = dp(48)
        minimumHeight = dp(48)
        minWidth = dp(64)
        val fg = if (primary) R.color.on_primary else if (danger) R.color.danger else R.color.primary
        setTextColor(c(fg))
        background = pressable(c(if (primary) R.color.primary else R.color.surface2), 12)
    }

internal fun Context.heading(value: String): TextView =
    text(value, 13f, c(R.color.muted), true).apply {
        isAllCaps = true
        letterSpacing = 0.06f
        if (Build.VERSION.SDK_INT >= 28) isAccessibilityHeading = true
    }

internal fun Context.tapRow(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
    minimumHeight = dp(48)
    isClickable = true
    isFocusable = true
}

internal fun LinearLayout.add(
    child: View, width: Int = MATCH, height: Int = WRAP, top: Int = 0, start: Int = 0, weight: Float = 0f,
): View {
    addView(child, LinearLayout.LayoutParams(width, height, weight).apply {
        topMargin = context.dp(top)
        marginStart = context.dp(start)
    })
    return child
}

internal fun TextView.oneLine(): TextView = apply {
    maxLines = 1
    ellipsize = TextUtils.TruncateAt.END
}

/** A row of mutually exclusive options. */
internal class Segmented(
    context: Context,
    private val labels: List<String>,
    private val ids: List<Int>,
    private val onPick: (Int) -> Unit,
) : LinearLayout(context) {
    private val items = labels.mapIndexed { index, label ->
        context.text(label, 14f, context.c(R.color.text), true).apply {
            id = ids[index]
            gravity = Gravity.CENTER
            minimumHeight = context.dp(44)
            isClickable = true
            isFocusable = true
            setOnClickListener { onPick(index) }
        }
    }

    init {
        orientation = HORIZONTAL
        setPadding(context.dp(3), context.dp(3), context.dp(3), context.dp(3))
        background = context.shape(context.c(R.color.surface2), 12)
        items.forEach { add(it, 0, WRAP, weight = 1f) }
        select(-1)
    }

    private var current = -2

    fun select(index: Int) {
        if (index == current) return
        current = index
        items.forEachIndexed { i, view ->
            val on = i == index
            view.isSelected = on
            view.setTextColor(context.c(if (on) R.color.on_primary else R.color.text))
            view.background = if (on) context.pressable(context.c(R.color.primary), 10) else null
        }
    }

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        items.forEach { it.isEnabled = enabled }
        alpha = if (enabled) 1f else 0.5f
    }
}

internal fun formatRate(bytes: Long): String = when {
    bytes >= 1024 * 1024 -> String.format(Locale.getDefault(), "%.1f MB/s", bytes / (1024.0 * 1024))
    bytes >= 1024 -> String.format(Locale.getDefault(), "%.0f KB/s", bytes / 1024.0)
    else -> "$bytes B/s"
}

internal fun formatBytes(bytes: Long): String = when {
    bytes >= 1024L * 1024 * 1024 -> String.format(Locale.getDefault(), "%.2f GB", bytes / (1024.0 * 1024 * 1024))
    bytes >= 1024 * 1024 -> String.format(Locale.getDefault(), "%.1f MB", bytes / (1024.0 * 1024))
    bytes >= 1024 -> String.format(Locale.getDefault(), "%.0f KB", bytes / 1024.0)
    else -> "$bytes B"
}

internal fun formatSince(millis: Long): String {
    val minutes = (System.currentTimeMillis() - millis) / 60000
    return when {
        millis <= 0 -> ""
        minutes < 1 -> "less than a minute"
        minutes < 60 -> "$minutes min"
        else -> "${minutes / 60} h ${minutes % 60} min"
    }
}

internal fun routeName(tier: String): String = tier.replaceFirstChar { it.uppercase() }

/** Everything the tabs need to draw themselves. */
internal class Model {
    var status = JSONObject()
    var connected = false
    val blocked get() = status.optBoolean("blocked")
    var connecting = false
    var profiles = Profiles()
    var names: List<String> = emptyList()
    var domains: List<String> = emptyList()
    var selectedName = ""
    var hasCdn = false
    var prefs = VpnPreferences()
    var testing = false
}

/** What the tabs can ask the activity to do. */
internal interface Actions {
    fun toggleConnect()
    fun chooseProfile()
    fun showImport()
    fun scanQr()
    fun importFromImage()
    fun pasteImport()
    fun currentProfileLink(): String?
    fun selectProfile(index: Int)
    fun deleteProfile(index: Int)
    fun setRelay(index: Int, link: String, code: String, on: Boolean): String?
    fun setMode(mode: String)
    fun setTier(tier: String)
    fun setRules(rules: List<Rule>)
    fun setLogLevel(level: String)
    fun testRoutes()
    fun fetchLogs(after: Long)
    fun clearLogs()
    fun openApps()
    fun checkUpdates(automatic: Boolean = false)
    fun downloadUpdate()
    fun installUpdate()
    fun toast(text: String)
}

/** Ignores identical updates, so screen readers and UI tools are not flooded with change events every second. */
internal class QuietText(context: Context) : TextView(context) {
    override fun setText(text: CharSequence?, type: BufferType?) {
        if (text != null && this.text != null && this.text.toString() == text.toString()) return
        super.setText(text, type)
    }
}
