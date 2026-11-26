// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.Activity
import android.content.Context
import android.view.View
import android.widget.Switch
import mobile.Mobile
import org.json.JSONObject

internal class UpdatesView(private val a: Activity, actions: Actions) {
    val root = a.card()
    private val detail = a.text("", 13f, a.c(R.color.muted)).apply {
        accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
    }
    private val check = a.button("Check now").apply { setOnClickListener { actions.checkUpdates() } }
    private val download = a.button("Download", primary = true).apply {
        setOnClickListener { actions.downloadUpdate() }
    }
    private val install = a.button("Install update", primary = true).apply {
        setOnClickListener { actions.installUpdate() }
    }

    init {
        root.add(a.heading("Updates"))
        root.add(a.text("Installed version ${Mobile.version()}", 14f, a.c(R.color.text)), top = 4)
        root.add(Switch(a).apply {
            text = "Check automatically"
            minHeight = a.dp(48)
            isChecked = automatic(a)
            setOnCheckedChangeListener { _, enabled ->
                prefs(a).edit().putBoolean(AUTO, enabled).apply()
                if (enabled) actions.checkUpdates(automatic = true)
            }
        }, top = 6)
        root.add(detail, top = 4)
        root.add(check, MATCH, WRAP, top = 8)
        root.add(download, MATCH, WRAP, top = 6)
        root.add(install, MATCH, WRAP, top = 6)
        render(JSONObject())
    }

    fun render(status: JSONObject) {
        val version = status.optString("version")
        val ready = status.optString("artifact").isNotEmpty()
        val busy = status.optString("state") in setOf("checking", "downloading") || UpdateInstallResult.busy
        val text = UpdateInstallResult.message.ifEmpty {
            when (status.optString("state")) {
                "checking" -> "Checking for updates…"
                "available" -> "Version $version is available."
                "current" -> "Pipe is up to date."
                "downloading" -> "Downloading version $version…"
                "ready" -> "Version $version is verified and ready."
                "error" -> status.optString("error")
                else -> ""
            }
        }
        if (detail.text.toString() != text) detail.text = text
        detail.visibility = if (text.isEmpty()) View.GONE else View.VISIBLE
        check.isEnabled = !busy
        download.visibility = if (version.isNotEmpty() && !ready) View.VISIBLE else View.GONE
        download.isEnabled = !busy
        install.visibility = if (ready) View.VISIBLE else View.GONE
        install.isEnabled = !busy
    }

    companion object {
        private const val AUTO = "automatic"
        private fun prefs(context: Context) = context.getSharedPreferences("updates", Context.MODE_PRIVATE)
        fun automatic(context: Context) = prefs(context).getBoolean(AUTO, true)
    }
}
