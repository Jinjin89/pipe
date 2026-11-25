// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.BitmapDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.provider.Settings
import android.text.InputType
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import mobile.Mobile
import org.json.JSONObject

internal class SettingsView(private val a: Activity, private val act: Actions) {
    val root = ScrollView(a)
    private val profileList = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
    private val relayButton = a.button("Relay").apply { visibility = View.GONE }
    private val deviceLinkCard = a.card()
    private val secretHidden = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
    private val secretShown = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
    private val qrFrame = FrameLayout(a)
    private val qrImage = ImageView(a).apply {
        scaleType = ImageView.ScaleType.FIT_CENTER
        setBackgroundColor(Color.WHITE)
        contentDescription = "Device link QR code"
    }
    private val linkText = monoBox()
    private val proxyBox = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
    private val proxyText = monoBox()
    private val exportText = monoBox()
    private val noProxyNote = a.text("This link has no HTTPS proxy.", 13f, a.c(R.color.muted))

    private val ui = Handler(Looper.getMainLooper())
    private val autoHide = Runnable { hideSecret() }
    private var secretVisible = false
    private var qrBitmap: Bitmap? = null
    private var revealedLink = ""
    private var revealedProxy = ""
    private var revealedCmd = ""

    private val logLevel = Segmented(a, listOf("Normal", "Every connection"), listOf(R.id.log_normal, R.id.log_connections)) {
        act.setLogLevel(if (it == 0) "warn" else "info")
    }
    private val logHint = a.text("", 13f, a.c(R.color.muted))
    private var confirm: AlertDialog? = null
    private var relayDialog: AlertDialog? = null
    private var relayProfile: SavedProfile? = null
    private var drawn: List<String>? = null
    private var drawnIndex = -1

    init {
        val col = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(a.dp(16), a.dp(12), a.dp(16), a.dp(20))
        }
        root.addView(col, MATCH, WRAP)
        col.add(a.text("Settings", 24f, a.c(R.color.text), true))

        val profiles = a.card()
        profiles.add(a.heading("Profiles"))
        profiles.add(profileList, top = 4)
        relayButton.setOnClickListener { relayProfile?.let { editRelay(drawnIndex, it) } }
        profiles.add(relayButton, MATCH, WRAP, top = 8)
        profiles.add(a.button("Import a profile", primary = true).apply {
            id = R.id.import_profile
            setOnClickListener { act.showImport() }
        }, MATCH, WRAP, top = 8)
        profiles.add(a.text("Scan a QR code, pick an image, or paste a Pipe link.", 13f, a.c(R.color.muted)), top = 8)
        col.add(profiles, top = 16)

        buildDeviceLinkCard()
        col.add(deviceLinkCard, top = 12)

        val network = a.card()
        network.add(a.heading("Connection"))
        val apps = a.tapRow().apply {
            id = R.id.open_apps
            setOnClickListener { act.openApps() }
        }
        val words = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        words.add(a.text("Per-app VPN and IPv6", 16f, a.c(R.color.text), true))
        words.add(a.text("Pick which apps use pipe.", 13f, a.c(R.color.muted)))
        apps.add(words, 0, WRAP, weight = 1f)
        apps.add(a.text("›", 22f, a.c(R.color.muted)), WRAP, WRAP)
        network.add(apps, MATCH, WRAP, top = 4)
        network.add(a.text("For a kill switch, turn on Always-on VPN and Block connections without VPN in Android settings.", 13f, a.c(R.color.muted)), top = 8)
        network.add(a.button("Android VPN settings").apply {
            setOnClickListener {
                try {
                    a.startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                } catch (_: Exception) {
                    act.toast("Open Android settings and search for VPN")
                }
            }
        }, MATCH, WRAP, top = 8)
        col.add(network, top = 12)

        val logs = a.card()
        logs.add(a.heading("Logs"))
        logs.add(a.text("Log detail", 16f, a.c(R.color.text), true), top = 4)
        logs.add(logLevel, top = 8)
        logs.add(logHint, top = 8)
        col.add(logs, top = 12)

        val about = a.card()
        about.add(a.heading("About"))
        about.add(a.text("pipe ${Mobile.version()}", 16f, a.c(R.color.text), true), top = 4)
        about.add(a.text("A private VPN. Logs stay in memory and are never saved to disk.", 13f, a.c(R.color.muted)), top = 2)
        col.add(about, top = 12)
    }

    private fun monoBox(): TextView = a.text("", 12f, a.c(R.color.text)).apply {
        typeface = Typeface.MONOSPACE
        setPadding(a.dp(12), a.dp(10), a.dp(12), a.dp(10))
        background = a.shape(a.c(R.color.surface2), 10)
    }

    private fun buildDeviceLinkCard() {
        deviceLinkCard.add(a.heading("Device link"))

        secretHidden.add(a.text("Hidden", 15f, a.c(R.color.text), true), top = 8)
        secretHidden.add(monoBox().apply {
            text = "pipe://••••••••••••••••••••••••••••••••"
            setTextColor(a.c(R.color.muted))
        }, top = 6)
        secretHidden.add(a.text("Your link, QR code and HTTPS proxy stay hidden until you tap Show.", 13f, a.c(R.color.muted)), top = 6)
        secretHidden.add(a.button("Show").apply { setOnClickListener { revealSecret() } }, MATCH, WRAP, top = 10)
        deviceLinkCard.add(secretHidden)

        qrFrame.apply {
            background = a.shape(Color.WHITE, 12, a.c(R.color.border))
            setPadding(a.dp(10), a.dp(10), a.dp(10), a.dp(10))
            addView(qrImage, FrameLayout.LayoutParams(MATCH, MATCH))
        }
        secretShown.add(qrFrame, a.dp(220), a.dp(220), top = 10).also {
            (it.layoutParams as LinearLayout.LayoutParams).gravity = Gravity.CENTER_HORIZONTAL
        }

        secretShown.add(a.text("Link", 13f, a.c(R.color.muted), true), top = 12)
        secretShown.add(linkText, top = 4)
        secretShown.add(a.button("Copy link").apply {
            setOnClickListener { copySensitive("Pipe link", revealedLink, "Device link copied") }
        }, MATCH, WRAP, top = 6)

        proxyBox.add(a.text("HTTPS proxy", 13f, a.c(R.color.muted), true), top = 12)
        proxyBox.add(proxyText, top = 4)
        proxyBox.add(a.button("Copy proxy URL").apply {
            setOnClickListener { copySensitive("Pipe HTTPS proxy", revealedProxy, "HTTPS proxy URL copied") }
        }, MATCH, WRAP, top = 6)
        proxyBox.add(a.text("Terminal command", 13f, a.c(R.color.muted), true), top = 12)
        proxyBox.add(exportText, top = 4)
        proxyBox.add(a.button("Copy export command").apply {
            setOnClickListener { copySensitive("Pipe proxy command", revealedCmd, "Terminal command copied") }
        }, MATCH, WRAP, top = 6)
        secretShown.add(proxyBox)

        secretShown.add(noProxyNote, top = 10)
        secretShown.add(a.text("Hides automatically after 30 s.", 13f, a.c(R.color.muted)), top = 10)
        secretShown.add(a.button("Hide").apply { setOnClickListener { hideSecret() } }, MATCH, WRAP, top = 8)
        deviceLinkCard.add(secretShown)
        deviceLinkCard.visibility = View.GONE
    }

    private fun revealSecret() {
        val raw = act.currentProfileLink()?.trim().orEmpty()
        if (raw.isEmpty()) return
        val details = try {
            JSONObject(Mobile.linkDetails(raw))
        } catch (_: Exception) {
            act.toast("Could not load device link")
            return
        }
        val proxy = details.optString("proxy")
        val bitmap = try {
            val bytes = Base64.decode(details.optString("qr"), Base64.DEFAULT)
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        } catch (_: Exception) {
            null
        }

        // Protect the window before placing any secret into a View.
        a.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        secretVisible = true

        qrImage.setImageDrawable(null)
        qrBitmap?.recycle()
        qrBitmap = bitmap
        if (bitmap != null) {
            qrImage.setImageDrawable(BitmapDrawable(a.resources, bitmap).apply {
                setFilterBitmap(false)
                setAntiAlias(false)
            })
            qrFrame.visibility = View.VISIBLE
        } else {
            qrFrame.visibility = View.GONE
        }

        revealedLink = raw
        revealedProxy = proxy
        revealedCmd = details.optString("export")
        linkText.text = revealedLink
        if (proxy.isNotEmpty()) {
            proxyText.text = revealedProxy
            exportText.text = revealedCmd
            proxyBox.visibility = View.VISIBLE
            noProxyNote.visibility = View.GONE
        } else {
            proxyText.text = ""
            exportText.text = ""
            proxyBox.visibility = View.GONE
            noProxyNote.visibility = View.VISIBLE
        }

        secretHidden.visibility = View.GONE
        secretShown.visibility = View.VISIBLE
        ui.removeCallbacks(autoHide)
        ui.postDelayed(autoHide, SECRET_TTL_MS)
    }

    fun hideSecret() {
        ui.removeCallbacks(autoHide)
        revealedLink = ""
        revealedProxy = ""
        revealedCmd = ""
        linkText.text = ""
        proxyText.text = ""
        exportText.text = ""
        qrImage.setImageDrawable(null)
        qrBitmap?.recycle()
        qrBitmap = null
        secretShown.visibility = View.GONE
        secretHidden.visibility = View.VISIBLE
        if (secretVisible) {
            secretVisible = false
            a.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    private fun copySensitive(label: String, value: String, message: String) {
        if (value.isEmpty()) return
        val clip = ClipData.newPlainText(label, value)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        a.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        act.toast(message)
    }

    fun render(m: Model) {
        val level = m.prefs.logLevel
        logLevel.select(if (level == "info") 1 else 0)
        logHint.text = if (level == "info") "Logs show every connection and the route it took."
        else "Logs show problems only."
        relayProfile = m.profiles.current
        val hasProfile = relayProfile != null
        relayButton.visibility = if (hasProfile) View.VISIBLE else View.GONE
        deviceLinkCard.visibility = if (hasProfile) View.VISIBLE else View.GONE
        if (!hasProfile) hideSecret()
        if (drawn != m.names || drawnIndex != m.profiles.selected) {
            if (drawnIndex != m.profiles.selected) hideSecret()
            drawn = m.names
            drawnIndex = m.profiles.selected
            drawProfiles(m)
        }
    }

    private fun editRelay(index: Int, profile: SavedProfile) {
        val form = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(a.dp(20), a.dp(8), a.dp(20), 0)
        }
        val code = EditText(a).apply {
            hint = "Relay IP, name or code"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine()
            setTextColor(a.c(R.color.text))
            setHintTextColor(a.c(R.color.muted))
            setText(profile.relay.code)
            minHeight = a.dp(48)
        }
        val enabled = Switch(a).apply {
            text = "Use relay"
            isChecked = profile.relay.on
            minHeight = a.dp(48)
        }
        form.add(code)
        form.add(enabled, top = 4)
        relayDialog?.dismiss()
        val dialog = AlertDialog.Builder(a)
            .setTitle("Relay")
            .setView(form)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val error = act.setRelay(index, profile.link, code.text.toString(), enabled.isChecked)
                if (error == null) dialog.dismiss() else code.error = error
            }
        }
        dialog.setOnDismissListener { if (relayDialog === dialog) relayDialog = null }
        relayDialog = dialog
        dialog.show()
    }

    private fun drawProfiles(m: Model) {
        profileList.removeAllViews()
        if (m.names.isEmpty()) {
            profileList.add(a.text("No profiles yet.", 14f, a.c(R.color.muted)).apply { minHeight = a.dp(48); gravity = Gravity.CENTER_VERTICAL })
            return
        }
        m.names.forEachIndexed { index, name ->
            val active = index == m.profiles.selected
            val row = a.tapRow().apply { setOnClickListener { act.selectProfile(index) } }
            val words = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
            words.add(a.text(name, 16f, a.c(R.color.text), true).oneLine())
            words.add(a.text(m.domains.getOrElse(index) { "" }, 13f, a.c(R.color.muted)).oneLine())
            row.add(words, 0, WRAP, weight = 1f)
            if (active) row.add(a.pill("Active", a.c(R.color.connected), a.c(R.color.connected_soft)), WRAP, WRAP, start = 8)
            row.add(a.text("×", 22f, a.c(R.color.muted), true).apply {
                gravity = Gravity.CENTER
                contentDescription = "Delete profile $name"
                isClickable = true
                setOnClickListener { confirmDelete(index, name) }
            }, a.dp(48), a.dp(48))
            profileList.add(row)
        }
    }

    private fun confirmDelete(index: Int, name: String) {
        confirm?.dismiss()
        confirm = AlertDialog.Builder(a)
            .setTitle("Delete $name?")
            .setMessage("The saved link for this profile will be removed from this phone.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete") { _, _ -> act.deleteProfile(index) }
            .show()
    }

    fun dismiss() {
        hideSecret()
        confirm?.dismiss()
        confirm = null
        relayDialog?.dismiss()
    }

    private companion object {
        const val SECRET_TTL_MS = 30_000L
    }
}
