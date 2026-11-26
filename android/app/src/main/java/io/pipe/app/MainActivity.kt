// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.res.ColorStateList
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Messenger
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import mobile.Mobile
import org.json.JSONObject
import java.util.concurrent.Executors

class MainActivity : Activity(), Actions {
    private lateinit var profileStore: ProfileStore
    private lateinit var home: HomeView
    private lateinit var routing: RoutingView
    private lateinit var logs: LogsView
    private lateinit var settings: SettingsView
    private val tabViews = ArrayList<View>()
    private val tabButtons = ArrayList<Pair<ImageView, TextView>>()
    private var tab = 0
    private val model = Model()
    private val ui = Handler(Looper.getMainLooper())
    private var service: Messenger? = null
    private var bound = false
    private var started = false
    private var resumed = false
    private var pendingPrefs = false
    private var importDialog: AlertDialog? = null
    private var chooser: AlertDialog? = null
    private var pendingLink: String? = null
    private class PendingImport(var link: String?)
    private val imageLoader = Executors.newSingleThreadExecutor()

    private val poll = object : Runnable {
        override fun run() {
            if (started && tab == LOGS_TAB) {
                if (!logs.paused) fetchLogs(logCursor)
                ui.postDelayed(this, 1000)
            }
        }
    }
    private var logCursor = 0L
    private var applyPending = false
    private val applyLater = Runnable {
        applyPending = false
        applyPreferences()
    }
    private val testTimeout = Runnable { endTest() }
    private var updateStatus = JSONObject()
    private val updatePoll = Runnable(::pollUpdates)
    private val installPrepTimeout = Runnable {
        UpdateInstallResult.cancelPreparation("Pipe updater timed out. Try again.")
    }

    private val listener = Messenger(Handler(Looper.getMainLooper()) { message ->
        when (message.what) {
            VpnControl.STATUS -> message.data.getString(VpnControl.STATUS_JSON)?.let {
                model.status = JSONObject(it)
                model.connected = model.status.optBoolean("running")
                if (model.connected || model.status.optString("lastError").isNotEmpty()) model.connecting = false
                render()
            }
            VpnControl.LOGS -> message.data.getString(VpnControl.PAYLOAD)?.let {
                logs.onLogs(it)
                logCursor = runCatching { JSONObject(it).getLong("next") }.getOrDefault(logCursor)
            }
            VpnControl.TEST_DONE -> endTest()
            VpnControl.UPDATE_STATUS -> message.data.getString(VpnControl.PAYLOAD)?.let {
                updateStatus = JSONObject(it)
                settings.renderUpdates(updateStatus)
                ui.removeCallbacks(updatePoll)
                if (resumed && updateStatus.optString("state") in setOf("checking", "downloading")) {
                    ui.postDelayed(updatePoll, 750)
                }
            }
            VpnControl.UPDATE_INSTALL_ERROR -> {
                ui.removeCallbacks(installPrepTimeout)
                UpdateInstallResult.finish(message.data.getString(VpnControl.PAYLOAD).orEmpty())
                pollUpdates()
            }
        }
        true
    })

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = Messenger(binder)
            VpnControl.send(service, VpnControl.SUBSCRIBE, listener)
            if (pendingPrefs) applyPreferences()
            if (resumed) resumeUpdateChecks()
            startPolling()
        }

        override fun onServiceDisconnected(name: ComponentName) {
            service = null
            model.connecting = false
            model.connected = false
            model.testing = false
            model.status = JSONObject()
            updateStatus = JSONObject()
            UpdateInstallResult.cancelPreparation("Pipe updater disconnected. Try again.")
            settings.renderUpdates(updateStatus)
            render()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        profileStore = ProfileStore(this)
        home = HomeView(this, this)
        routing = RoutingView(this, this)
        logs = LogsView(this, this)
        settings = SettingsView(this, this)

        val content = FrameLayout(this)
        listOf(home.root, routing.root, logs.root, settings.root).forEach {
            tabViews.add(it)
            content.addView(it, MATCH, MATCH)
        }
        val bar = LinearLayout(this).apply {
            background = shape(c(R.color.surface), 0)
        }
        val divider = View(this).apply { setBackgroundColor(c(R.color.border)) }
        listOf(
            Triple("Home", R.drawable.ic_tab_home, R.id.tab_home),
            Triple("Routing", R.drawable.ic_tab_routing, R.id.tab_routing),
            Triple("Logs", R.drawable.ic_tab_logs, R.id.tab_logs),
            Triple("Settings", R.drawable.ic_tab_settings, R.id.tab_settings),
        ).forEachIndexed { index, (label, icon, id) ->
            val item = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                this.id = id
                isClickable = true
                isFocusable = true
                contentDescription = label
                background = pressable(0, 0)
                setOnClickListener { showTab(index) }
            }
            val image = ImageView(this).apply {
                setImageResource(icon)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            val name = text(label, 12f, c(R.color.muted), true).apply {
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            item.add(image, dp(24), dp(24))
            item.add(name, WRAP, WRAP, top = 2)
            tabButtons.add(image to name)
            bar.add(item, 0, dp(60), weight = 1f)
        }
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.add(content, MATCH, 0, weight = 1f)
        root.add(divider, MATCH, 1)
        root.add(bar, MATCH, WRAP)
        setContentView(root)
        root.padForSystemBars()
        tab = savedInstanceState?.getInt("tab") ?: 0
        showTab(tab)
        @Suppress("DEPRECATION")
        (lastNonConfigurationInstance as? PendingImport)?.let { retained ->
            val raw = retained.link
            retained.link = null
            raw?.let(::confirmImport)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt("tab", tab)
    }

    @Suppress("DEPRECATION")
    override fun onRetainNonConfigurationInstance(): Any? = pendingLink?.let { PendingImport(it) }

    private fun showTab(index: Int) {
        if (index != SETTINGS_TAB) settings.hideSecret()
        tab = index
        tabViews.forEachIndexed { i, view -> view.visibility = if (i == index) View.VISIBLE else View.GONE }
        tabButtons.forEachIndexed { i, (image, name) ->
            val color = c(if (i == index) R.color.primary else R.color.muted)
            image.imageTintList = ColorStateList.valueOf(color)
            name.setTextColor(color)
        }
        if (index == LOGS_TAB) {
            startPolling()
        } else {
            ui.removeCallbacks(poll)
            getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(tabViews[index].windowToken, 0)
        }
        render()
    }

    override fun onStart() {
        super.onStart()
        started = true
        refreshProfiles()
        bound = bindService(VpnControl.intent(this, VpnControl.BIND), connection, Context.BIND_AUTO_CREATE)
        startPolling()
    }

    private fun startPolling() {
        ui.removeCallbacks(poll)
        if (tab == LOGS_TAB) poll.run()
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        UpdateInstallResult.changed = ::renderInstallation
        renderInstallation()
        resumeUpdateChecks()
    }

    override fun onPause() {
        resumed = false
        UpdateInstallResult.changed = null
        ui.removeCallbacks(updatePoll)
        settings.hideSecret()
        super.onPause()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) SecretClipboard.clearExpired(this)
    }

    override fun onStop() {
        started = false
        if (applyPending) {
            ui.removeCallbacks(applyLater)
            applyPending = false
            applyPreferences()
        }
        ui.removeCallbacks(poll)
        ui.removeCallbacks(testTimeout)
        model.testing = false
        if (bound) {
            VpnControl.send(service, VpnControl.UNSUBSCRIBE, listener)
            unbindService(connection)
            bound = false
        }
        service = null
        super.onStop()
    }

    override fun onDestroy() {
        importDialog?.dismiss()
        importDialog = null
        pendingLink = null
        chooser?.dismiss()
        chooser = null
        routing.dismiss()
        settings.dismiss()
        imageLoader.shutdownNow()
        ui.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    @Deprecated("Platform activity results are used without AndroidX.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            CONSENT -> if (resultCode == RESULT_OK) connectVPN()
            APPS -> if (resultCode == RESULT_OK) {
                model.prefs = runCatching { VpnPreferences.read(this) }.getOrDefault(model.prefs)
                applyPreferences()
                render()
            }
            SCAN_QR -> when (resultCode) {
                RESULT_OK -> data?.getStringExtra(ScanActivity.EXTRA_LINK)?.takeIf { it.isNotEmpty() }?.let { confirmImport(it) }
                ScanActivity.RESULT_FROM_IMAGE -> importFromImage()
            }
            PICK_IMAGE -> if (resultCode == RESULT_OK) {
                data?.data?.let { decodePickedImage(it) }
            }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERM) {
            if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
                launchScanner()
            } else {
                showImportDialog(AlertDialog.Builder(this)
                    .setTitle("Camera permission needed")
                    .setMessage("Pipe needs camera access to scan a QR code. You can import a QR code from an image instead.")
                    .setPositiveButton("From image") { _, _ -> importFromImage() }
                    .setNegativeButton("Cancel", null)
                )
            }
        }
    }

    // Actions

    override fun toggleConnect() {
        if (model.connected || model.blocked) {
            startService(VpnControl.intent(this, VpnControl.DISCONNECT))
        } else if (model.profiles.current == null) {
            showImport()
        } else {
            val consent = VpnService.prepare(this)
            if (consent == null) connectVPN() else startActivityForResult(consent, CONSENT)
        }
    }

    override fun setMode(mode: String) = change { it.copy(mode = mode) }
    override fun setTier(tier: String) = change { it.copy(tier = tier) }
    override fun setLogLevel(level: String) = change { it.copy(logLevel = level) }

    override fun setRules(rules: List<Rule>) = change(debounce = true) { it.copy(rules = rules) }

    private fun change(debounce: Boolean = false, edit: (VpnPreferences) -> VpnPreferences) {
        try {
            val next = edit(VpnPreferences.read(this))
            next.save(this)
            model.prefs = next
            ui.removeCallbacks(applyLater)
            applyPending = false
            if (model.connected || model.connecting) {
                if (debounce) {
                    applyPending = true
                    ui.postDelayed(applyLater, 500)
                } else {
                    applyPreferences()
                }
            }
        } catch (_: Exception) {
            toast("Could not save your change")
        }
        render()
    }

    override fun testRoutes() {
        if (!model.connected || model.testing) return
        model.testing = true
        ui.postDelayed(testTimeout, 20_000)
        if (!VpnControl.send(service, VpnControl.TEST_ROUTES, listener)) endTest()
        render()
    }

    private fun endTest() {
        ui.removeCallbacks(testTimeout)
        model.testing = false
        render()
    }

    override fun fetchLogs(after: Long) {
        VpnControl.send(service, VpnControl.LOGS_REQUEST, listener, after = after)
    }

    override fun clearLogs() {
        VpnControl.send(service, VpnControl.CLEAR_LOGS)
    }

    override fun openApps() {
        startActivityForResult(Intent(this, SettingsActivity::class.java), APPS)
    }

    private fun resumeUpdateChecks() {
        if (UpdatesView.automatic(this)) checkUpdates(automatic = true)
        else pollUpdates()
    }

    private fun pollUpdates() {
        VpnControl.send(service, VpnControl.UPDATE_POLL, listener)
    }

    private fun updateFlags(): Int =
        if (model.connected || model.connecting || model.blocked) VpnControl.UPDATE_VIA_TUNNEL else 0

    override fun checkUpdates(automatic: Boolean) {
        if (!automatic) UpdateInstallResult.finish("")
        val flag = if (automatic) VpnControl.UPDATE_AUTOMATIC else 0
        if (!VpnControl.send(service, VpnControl.UPDATE_CHECK, listener, flags = updateFlags() or flag) && !automatic) {
            toast("Pipe updater is unavailable. Try again.")
        }
    }

    override fun downloadUpdate() {
        UpdateInstallResult.finish("")
        if (!VpnControl.send(service, VpnControl.UPDATE_DOWNLOAD, listener, flags = updateFlags())) {
            toast("Pipe updater is unavailable. Try again.")
        }
    }

    override fun installUpdate() {
        val artifact = updateStatus.optString("artifact")
        if (artifact.isEmpty() || UpdateInstallResult.busy) return
        if (!packageManager.canRequestPackageInstalls()) {
            val source = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName"))
            if (runCatching { startActivity(source) }.isFailure) toast("Allow Pipe to install updates in Android settings.")
            return
        }
        UpdateInstallResult.begin()
        ui.removeCallbacks(installPrepTimeout)
        ui.postDelayed(installPrepTimeout, 15_000L)
        if (!VpnControl.send(service, VpnControl.UPDATE_INSTALL, listener, payload = artifact)) {
            ui.removeCallbacks(installPrepTimeout)
            UpdateInstallResult.finish("Pipe updater is unavailable. Try again.")
        }
    }

    private fun renderInstallation() {
        settings.renderUpdates(updateStatus)
        if (!resumed || isFinishing || isDestroyed) return
        UpdateInstallResult.takeApproval()?.let {
            if (runCatching { startActivity(it) }.isFailure) {
                UpdateInstallResult.finish("Android could not open the installer.")
            }
        }
    }

    override fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_SHORT).show()

    private fun connectVPN() {
        model.connecting = true
        render()
        try {
            startForegroundService(VpnControl.intent(this, VpnControl.CONNECT))
            if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATIONS)
            }
        } catch (_: Exception) {
            model.connecting = false
            model.status = JSONObject().put("lastError", "Android could not start the VPN")
            render()
        }
    }

    private fun applyPreferences() {
        pendingPrefs = !VpnControl.send(service, VpnControl.APPLY_PREFS)
    }

    override fun showImport() {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(12), dp(20), dp(4))
        }
        box.add(button("Scan QR", primary = true).apply {
            setOnClickListener { importDialog?.dismiss(); scanQr() }
        }, MATCH, WRAP)
        box.add(button("From image").apply {
            setOnClickListener { importDialog?.dismiss(); importFromImage() }
        }, MATCH, WRAP, top = 8)
        box.add(button("Paste").apply {
            setOnClickListener { importDialog?.dismiss(); pasteImport() }
        }, MATCH, WRAP, top = 8)
        showImportDialog(AlertDialog.Builder(this)
            .setTitle("Add profile")
            .setView(box)
            .setNegativeButton("Cancel", null)
        )
    }

    override fun scanQr() {
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            launchScanner()
        } else {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), CAMERA_PERM)
        }
    }

    private fun launchScanner() {
        startActivityForResult(Intent(this, ScanActivity::class.java), SCAN_QR)
    }

    override fun importFromImage() {
        val pick = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "image/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        try {
            startActivityForResult(pick, PICK_IMAGE)
        } catch (_: Exception) {
            toast("No image picker available")
        }
    }

    override fun pasteImport() {
        val clip = getSystemService(ClipboardManager::class.java).primaryClip
        val raw = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null
        if (raw.isNullOrBlank()) toast("The clipboard has no Pipe link") else confirmImport(raw)
    }

    override fun currentProfileLink(): String? = model.profiles.current?.link

    private fun decodePickedImage(uri: Uri) {
        val app = applicationContext
        imageLoader.execute {
            val raw = decodeQrFromUri(app, uri)
            ui.post {
                if (!isFinishing && !isDestroyed) {
                    if (raw.isNotEmpty()) confirmImport(raw) else toast("No Pipe QR code found in that image")
                }
            }
        }
    }

    private fun confirmImport(link: String) {
        importDialog?.dismiss()
        val raw = link.trim()
        val summary = try {
            describe(raw)
        } catch (_: Exception) {
            toast("Invalid Pipe link")
            return
        }
        val name = summary.getString("name")
        val fingerprint = summary.getString("keyFingerprint")
        val saved = runCatching { profileStore.read() }
        val recovery = saved.isFailure
        val current = saved.getOrNull()?.current?.let { runCatching { describe(it.link) }.getOrNull() }
        fun endpoint(preview: JSONObject, key: String, fallback: String): String =
            preview.optString(key).ifEmpty { preview.optString(fallback).ifEmpty { "None" } }
        fun line(label: String, key: String, fallback: String = key): String {
            val incoming = endpoint(summary, key, fallback)
            val previous = current?.let { endpoint(it, key, fallback) }
            return if (previous != null && previous != incoming) "$label: $previous → $incoming" else "$label: $incoming"
        }
        val message = listOf(
            "Name: $name", line("Fast", "fastEndpoint", "domain"), line("Stealth", "stealthEndpoint", "domain"),
            line("Rescue CDN", "cdn"), line("HTTPS proxy", "proxyAuthority"), "", "Key fingerprint", fingerprint,
        ).joinToString("\n")
        val dialog = AlertDialog.Builder(this)
            .setTitle("Confirm profile import")
            .setMessage(if (recovery) "$message\n\nSaved profiles are unreadable. Replace them with this profile?" else message)
            .setNegativeButton("Cancel", null)
        if (recovery) {
            dialog.setPositiveButton("Replace") { _, _ -> saveImport(raw, replace = true, recover = true) }
        } else {
            dialog.setPositiveButton("Add") { _, _ -> saveImport(raw, replace = false) }
            if (saved.getOrThrow().current != null) {
                dialog.setNeutralButton("Replace") { _, _ -> saveImport(raw, replace = true) }
            }
        }
        showImportDialog(dialog, raw)
    }

    private fun showImportDialog(builder: AlertDialog.Builder, raw: String? = null) {
        importDialog?.dismiss()
        val dialog = builder.create()
        dialog.setOnDismissListener {
            if (importDialog === dialog) {
                importDialog = null
                pendingLink = null
            }
        }
        importDialog = dialog
        pendingLink = raw
        dialog.show()
    }

    private fun saveImport(raw: String, replace: Boolean, recover: Boolean = false) {
        pendingLink = null
        settings.hideSecret()
        try {
            val result = runCatching { profileStore.read() }
            if (recover && result.isFailure) {
                profileStore.replaceUnreadable(raw)
                dropConnection()
                refreshProfiles()
                return
            }
            val saved = result.getOrThrow()
            val entries = saved.entries.toMutableList()
            val selected = if (replace && saved.current != null) {
                if (saved.current?.link != raw) entries[saved.selected] = SavedProfile(raw)
                saved.selected
            } else {
                val existing = entries.indexOfFirst { it.link == raw }
                if (existing >= 0) existing else {
                    entries.add(SavedProfile(raw))
                    entries.lastIndex
                }
            }
            profileStore.save(Profiles(entries, selected))
            if (selected != saved.selected || saved.current?.link != raw) dropConnection()
            refreshProfiles()
        } catch (_: Exception) {
            toast("Could not save the encrypted profile")
        }
    }

    override fun chooseProfile() {
        if (model.profiles.entries.isEmpty()) {
            showImport()
            return
        }
        val labels = model.names.mapIndexed { i, n -> "$n · ${model.domains.getOrElse(i) { "" }}" }.toTypedArray()
        chooser?.dismiss()
        chooser = AlertDialog.Builder(this)
            .setTitle("Server profiles")
            .setSingleChoiceItems(labels, model.profiles.selected) { dialog, selected ->
                selectProfile(selected)
                dialog.dismiss()
            }
            .setNeutralButton("Import") { _, _ -> showImport() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun dropConnection() {
        if (model.connected || model.connecting || model.blocked) {
            startService(VpnControl.intent(this, VpnControl.DISCONNECT))
            toast("Disconnected. Tap the button to connect with this profile.")
        }
    }

    override fun selectProfile(index: Int) {
        if (index == model.profiles.selected) return
        settings.hideSecret()
        try {
            dropConnection()
            profileStore.save(model.profiles.copy(selected = index))
            refreshProfiles()
        } catch (_: Exception) {
            toast("Could not select the profile")
        }
    }

    override fun deleteProfile(index: Int) {
        settings.hideSecret()
        try {
            val entries = model.profiles.entries.toMutableList()
            if (index !in entries.indices) return
            if (index == model.profiles.selected) dropConnection()
            entries.removeAt(index)
            val selected = when {
                model.profiles.selected > index -> model.profiles.selected - 1
                else -> model.profiles.selected
            }.coerceIn(0, maxOf(0, entries.lastIndex))
            profileStore.save(Profiles(entries, selected))
            refreshProfiles()
        } catch (_: Exception) {
            toast("Could not delete the profile")
        }
    }

    override fun setRelay(index: Int, link: String, code: String, on: Boolean): String? {
        val cleanCode = code.trim()
        if (on && cleanCode.isEmpty()) return "Enter a relay IP, name or code"
        val error = Mobile.validateRelay(link, cleanCode)
        if (error.isNotEmpty()) return error
        val relay = ProfileRelay(cleanCode, on)
        try {
            val saved = profileStore.read()
            val profile = saved.current
            if (profile == null || saved.selected != index || profile.link != link) return "The selected profile changed"
            if (profile.relay != relay) {
                val entries = saved.entries.toMutableList()
                entries[index] = profile.copy(relay = relay)
                val updated = saved.copy(entries = entries)
                profileStore.save(updated)
                model.profiles = updated
                if (profile.relay.enabledCode != relay.enabledCode) applyPreferences()
                render()
            }
        } catch (_: Exception) {
            return "Could not save the relay"
        }
        return null
    }

    private fun refreshProfiles() {
        model.profiles = runCatching { profileStore.read() }.getOrDefault(Profiles())
        val summaries = model.profiles.entries.map { runCatching { describe(it.link) }.getOrNull() }
        model.names = summaries.map { it?.optString("name").orEmpty().ifEmpty { "Unavailable profile" } }
        model.domains = summaries.map { it?.optString("domain").orEmpty() }
        model.selectedName = model.names.getOrElse(model.profiles.selected) { "" }
        model.hasCdn = model.profiles.current?.let { runCatching { profileHasCdn(it.link) }.getOrDefault(false) } ?: false
        model.prefs = runCatching { VpnPreferences.read(this) }.getOrDefault(VpnPreferences()).withAvailableTier(model.hasCdn)
        render()
    }

    private fun render() {
        if (model.connected && model.status.has("rescueAvailable")) model.hasCdn = model.status.optBoolean("rescueAvailable")
        when (tab) {
            0 -> home.render(model)
            1 -> routing.render(model)
            3 -> settings.render(model)
        }
    }

    private fun describe(raw: String) = JSONObject(Mobile.parseLink(raw))

    private companion object {
        const val CONSENT = 100
        const val APPS = 101
        const val NOTIFICATIONS = 102
        const val SCAN_QR = 103
        const val PICK_IMAGE = 104
        const val CAMERA_PERM = 105
        const val LOGS_TAB = 2
        const val SETTINGS_TAB = 3
    }
}
