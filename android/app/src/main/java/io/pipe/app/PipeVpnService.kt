// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Messenger
import android.os.Process
import android.service.quicksettings.TileService
import android.content.ComponentName
import mobile.Mobile
import mobile.Platform
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

class PipeVpnService : VpnService(), Platform {
    private val main = Handler(Looper.getMainLooper())
    private lateinit var connectivity: ConnectivityManager
    private val subscribers = LinkedHashSet<Messenger>()
    private var latestStatus = JSONObject().put("running", false)
    private var foreground = false
    @Volatile private var latestStart = 0
    @Volatile private var running = false
    @Volatile private var destroyed = false
    @Volatile private var sessionGeneration = 0L
    @Volatile private var networkState = "{}"
    private var hasCdn = false
    private var applied: VpnPreferences? = null
    private var appliedProfileLink: String? = null
    private var networkCallback: DefaultNetworkCallback? = null

    private val messenger = Messenger(Handler(Looper.getMainLooper()) { message ->
        if (message.sendingUid != Process.myUid()) return@Handler true
        val reply = message.replyTo
        when (message.what) {
            VpnControl.SUBSCRIBE -> if (reply != null) {
                if (VpnControl.send(reply, VpnControl.STATUS, status = latestStatus.toString())) {
                    subscribers.add(reply)
                }
            }
            VpnControl.UNSUBSCRIBE -> subscribers.remove(reply)
            VpnControl.LOGS_REQUEST -> if (reply != null) {
                val after = message.data.getLong(VpnControl.AFTER)
                aux.execute {
                    val json = runCatching { Mobile.logs(after) }.getOrDefault("""{"next":$after,"entries":[]}""")
                    VpnControl.send(reply, VpnControl.LOGS, payload = json)
                }
            }
            VpnControl.CLEAR_LOGS -> aux.execute { runCatching { Mobile.clearLogs() } }
            VpnControl.TEST_ROUTES -> {
                val generation = sessionGeneration
                probeRoutes(generation) { if (reply != null) VpnControl.send(reply, VpnControl.TEST_DONE) }
            }
            VpnControl.APPLY_PREFS -> {
                val startId = latestStart
                worker.execute { if (startId == latestStart && !destroyed) applyPreferences(startId) }
            }
        }
        true
    })

    private inner class DefaultNetworkCallback(
        private val generation: Long,
        initialPhysical: Network?,
        snapshot: AndroidNetworkSnapshot,
    ) : ConnectivityManager.NetworkCallback() {
        private val changes = DefaultNetworkChanges(initialPhysical?.networkHandle, snapshot)
        private var properties: LinkProperties? = null

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            onWorker {
                val handle = network.networkHandle
                val sameNetwork = changes.physical == handle
                val isVpn = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                if (!changes.onCapabilities(handle, isVpn)) return@onWorker
                if (!sameNetwork) {
                    properties = null
                } else {
                    properties?.let { update(network, it) }
                }
            }
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            onWorker {
                if (network.networkHandle == changes.physical) {
                    properties = linkProperties
                    update(network, linkProperties)
                }
            }
        }

        override fun onLost(network: Network) {
            onWorker {
                if (changes.onLost(network.networkHandle)) {
                    properties = null
                    update(null, null)
                }
            }
        }

        private fun update(network: Network?, linkProperties: LinkProperties?) {
            val snapshot = connectivity.networkSnapshot(network, linkProperties)
            val reset = changes.update(snapshot) ?: return
            networkState = snapshot.json
            if (reset) Mobile.networkChanged() else Mobile.refreshNetwork()
            // A rebuild for the new network that failed, rollback included,
            // leaves no session: stop the service instead of showing Connected.
            if (!JSONObject(Mobile.status()).optBoolean("running")) {
                val startId = latestStart
                stopVPN(generation)
                publishStopped("Pipe stopped: it could not restart on the new network", startId)
                stopServiceStart(startId)
            }
        }

        private fun onWorker(update: () -> Unit) {
            worker.execute { if (!destroyed && ownsSession(generation)) update() }
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivity = getSystemService(ConnectivityManager::class.java)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Pipe VPN", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onBind(intent: Intent): IBinder? {
        if (intent.action != VpnControl.BIND) return super.onBind(intent)
        return if (Binder.getCallingUid() == Process.myUid()) messenger.binder else null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStart = startId
        val action = intent?.action ?: VpnControl.CONNECT
        if (action != VpnControl.DISCONNECT && !foreground) {
            try {
                val notification = notification("Connecting")
                if (Build.VERSION.SDK_INT >= 34) {
                    startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
                } else {
                    startForeground(NOTIFICATION_ID, notification)
                }
                foreground = true
            } catch (_: Exception) {
                publishStopped("Android could not start the VPN service", startId)
                stopSelf(startId)
                return START_NOT_STICKY
            }
        }
        worker.execute {
            if (destroyed || startId != latestStart) return@execute
            if (action == VpnControl.DISCONNECT) {
                disconnect(startId, sessionGeneration)
            } else if (!running) {
                connect(startId)
            }
        }
        return if (action == VpnControl.DISCONNECT) START_NOT_STICKY else START_STICKY
    }

    private fun connect(startId: Int) {
        try {
            val profile = ProfileStore(this).read().current
                ?: throw IllegalStateException("Import a server profile first")
            hasCdn = profileHasCdn(profile.link)
            val prefs = VpnPreferences.read(this).withAvailableTier(hasCdn)
            startVPN(profile.link, prefs.copy(relay = profile.relay.enabledCode))
        } catch (error: Exception) {
            stopVPN(sessionGeneration)
            val message = (error as? IllegalStateException)?.message ?: "VPN could not start"
            publishStopped(message, startId)
            stopServiceStart(startId)
        }
    }

    private fun startVPN(profile: String, prefs: VpnPreferences) {
        check(prepare(this) == null) { "Android VPN consent is required" }
        if (destroyed) return
        activeService?.let { previous -> previous.stopVPN(previous.sessionGeneration) }
        val generation = ++nextGeneration
        sessionGeneration = generation
        activeService = this
        val physical = connectivity.activeNetwork?.takeIf {
            connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false
        }
        val snapshot = connectivity.networkSnapshot(physical)
        networkState = snapshot.json
        Mobile.start(profile, prefs.forEngine(this), this)
        if (destroyed) {
            stopVPN(generation)
            return
        }
        applied = prefs
        appliedProfileLink = profile
        running = true
        val callback = DefaultNetworkCallback(generation, physical, snapshot)
        connectivity.registerDefaultNetworkCallback(callback, main)
        networkCallback = callback
        publish(Mobile.status())
    }

    // Mobile.testRoutes blocks for up to 12 seconds, so it runs on its own
    // single thread (requests queue up) and never on the main or worker threads.
    private fun probeRoutes(generation: Long, done: () -> Unit) {
        prober.execute {
            try {
                if (ownsSession(generation) && running) Mobile.testRoutes()
            } catch (_: Exception) {
                // Latency is optional.
            }
            done()
        }
    }

    private fun applyPreferences(startId: Int) {
        var current = applied ?: return
        val generation = sessionGeneration
        if (!ownsSession(generation)) return
        try {
            val profile = ProfileStore(this).read().current
            val relay = profile?.takeIf { it.link == appliedProfileLink }?.relay?.enabledCode ?: current.relay
            val next = VpnPreferences.read(this).withAvailableTier(hasCdn).copy(relay = relay)
            if (next.ipv6 != current.ipv6 || next.perApp != current.perApp || next.packages != current.packages ||
                next.rules != current.rules || next.logLevel != current.logLevel || next.relay != current.relay
            ) {
                val routing = next.copy(tier = current.tier)
                Mobile.applyPreferences(routing.forEngine(this))
                current = routing
                applied = current
            } else if (next.mode != current.mode) {
                Mobile.setMode(next.mode)
                current = current.copy(mode = next.mode)
                applied = current
            }
            if (next.tier != current.tier) {
                Mobile.setTier(next.tier)
                applied = current.copy(tier = next.tier)
            }
            publish(Mobile.status())
        } catch (_: Exception) {
            val status = JSONObject(Mobile.status())
            if (status.optBoolean("running")) {
                publish(status.put("lastError", "Could not apply VPN settings").toString())
            } else {
                stopVPN(generation)
                publishStopped("Could not apply VPN settings", startId)
                stopServiceStart(startId)
            }
        }
    }

    override fun openTun(optionsJSON: String): Int {
        check(!destroyed)
        val options = JSONObject(optionsJSON)
        val builder = Builder()
            .setSession("Pipe")
            .setMtu(options.getInt("mtu"))
            .setBlocking(false)
            .setConfigureIntent(openActivity())
        options.getJSONArray("addresses").strings().forEach { value ->
            builder.addAddress(value.substringBeforeLast('/'), value.substringAfterLast('/').toInt())
        }
        options.getJSONArray("routes").strings().forEach { value ->
            builder.addRoute(value.substringBeforeLast('/'), value.substringAfterLast('/').toInt())
        }
        options.getJSONArray("dns").strings().forEach { builder.addDnsServer(it) }
        val selected = options.optJSONArray("packages")?.strings().orEmpty().toSet() - packageName
        if (options.getString("perApp") == "only") {
            var allowed = 0
            for (app in selected) {
                try {
                    builder.addAllowedApplication(app)
                    allowed++
                } catch (_: PackageManager.NameNotFoundException) {
                    // A saved app may have been uninstalled.
                }
            }
            check(allowed > 0) { "No selected apps are installed" }
        } else {
            builder.addDisallowedApplication(packageName)
            if (options.getString("perApp") == "bypass") {
                for (app in selected) {
                    try {
                        builder.addDisallowedApplication(app)
                    } catch (_: PackageManager.NameNotFoundException) {
                        // A saved app may have been uninstalled.
                    }
                }
            }
        }
        return builder.establish()?.detachFd() ?: error("Android could not establish the VPN")
    }

    override fun protect(fd: Int): Boolean = super.protect(fd)

    override fun networkState(): String = networkState

    override fun onStatus(statusJSON: String) {
        if (running && !destroyed) publish(statusJSON)
    }

    override fun onRevoke() {
        val startId = latestStart
        val generation = sessionGeneration
        worker.execute {
            if (!destroyed && ownsSession(generation)) disconnect(startId, generation)
        }
    }

    override fun onDestroy() {
        destroyed = true
        val generation = sessionGeneration
        worker.execute { stopVPN(generation) }
        super.onDestroy()
    }

    private fun ownsSession(generation: Long): Boolean =
        generation != 0L && generation == sessionGeneration && activeService === this

    private fun stopVPN(generation: Long) {
        if (!ownsSession(generation)) return
        running = false
        networkCallback?.let { callback ->
            runCatching { connectivity.unregisterNetworkCallback(callback) }
        }
        networkCallback = null
        Mobile.stop()
        activeService = null
        sessionGeneration = 0
        networkState = "{}"
        applied = null
        appliedProfileLink = null
    }

    private fun disconnect(startId: Int, generation: Long) {
        stopVPN(generation)
        publishStopped("", startId)
        stopServiceStart(startId)
    }

    private fun stopServiceStart(startId: Int) {
        main.post {
            if (!destroyed && startId == latestStart) {
                if (foreground) stopForeground(STOP_FOREGROUND_REMOVE)
                foreground = false
                stopSelf(startId)
            }
        }
    }

    private fun publishStopped(error: String, startId: Int) {
        publish(JSONObject().put("running", false).put("lastError", error).toString(), startId)
    }

    private fun publish(json: String, startId: Int? = null) {
        val generation = sessionGeneration
        main.post {
            if (destroyed || generation != sessionGeneration || (startId != null && startId != latestStart)) return@post
            val status = JSONObject(json)
            if (status.optBoolean("running") && !running) return@post
            val changed = latestStatus.optBoolean("running") != status.optBoolean("running")
            val tier = status.optString("tier")
            val tierChanged = latestStatus.optString("tier") != tier
            latestStatus = status
            if (changed) TileService.requestListeningState(this, ComponentName(this, PipeTileService::class.java))
            if (foreground && status.optBoolean("running") && (changed || tierChanged)) {
                getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification("Connected · $tier"))
            }
            val iterator = subscribers.iterator()
            while (iterator.hasNext()) {
                if (!VpnControl.send(iterator.next(), VpnControl.STATUS, status = json)) iterator.remove()
            }
        }
    }

    private fun openActivity(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    private fun notification(text: String): Notification {
        val disconnect = PendingIntent.getService(
            this, 1, VpnControl.intent(this, VpnControl.DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_pipe)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(openActivity())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", disconnect).build())
            .build()
    }

    private fun JSONArray.strings(): List<String> = List(length()) { getString(it) }

    private companion object {
        const val CHANNEL = "pipe-vpn"
        const val NOTIFICATION_ID = 1
        // The Go tunnel is process-wide, including across service recreation.
        val worker = Executors.newSingleThreadExecutor { task -> Thread(task, "Pipe VPN") }
        val aux = Executors.newSingleThreadExecutor { task -> Thread(task, "Pipe logs").apply { isDaemon = true } }
        val prober = Executors.newSingleThreadExecutor { task -> Thread(task, "Pipe probe").apply { isDaemon = true } }
        var nextGeneration = 0L
        var activeService: PipeVpnService? = null
    }
}
