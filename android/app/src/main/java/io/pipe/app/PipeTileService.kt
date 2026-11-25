// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Messenger
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.json.JSONObject

class PipeTileService : TileService() {
    private var bound = false
    private var running = false
    private var service: Messenger? = null
    private val listener = Messenger(Handler(Looper.getMainLooper()) { message ->
        if (message.what == VpnControl.STATUS) {
            val running = message.data.getString(VpnControl.STATUS_JSON)?.let {
                JSONObject(it).optBoolean("running")
            } ?: false
            render(running)
        }
        true
    })
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = Messenger(binder)
            VpnControl.send(service, VpnControl.SUBSCRIBE, listener)
        }

        override fun onServiceDisconnected(name: ComponentName) {
            service = null
            render(false)
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        bound = bindService(VpnControl.intent(this, VpnControl.BIND), connection, Context.BIND_AUTO_CREATE)
    }

    override fun onStopListening() {
        if (bound) {
            VpnControl.send(service, VpnControl.UNSUBSCRIBE, listener)
            unbindService(connection)
            bound = false
        }
        service = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }

    private fun toggle() {
        if (VpnService.prepare(this) != null) {
            openApp()
            return
        }
        try {
            if (running) {
                startService(VpnControl.intent(this, VpnControl.DISCONNECT))
            } else {
                startForegroundService(VpnControl.intent(this, VpnControl.CONNECT))
            }
        } catch (_: Exception) {
            openApp()
        }
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun render(running: Boolean) {
        this.running = running
        qsTile?.apply {
            state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= 29) subtitle = if (running) "Connected" else "Disconnected"
            updateTile()
        }
    }
}
