// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import android.view.View
import android.view.WindowInsets

internal object VpnControl {
    const val CONNECT = "io.pipe.app.CONNECT"
    const val DISCONNECT = "io.pipe.app.DISCONNECT"
    const val BIND = "io.pipe.app.BIND_VPN_UI"
    const val SUBSCRIBE = 1
    const val UNSUBSCRIBE = 2
    const val STATUS = 3
    const val APPLY_PREFS = 4
    const val LOGS_REQUEST = 5
    const val LOGS = 6
    const val CLEAR_LOGS = 7
    const val TEST_ROUTES = 8
    const val TEST_DONE = 9
    const val UPDATE_POLL = 10
    const val UPDATE_CHECK = 11
    const val UPDATE_DOWNLOAD = 12
    const val UPDATE_STATUS = 13
    const val UPDATE_INSTALL = 14
    const val UPDATE_INSTALL_ERROR = 15
    const val UPDATE_VIA_TUNNEL = 1
    const val UPDATE_AUTOMATIC = 2
    const val STATUS_JSON = "status"
    const val PAYLOAD = "payload"
    const val AFTER = "after"

    fun intent(context: Context, action: String) =
        Intent(context, PipeVpnService::class.java).setAction(action)

    fun send(
        receiver: Messenger?, what: Int, reply: Messenger? = null, status: String? = null,
        payload: String? = null, after: Long = 0, flags: Int = 0,
    ): Boolean {
        if (receiver == null) return false
        return try {
            receiver.send(Message.obtain(null, what).apply {
                replyTo = reply
                arg1 = flags
                if (status != null || payload != null || after != 0L) {
                    data = Bundle().apply {
                        if (status != null) putString(STATUS_JSON, status)
                        if (payload != null) putString(PAYLOAD, payload)
                        putLong(AFTER, after)
                    }
                }
            })
            true
        } catch (_: RemoteException) {
            false
        }
    }
}

internal fun View.padForSystemBars() {
    val left = paddingLeft
    val top = paddingTop
    val right = paddingRight
    val bottom = paddingBottom
    setOnApplyWindowInsetsListener { view, insets ->
        if (Build.VERSION.SDK_INT >= 30) {
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
            view.setPadding(left + bars.left, top + bars.top, right + bars.right, bottom + bars.bottom)
        } else {
            @Suppress("DEPRECATION")
            view.setPadding(
                left + insets.systemWindowInsetLeft, top + insets.systemWindowInsetTop,
                right + insets.systemWindowInsetRight, bottom + insets.systemWindowInsetBottom,
            )
        }
        insets
    }
    requestApplyInsets()
}
