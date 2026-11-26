// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.Activity
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

internal class HomeView(private val a: Activity, private val act: Actions) {
    val root = ScrollView(a).apply { isFillViewport = true }
    private val power = PowerButton(a).apply { id = R.id.connect }
    private val status = a.text("Not connected", 26f, a.c(R.color.text), true).apply {
        id = R.id.status
        gravity = Gravity.CENTER
        accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
    }
    private val detail = a.text("", 14f, a.c(R.color.muted)).apply { id = R.id.detail; gravity = Gravity.CENTER }
    private val error = a.text("", 14f, a.c(R.color.danger)).apply {
        id = R.id.error
        setPadding(a.dp(12), a.dp(10), a.dp(12), a.dp(10))
        background = a.shape(a.c(R.color.danger_soft), 10)
        visibility = View.GONE
    }
    private val chip = a.tapRow().apply {
        id = R.id.server
        setPadding(a.dp(16), 0, a.dp(14), 0)
        background = a.pressable(a.c(R.color.surface2), 24)
    }
    private val chipName = a.text("No server imported", 15f, a.c(R.color.text), true).oneLine()
    private val routePill = a.pill("", a.c(R.color.primary), a.c(R.color.primary_soft))
    private val routeMs = a.text("", 24f, a.c(R.color.text), true)
    private val routeList = a.text("", 13f, a.c(R.color.muted))
    private val test = a.button("Test").apply { id = R.id.test }
    private val mode = Segmented(a, listOf("Smart", "Global", "Direct"), listOf(R.id.smart, R.id.global, R.id.direct)) {
        act.setMode(MODES[it])
    }
    private val modeHint = a.text("", 13f, a.c(R.color.muted))
    private val up = a.text("0 B/s", 20f, a.c(R.color.text), true)
    private val down = a.text("0 B/s", 20f, a.c(R.color.text), true)
    private val totals = a.text("", 13f, a.c(R.color.muted))
    private val empty = a.card()
    private val routeCard = a.card()
    private val trafficCard = a.card()

    init {
        val col = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(a.dp(16), a.dp(12), a.dp(16), a.dp(20))
        }
        root.addView(col, MATCH, WRAP)
        col.add(a.text("pipe", 24f, a.c(R.color.primary), true).apply { accessibilityHeading() })

        val hero = a.card().apply { gravity = Gravity.CENTER_HORIZONTAL }
        hero.add(power, WRAP, WRAP, top = 6).also { (it.layoutParams as LinearLayout.LayoutParams).gravity = Gravity.CENTER_HORIZONTAL }
        hero.add(status, MATCH, WRAP, top = 12)
        hero.add(detail, MATCH, WRAP, top = 2)
        hero.add(error, MATCH, WRAP, top = 12)
        chip.add(a.text("Profile", 12f, a.c(R.color.muted)), WRAP, WRAP)
        chip.add(chipName, 0, WRAP, start = 8, weight = 1f)
        chip.add(a.text("▾", 14f, a.c(R.color.muted)), WRAP, WRAP, start = 8)
        hero.add(chip, MATCH, a.dp(48), top = 14)
        col.add(hero, top = 12)

        empty.add(a.text("Add your server", 17f, a.c(R.color.text), true))
        empty.add(a.text("Scan a Pipe QR code, pick an image, or paste a link.", 14f, a.c(R.color.muted)), top = 4)
        empty.add(a.button("Scan QR", primary = true).apply {
            setOnClickListener { act.scanQr() }
        }, MATCH, WRAP, top = 12)
        val emptyRow = LinearLayout(a)
        emptyRow.add(a.button("From image").apply {
            setOnClickListener { act.importFromImage() }
        }, 0, WRAP, weight = 1f)
        emptyRow.add(a.button("Paste").apply {
            setOnClickListener { act.pasteImport() }
        }, 0, WRAP, start = 8, weight = 1f)
        empty.add(emptyRow, MATCH, WRAP, top = 8)
        col.add(empty, top = 12)

        routeCard.add(a.heading("Route"))
        val routeRow = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL }
        routeRow.add(routePill, WRAP, WRAP)
        routeRow.add(routeMs, 0, WRAP, start = 12, weight = 1f)
        routeRow.add(test, WRAP, WRAP)
        routeCard.add(routeRow, top = 8)
        routeCard.add(routeList, top = 4)
        col.add(routeCard, top = 12)

        val modeCard = a.card()
        modeCard.add(a.heading("Mode"))
        modeCard.add(mode, top = 10)
        modeCard.add(modeHint, top = 8)
        col.add(modeCard, top = 12)

        trafficCard.add(a.heading("Traffic"))
        val rates = LinearLayout(a)
        val upBox = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        upBox.add(a.text("↑ Upload", 12f, a.c(R.color.muted)))
        upBox.add(up)
        val downBox = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        downBox.add(a.text("↓ Download", 12f, a.c(R.color.muted)))
        downBox.add(down)
        rates.add(upBox, 0, WRAP, weight = 1f)
        rates.add(downBox, 0, WRAP, weight = 1f)
        trafficCard.add(rates, top = 8)
        trafficCard.add(totals, top = 8)
        col.add(trafficCard, top = 12)

        // These change every second. Keeping them out of the accessibility tree stops a
        // constant stream of change events, which would keep UI tools from ever seeing an idle screen.
        listOf(up, down, totals).forEach { it.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO }
        power.setOnClickListener { act.toggleConnect() }
        chip.setOnClickListener { act.chooseProfile() }
        test.setOnClickListener { act.testRoutes() }
    }

    private fun TextView.accessibilityHeading() {
        if (android.os.Build.VERSION.SDK_INT >= 28) isAccessibilityHeading = true
    }

    fun render(m: Model) {
        val s = m.status
        val tier = s.optString("tier")
        val noProfile = m.profiles.current == null
        val message = s.optString("lastError")
        power.state = when {
            m.connecting && !m.connected -> PowerButton.State.CONNECTING
            m.connected || m.blocked -> PowerButton.State.ON
            else -> PowerButton.State.OFF
        }
        power.isEnabled = !m.connecting || m.connected || m.blocked
        status.text = when {
            m.connected -> "Connected"
            m.blocked -> "Traffic blocked"
            m.connecting -> "Connecting…"
            else -> "Not connected"
        }
        status.setTextColor(a.c(if (m.connected) R.color.connected else R.color.text))
        val ms = if (s.isNull("latencyMs")) null else s.optLong("latencyMs")
        val relay = s.optString("relay").takeIf { it.isNotEmpty() }?.let { host ->
            when (s.optString("relayState")) {
                "via" -> "via $host"
                "direct" -> "relay not reachable, direct"
                else -> null
            }
        }
        detail.text = when {
            m.connected -> listOfNotNull(
                s.optString("server").ifEmpty { m.selectedName }.ifEmpty { null },
                routeName(tier).ifEmpty { null },
                ms?.let { "$it ms" },
                relay,
            ).joinToString(" · ")
            m.connecting -> "Setting up the tunnel"
            m.blocked -> "Tap the button to disconnect"
            noProfile -> "Add a server to get started"
            else -> "Tap the button to connect"
        }
        error.visibility = if (message.isNotEmpty()) View.VISIBLE else View.GONE
        error.text = message
        chipName.text = m.selectedName.ifEmpty { "No server imported" }
        empty.visibility = if (noProfile) View.VISIBLE else View.GONE

        val directMode = m.prefs.mode == "direct"
        mode.select(MODES.indexOf(m.prefs.mode))
        modeHint.text = MODE_HINTS[m.prefs.mode]
        renderRoute(m, directMode, tier, ms)

        up.text = formatRate(s.optLong("upBytesPerSecond"))
        down.text = formatRate(s.optLong("downBytesPerSecond"))
        totals.text = if (m.connected) {
            val since = formatSince(s.optLong("connectedSince"))
            "Sent ${formatBytes(s.optLong("upBytes"))} · Received ${formatBytes(s.optLong("downBytes"))}" +
                if (since.isNotEmpty()) " · Connected for $since" else ""
        } else {
            "Traffic appears here once you connect"
        }
    }

    private fun renderRoute(m: Model, directMode: Boolean, tier: String, ms: Long?) {
        val routes = m.status.optJSONObject("routes")
        if (!m.connected || directMode) {
            routePill.visibility = View.GONE
            routeMs.text = if (directMode) "Not used" else "—"
            routeList.text = if (directMode) "Direct mode sends traffic straight out, so there is no route to test."
            else "Connect to see which route pipe is using."
            test.isEnabled = false
            test.text = "Test"
            return
        }
        routePill.visibility = View.VISIBLE
        routePill.text = routeName(tier)
        routeMs.text = ms?.let { "$it ms" } ?: "—"
        val parts = ROUTES.mapNotNull { name ->
            val item = routes?.optJSONObject(name) ?: return@mapNotNull null
            val result = when {
                !item.optBoolean("ok") -> "No reply"
                item.optLong("ms") == 0L -> "Reachable"
                else -> "${item.optLong("ms")} ms"
            }
            "${routeName(name)} $result" + if (item.optString("via") == "relay") " via relay" else ""
        }
        routeList.text = if (parts.isEmpty()) "Tap Test to check every route." else parts.joinToString(" · ")
        test.isEnabled = !m.testing
        test.text = if (m.testing) "Testing…" else "Test"
    }

    companion object {
        val MODES = listOf("smart", "global", "direct")
        val ROUTES = listOf("fast", "stealth", "rescue")
        val MODE_HINTS = mapOf(
            "smart" to "China and local sites go direct. Everything else goes through pipe.",
            "global" to "Everything goes through pipe.",
            "direct" to "pipe is not used. Your traffic goes out as usual.",
        )
    }
}
