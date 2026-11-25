// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.Activity
import android.app.AlertDialog
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import mobile.Mobile
import android.widget.TextView

internal class RoutingView(private val a: Activity, private val act: Actions) {
    val root = ScrollView(a)
    private class Tile(val box: LinearLayout, val title: TextView, val badge: TextView, val note: TextView) {
        var look = ""
    }

    private val modeTiles = HomeView.MODES.associateWith { tile(it, MODE_TITLES.getValue(it), HomeView.MODE_HINTS.getValue(it)) }
    private val tierTiles = TIERS.associateWith { tile(it, TIER_TITLES.getValue(it), TIER_HINTS.getValue(it)) }
    private val rulesBox = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
    private val paused = a.text("Rules are paused in Direct mode.", 13f, a.c(R.color.warn)).apply {
        setPadding(a.dp(12), a.dp(8), a.dp(12), a.dp(8))
        background = a.shape(a.c(R.color.warn_soft), 10)
    }
    private val noRules = a.text("No rules yet. Rules are checked top to bottom before the mode. Local network addresses always go direct.", 13f, a.c(R.color.muted))
    private var shownRules: List<Rule>? = null
    private var rules: List<Rule> = emptyList()
    private var addDialog: AlertDialog? = null

    init {
        val col = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(a.dp(16), a.dp(12), a.dp(16), a.dp(20))
        }
        root.addView(col, MATCH, WRAP)
        col.add(a.text("Routing", 24f, a.c(R.color.text), true))
        col.add(a.text("Rules first, then the mode, then the route.", 14f, a.c(R.color.muted)), top = 2)

        col.add(a.heading("Mode"), top = 16)
        modeTiles.forEach { (mode, tile) ->
            tile.box.id = when (mode) {
                "smart" -> R.id.mode_smart
                "global" -> R.id.mode_global
                else -> R.id.mode_direct
            }
            tile.box.setOnClickListener { act.setMode(mode) }
            col.add(tile.box, top = 8)
        }

        col.add(a.heading("Route"), top = 20)
        tierTiles.forEach { (tier, tile) ->
            tile.box.id = when (tier) {
                "auto" -> R.id.tier_auto
                "fast" -> R.id.tier_fast
                "stealth" -> R.id.tier_stealth
                else -> R.id.tier_rescue
            }
            tile.box.setOnClickListener { act.setTier(tier) }
            col.add(tile.box, top = 8)
        }

        val head = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL }
        head.add(a.heading("Rules"), 0, WRAP, weight = 1f)
        head.add(a.button("Add rule", primary = true).apply {
            id = R.id.add_rule
            setOnClickListener { addDialog() }
        }, WRAP, WRAP)
        col.add(head, top = 20)
        col.add(paused, top = 8)
        col.add(rulesBox, top = 8)
    }

    private fun tile(key: String, title: String, hint: String): Tile {
        val box = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(a.dp(16), a.dp(12), a.dp(16), a.dp(12))
            minimumHeight = a.dp(56)
            isClickable = true
            isFocusable = true
        }
        val top = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL }
        val name = a.text(title, 16f, a.c(R.color.text), true)
        val badge = a.pill("", a.c(R.color.primary), a.c(R.color.primary_soft))
        top.add(name, 0, WRAP, weight = 1f)
        top.add(badge, WRAP, WRAP)
        box.add(top)
        val note = a.text(hint, 13f, a.c(R.color.muted))
        box.add(note, top = 2)
        box.contentDescription = null
        return Tile(box, name, badge, note)
    }

    private fun style(tile: Tile, selected: Boolean, enabled: Boolean) {
        val look = "$selected/$enabled"
        if (tile.look == look) return
        tile.look = look
        tile.box.isEnabled = enabled
        tile.box.isSelected = selected
        tile.box.alpha = if (enabled) 1f else 0.5f
        tile.box.background = a.pressable(
            a.c(if (selected) R.color.primary_soft else R.color.surface), 14,
            a.c(if (selected) R.color.primary else R.color.border),
        )
    }

    fun render(m: Model) {
        val direct = m.prefs.mode == "direct"
        modeTiles.forEach { (mode, tile) -> style(tile, mode == m.prefs.mode, true); if (tile.badge.visibility != View.GONE) tile.badge.visibility = View.GONE }
        val routes = m.status.optJSONObject("routes")
        val active = m.status.optString("tier")
        tierTiles.forEach { (tier, tile) ->
            val enabled = tier != "rescue" || m.hasCdn
            style(tile, tier == m.prefs.tier && enabled, enabled)
            tile.note.text = if (enabled) TIER_HINTS.getValue(tier) else "Not in this profile. Your server link has no Cloudflare route."
            val item = routes?.optJSONObject(tier)
            val label = when {
                tier == "auto" && m.connected && !direct -> "Using ${routeName(active)}"
                item == null || !m.connected -> if (tier == "auto") "Recommended" else ""
                item.optBoolean("ok") -> "${item.optLong("ms")} ms"
                else -> "No answer"
            }
            tile.badge.text = label
            val want = if (label.isEmpty()) View.GONE else View.VISIBLE
            if (tile.badge.visibility != want) tile.badge.visibility = want
        }
        val pausedWant = if (direct) View.VISIBLE else View.GONE
        if (paused.visibility != pausedWant) paused.visibility = pausedWant
        if (rules != m.prefs.rules || shownRules == null) {
            rules = m.prefs.rules
            drawRules()
        }
    }

    private fun drawRules() {
        shownRules = rules
        rulesBox.removeAllViews()
        if (rules.isEmpty()) {
            rulesBox.add(noRules)
            return
        }
        val list = a.card().apply { setPadding(a.dp(4), a.dp(4), a.dp(4), a.dp(4)) }
        rules.forEachIndexed { index, rule -> list.add(row(index, rule)) }
        rulesBox.add(list)
    }

    private fun row(index: Int, rule: Rule): View {
        val row = LinearLayout(a).apply {
            gravity = Gravity.CENTER_VERTICAL
            setPadding(a.dp(12), a.dp(2), a.dp(0), a.dp(2))
            minimumHeight = a.dp(56)
        }
        val words = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
        words.add(a.text(rule.value, 15f, a.c(R.color.text), true).apply {
            maxLines = 2
            ellipsize = android.text.TextUtils.TruncateAt.MIDDLE
        })
        val color = when (rule.action) {
            "block" -> R.color.danger
            "direct" -> R.color.connected
            else -> R.color.primary
        }
        val type = TYPE_NAMES[rule.type] ?: rule.type
        words.add(a.text("$type · ${rule.action.replaceFirstChar { it.uppercase() }}", 12f, a.c(color), true))
        row.add(words, 0, WRAP, weight = 1f)
        row.add(iconButton("↑", "Move rule ${index + 1} up", index > 0) { move(index, -1) }, a.dp(44), a.dp(48))
        row.add(iconButton("↓", "Move rule ${index + 1} down", index < rules.lastIndex) { move(index, 1) }, a.dp(44), a.dp(48))
        row.add(iconButton("×", "Delete rule ${index + 1}", true) {
            act.setRules(rules.filterIndexed { i, _ -> i != index })
        }, a.dp(44), a.dp(48))
        return row
    }

    private fun iconButton(glyph: String, description: String, enabled: Boolean, click: () -> Unit): TextView =
        a.text(glyph, 20f, a.c(R.color.muted), true).apply {
            gravity = Gravity.CENTER
            contentDescription = description
            isEnabled = enabled
            alpha = if (enabled) 1f else 0.3f
            isClickable = true
            background = a.pressable(0, 12)
            setOnClickListener { click() }
        }

    private fun move(index: Int, by: Int) {
        val next = rules.toMutableList()
        next.add(index + by, next.removeAt(index))
        act.setRules(next)
    }

    private fun addDialog() {
        val form = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(a.dp(20), a.dp(8), a.dp(20), 0)
        }
        val type = Spinner(a).apply {
            adapter = ArrayAdapter(a, android.R.layout.simple_spinner_dropdown_item, TYPE_NAMES.values.toList())
        }
        val value = EditText(a).apply {
            hint = "example.com"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine()
            setTextColor(a.c(R.color.text))
            setHintTextColor(a.c(R.color.muted))
            minHeight = a.dp(48)
        }
        val action = Spinner(a).apply {
            adapter = ArrayAdapter(a, android.R.layout.simple_spinner_dropdown_item, listOf("Proxy", "Direct", "Block"))
        }
        val problem = a.text("", 13f, a.c(R.color.danger))
        form.add(a.text("Match", 12f, a.c(R.color.muted)))
        form.add(type, MATCH, a.dp(48))
        form.add(value, MATCH, WRAP, top = 4)
        form.add(a.text("Then", 12f, a.c(R.color.muted)), top = 8)
        form.add(action, MATCH, a.dp(48))
        form.add(problem, top = 4)
        addDialog?.dismiss()
        val dialog = AlertDialog.Builder(a)
            .setTitle("Add a rule")
            .setView(form)
            .setPositiveButton("Add", null)
            .setNegativeButton("Cancel", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val kind = TYPE_NAMES.keys.toList()[type.selectedItemPosition]
                val clean = cleanRule(kind, value.text.toString())
                if (clean == null) {
                    problem.text = RULE_HELP.getValue(kind)
                } else {
                    val verdict = listOf("proxy", "direct", "block")[action.selectedItemPosition]
                    val error = if (rules.size >= MAX_RULES) "You can have at most $MAX_RULES rules."
                    else Mobile.validateRule(kind, clean, verdict)
                    if (error.isEmpty()) {
                        act.setRules(rules + Rule(kind, clean, verdict))
                        dialog.dismiss()
                    } else {
                        problem.text = error
                    }
                }
            }
        }
        addDialog = dialog
        dialog.show()
    }

    fun dismiss() {
        addDialog?.dismiss()
        addDialog = null
    }

    companion object {
        const val MAX_RULES = 500
        val TIERS = listOf("auto", "fast", "stealth", "rescue")
        val MODE_TITLES = mapOf("smart" to "Smart", "global" to "Global", "direct" to "Direct")
        val TIER_TITLES = mapOf("auto" to "Auto", "fast" to "Fast", "stealth" to "Stealth", "rescue" to "Rescue")
        val TIER_HINTS = mapOf(
            "auto" to "Recommended. Starts with Fast and switches to Stealth or Rescue if needed.",
            "fast" to "The quickest. Uses UDP (Hysteria2).",
            "stealth" to "Looks like a normal website. Uses TCP (REALITY).",
            "rescue" to "Goes through Cloudflare. Works when the others are blocked.",
        )
        val TYPE_NAMES = linkedMapOf("domain" to "Domain", "suffix" to "Domain suffix", "keyword" to "Keyword", "ip" to "IP address or range")
        private val RULE_HELP = mapOf(
            "domain" to "Enter one domain, like example.com.",
            "suffix" to "Enter a domain ending, like example.com.",
            "keyword" to "Enter a word without spaces.",
            "ip" to "Enter an IP address or range, like 203.0.113.0/24.",
        )
        private val NAME = Regex("[A-Za-z0-9._-]+")
        private val V4 = Regex("\\d{1,3}(\\.\\d{1,3}){3}")
        private val V6 = Regex("[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")

        /** Returns the cleaned value, or null when it can't be a rule of this type. */
        fun cleanRule(kind: String, raw: String): String? {
            val text = raw.trim().lowercase()
            if (text.isEmpty() || text.length > 253) return null
            return when (kind) {
                "domain" -> text.takeIf { NAME.matches(it) && !V4.matches(it) && '.' in it }
                "suffix" -> text.trimStart('.').takeIf { NAME.matches(it) && !V4.matches(it) }
                "keyword" -> text.takeIf { NAME.matches(it) }
                else -> {
                    val address = text.substringBefore('/')
                    val prefix = if ('/' in text) text.substringAfter('/').toIntOrNull() else 0
                    val v4 = V4.matches(address) && address.split('.').all { it.toInt() in 0..255 }
                    val v6 = V6.matches(address) && address.count { it == ':' } in 2..7
                    text.takeIf { prefix != null && prefix in 0..(if (v6) 128 else 32) && (v4 || v6) }
                }
            }
        }
    }
}
