// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.graphics.Typeface
import android.text.Editable
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.TextWatcher
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.AbsListView
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import org.json.JSONObject

internal class LogsView(private val a: Activity, private val act: Actions) {
    private class Entry(val seq: Long, val time: String, val level: String, val source: String, val message: String)

    val root = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL }
    private val all = ArrayList<Entry>()
    private var shown: List<Entry> = emptyList()
    private var cursor = 0L
    private var lastSeq = 0L
    private var level = 1
    private var query = ""
    var paused = false
        private set
    private val adapter = LogAdapter()
    private val list = ListView(a)
    private val empty = a.text("", 14f, a.c(R.color.muted)).apply { gravity = Gravity.CENTER }
    private val pause = a.button("Pause")
    private val filter: Segmented = Segmented(a, listOf("Errors", "Warnings", "Info", "All"), listOf(0, 0, 0, 0).map { View.generateViewId() }) {
        level = it
        filter.select(it)
        refilter(true)
    }

    init {
        root.setPadding(a.dp(16), a.dp(12), a.dp(16), 0)
        root.add(a.text("Logs", 24f, a.c(R.color.text), true))
        root.add(filter, top = 10)
        filter.select(level)
        val search = EditText(a).apply {
            hint = "Search logs"
            setSingleLine()
            imeOptions = EditorInfo.IME_ACTION_DONE
            setTextColor(a.c(R.color.text))
            setHintTextColor(a.c(R.color.muted))
            textSize = 14f
            minHeight = a.dp(48)
            setPadding(a.dp(14), 0, a.dp(14), 0)
            background = a.shape(a.c(R.color.surface), 12, a.c(R.color.border))
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    query = s.toString().trim()
                    refilter(true)
                }
                override fun afterTextChanged(s: Editable?) = Unit
            })
        }
        root.add(search, top = 8)
        val bar = LinearLayout(a)
        pause.setOnClickListener {
            paused = !paused
            pause.text = if (paused) "Resume" else "Pause"
            if (!paused) act.fetchLogs(cursor)
        }
        val copy = a.button("Copy").apply { setOnClickListener { copyAll() } }
        val clear = a.button("Clear").apply {
            setOnClickListener {
                all.clear()
                act.clearLogs()
                refilter(false)
            }
        }
        bar.add(pause, 0, WRAP, weight = 1f)
        bar.add(copy, 0, WRAP, start = 8, weight = 1f)
        bar.add(clear, 0, WRAP, start = 8, weight = 1f)
        root.add(bar, top = 6)

        val frame = android.widget.FrameLayout(a).apply {
            background = a.shape(a.c(R.color.surface), 14, a.c(R.color.border))
        }
        list.adapter = adapter
        list.divider = null
        list.transcriptMode = AbsListView.TRANSCRIPT_MODE_NORMAL
        list.setPadding(a.dp(8), a.dp(6), a.dp(8), a.dp(6))
        list.clipToPadding = false
        frame.addView(list, MATCH, MATCH)
        frame.addView(empty, MATCH, MATCH)
        root.add(frame, MATCH, 0, top = 6, weight = 1f)
        (frame.layoutParams as LinearLayout.LayoutParams).bottomMargin = a.dp(12)
        refilter(false)
    }

    fun onLogs(json: String) {
        val body = try {
            JSONObject(json)
        } catch (_: Exception) {
            return
        }
        val next = body.optLong("next")
        if (next < cursor) {
            all.clear()
            lastSeq = 0
        } // the service restarted and numbering began again
        cursor = next
        val items = body.optJSONArray("entries") ?: return
        for (i in 0 until items.length()) {
            val o = items.optJSONObject(i) ?: continue
            val seq = o.optLong("seq")
            if (seq <= lastSeq) continue
            lastSeq = seq
            all.add(Entry(o.optLong("seq"), o.optString("time"), o.optString("level"), o.optString("source"), o.optString("message")))
        }
        if (items.length() > 0) {
            while (all.size > MAX) all.removeAt(0)
            refilter(false)
        }
    }

    private fun matches(e: Entry): Boolean {
        val rank = when (e.level) {
            "error" -> 0
            "warn" -> 1
            "info" -> 2
            else -> 3
        }
        if (rank > level) return false
        return query.isEmpty() || e.message.contains(query, true) || e.source.contains(query, true) || e.level.contains(query, true)
    }

    private fun refilter(jump: Boolean) {
        shown = all.filter(::matches)
        adapter.notifyDataSetChanged()
        empty.visibility = if (shown.isEmpty()) View.VISIBLE else View.GONE
        empty.text = if (all.isEmpty()) "Nothing here yet. Problems show up as they happen." else "No lines match."
        if (jump && shown.isNotEmpty()) list.setSelection(shown.lastIndex)
    }

    private fun copyAll() {
        if (shown.isEmpty()) {
            act.toast("Nothing to copy")
            return
        }
        val text = shown.joinToString("\n") { "${clock(it.time)} ${it.level.uppercase()} ${it.source} ${it.message}" }
        a.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("pipe logs", text))
        act.toast("Copied ${shown.size} lines")
    }

    private fun clock(time: String): String = if (time.length >= 19) time.substring(11, 19) else time

    private inner class LogAdapter : BaseAdapter() {
        override fun getCount() = shown.size
        override fun getItem(position: Int) = shown[position]
        override fun getItemId(position: Int) = shown[position].seq

        override fun getView(position: Int, recycled: View?, parent: ViewGroup): View {
            val row = (recycled as? TextView) ?: a.text("", 12f).apply {
                typeface = Typeface.MONOSPACE
                setPadding(a.dp(4), a.dp(3), a.dp(4), a.dp(3))
                setTextIsSelectable(false)
            }
            val e = shown[position]
            val color = when (e.level) {
                "error" -> R.color.danger
                "warn" -> R.color.warn
                "info" -> R.color.primary
                else -> R.color.muted
            }
            val s = SpannableStringBuilder()
            s.append(clock(e.time), ForegroundColorSpan(a.c(R.color.muted)), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
            s.append(' ')
            val tag = when (e.level) {
                "error" -> "ERR"
                "warn" -> "WARN"
                "info" -> "INFO"
                else -> "DBG"
            }
            s.append(tag, ForegroundColorSpan(a.c(color)), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
            s.setSpan(StyleSpan(Typeface.BOLD), s.length - tag.length, s.length, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
            s.append(' ').append(e.message)
            row.text = s
            row.setTextColor(a.c(R.color.text))
            return row
        }
    }

    private companion object {
        const val MAX = 1000
    }
}
