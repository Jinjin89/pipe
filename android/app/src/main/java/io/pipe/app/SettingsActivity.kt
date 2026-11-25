// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.LruCache
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.ListView
import android.widget.Spinner
import android.widget.Toast
import java.util.concurrent.Executors

class SettingsActivity : Activity() {
    private data class InstalledApp(val info: ApplicationInfo, val label: String)
    private class AppRow(view: View) {
        val icon: ImageView = view.findViewById(R.id.icon)
        val selection: CheckBox = view.findViewById(R.id.include_app)
        var packageName: String? = null
    }

    private val selected = LinkedHashSet<String>()
    private val loader = Executors.newSingleThreadExecutor()
    private val icons = LruCache<String, Drawable>(64)
    private lateinit var apps: AppAdapter
    private lateinit var preferences: VpnPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        findViewById<View>(R.id.root).padForSystemBars()
        preferences = runCatching { VpnPreferences.read(this) }.getOrDefault(VpnPreferences())
        selected.addAll(preferences.packages)
        val mode = findViewById<Spinner>(R.id.per_app)
        val ipv6 = findViewById<CheckBox>(R.id.ipv6)
        setChoices(mode, listOf("All apps", "Only selected", "Bypass selected"), MODES.indexOf(preferences.perApp))
        ipv6.isChecked = preferences.ipv6

        apps = AppAdapter()
        findViewById<ListView>(R.id.apps).adapter = apps
        loader.execute {
            @Suppress("DEPRECATION")
            val installed = packageManager.getInstalledApplications(0)
                .filter { it.packageName != packageName }
                .map { InstalledApp(it, it.loadLabel(packageManager).toString()) }
                .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
            runOnUiThread { if (!isDestroyed) apps.setApps(installed) }
        }
        findViewById<EditText>(R.id.search_apps).addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {
                apps.search(text.toString())
            }
            override fun afterTextChanged(text: Editable?) = Unit
        })

        findViewById<Button>(R.id.save).setOnClickListener {
            val perApp = MODES[mode.selectedItemPosition]
            if (perApp == "only" && selected.isEmpty()) {
                toast("Select at least one app")
                return@setOnClickListener
            }
            try {
                preferences.copy(
                    ipv6 = ipv6.isChecked,
                    perApp = perApp,
                    packages = selected.sorted(),
                ).save(this)
                setResult(RESULT_OK)
                finish()
            } catch (_: Exception) {
                toast("Could not save VPN settings")
            }
        }
    }

    override fun onDestroy() {
        loader.shutdownNow()
        super.onDestroy()
    }

    private fun setChoices(spinner: Spinner, titles: List<String>, selected: Int) {
        spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, titles).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        spinner.setSelection(maxOf(0, selected))
    }

    private inner class AppAdapter : BaseAdapter() {
        private var installed = emptyList<InstalledApp>()
        private var visible = installed
        private var query = ""

        fun setApps(apps: List<InstalledApp>) {
            installed = apps
            search(query)
        }

        fun search(query: String) {
            this.query = query
            visible = installed.filter {
                it.label.contains(query, ignoreCase = true) || it.info.packageName.contains(query, ignoreCase = true)
            }
            notifyDataSetChanged()
        }

        override fun getCount(): Int = visible.size
        override fun getItem(position: Int): InstalledApp = visible[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, recycled: View?, parent: ViewGroup): View {
            val row = recycled ?: LayoutInflater.from(parent.context).inflate(R.layout.row_app, parent, false)
                .apply { tag = AppRow(this) }
            val holder = row.tag as AppRow
            val app = getItem(position)
            val id = app.info.packageName
            if (holder.packageName != id) {
                holder.packageName = id
                val cached = icons.get(id)
                holder.icon.setImageDrawable(cached?.constantState?.newDrawable(resources) ?: cached)
                if (cached == null) {
                    loader.execute {
                        val icon = runCatching { app.info.loadIcon(packageManager) }.getOrNull()
                        if (icon != null) runOnUiThread {
                            if (!isDestroyed) {
                                icons.put(id, icon)
                                if (holder.packageName == id) {
                                    holder.icon.setImageDrawable(icon.constantState?.newDrawable(resources) ?: icon)
                                }
                            }
                        }
                    }
                }
            }
            holder.selection.apply {
                setOnCheckedChangeListener(null)
                text = "${app.label}\n$id"
                isChecked = id in selected
                setOnCheckedChangeListener { _, checked ->
                    if (checked) selected.add(id) else selected.remove(id)
                }
            }
            return row
        }
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_SHORT).show()

    companion object {
        private val MODES = listOf("all", "only", "bypass")
    }
}
