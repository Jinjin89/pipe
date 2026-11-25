// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class ProfileRelay(val code: String = "", val on: Boolean = false) {
    val enabledCode: String get() = if (on) code else ""
}

internal data class SavedProfile(val link: String, val relay: ProfileRelay = ProfileRelay())

internal data class Profiles(val entries: List<SavedProfile> = emptyList(), val selected: Int = 0) {
    val current: SavedProfile? get() = entries.getOrNull(selected)
}

internal class ProfileStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "profiles.enc"))

    fun read(): Profiles {
        val bytes = try {
            file.readFully()
        } catch (_: FileNotFoundException) {
            return Profiles()
        }
        require(bytes.size > 2 && bytes[0] in KEY_ALIASES)
        val ivSize = bytes[1].toInt() and 0xff
        require(ivSize == 12 && bytes.size >= 2 + ivSize + 16)
        val cipher = Cipher.getInstance(CIPHER)
        cipher.init(Cipher.DECRYPT_MODE, key(bytes[0], create = false), GCMParameterSpec(128, bytes, 2, ivSize))
        val plain = cipher.doFinal(bytes, 2 + ivSize, bytes.size - 2 - ivSize)
        return try {
            val json = JSONObject(String(plain, Charsets.UTF_8))
            val saved = json.getJSONArray("profiles")
            val relays = json.optJSONArray("relays")
            val entries = List(saved.length()) { index ->
                val relay = relays?.optJSONObject(index)?.let { ProfileRelay(it.optString("host"), it.optBoolean("on")) }
                SavedProfile(saved.getString(index), relay ?: ProfileRelay())
            }
            Profiles(entries, json.getInt("selected").coerceIn(0, maxOf(0, entries.lastIndex)))
        } finally {
            plain.fill(0)
        }
    }

    fun save(profiles: Profiles) {
        val version = storedVersion()
        encrypt(profiles, version, key(version, create = true))
    }

    fun replaceUnreadable(raw: String) {
        val oldVersion = runCatching { storedVersion() }.getOrDefault(ORIGINAL)
        val version = if (oldVersion == ORIGINAL) REPLACEMENT else ORIGINAL
        // Prepare the new key independently so a failed write leaves the old
        // file and its key in place.
        val store = keystore()
        store.deleteEntry(KEY_ALIASES.getValue(version))
        encrypt(Profiles(listOf(SavedProfile(raw))), version, key(version, create = true))
        runCatching { store.deleteEntry(KEY_ALIASES.getValue(oldVersion)) }
    }

    private fun storedVersion(): Byte = try {
        file.openRead().use { it.read().toByte() }.takeIf { it in KEY_ALIASES } ?: ORIGINAL
    } catch (_: FileNotFoundException) {
        ORIGINAL
    }

    private fun encrypt(profiles: Profiles, version: Byte, key: SecretKey) {
        // Keep the link array readable by old versions of the app.
        val relays = profiles.entries.map { JSONObject().put("host", it.relay.code).put("on", it.relay.on) }
        val json = JSONObject()
            .put("profiles", JSONArray(profiles.entries.map { it.link }))
            .put("selected", profiles.selected)
            .put("relays", JSONArray(relays))
        val plain = json.toString().toByteArray(Charsets.UTF_8)
        try {
            val cipher = Cipher.getInstance(CIPHER)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            file.write(byteArrayOf(version, iv.size.toByte()) + iv + cipher.doFinal(plain))
        } finally {
            plain.fill(0)
        }
    }

    private fun keystore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(version: Byte, create: Boolean): SecretKey {
        val alias = KEY_ALIASES.getValue(version)
        (keystore().getKey(alias, null) as? SecretKey)?.let { return it }
        check(create)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private companion object {
        const val ORIGINAL: Byte = 1
        const val REPLACEMENT: Byte = 2
        val KEY_ALIASES = mapOf(ORIGINAL to "pipe-profile-v1", REPLACEMENT to "pipe-profile-v2")
        const val CIPHER = "AES/GCM/NoPadding"
    }
}

data class Rule(val type: String, val value: String, val action: String)

internal data class VpnPreferences(
    val mode: String = "smart",
    val tier: String = "auto",
    val ipv6: Boolean = true,
    val perApp: String = "all",
    val packages: List<String> = emptyList(),
    val rules: List<Rule> = emptyList(),
    val logLevel: String = "warn",
    // The service gets the enabled relay code from the encrypted profile store.
    val relay: String = "",
) {
    fun withAvailableTier(hasCdn: Boolean): VpnPreferences =
        if (tier == "rescue" && !hasCdn) copy(tier = "auto") else this

    private fun json(): JSONObject = JSONObject()
        .put("mode", mode)
        .put("tier", tier)
        .put("ipv6", ipv6)
        .put("perApp", JSONObject().put("mode", perApp).put("packages", JSONArray(packages)))
        .put("rules", JSONArray(rules.map { JSONObject().put("type", it.type).put("value", it.value).put("action", it.action) }))
        .put("logLevel", logLevel)

    fun forEngine(context: Context): String {
        val options = json().put("relay", relay)
        if (BuildConfig.DEBUG) {
            val ca = File(context.noBackupFilesDir, "test-ca.pem")
            val address = File(context.noBackupFilesDir, "test-address")
            if (ca.isFile && address.isFile && address.length() in 1..128) {
                options.put("test", JSONObject().put("caFile", ca.path).put("address", address.readText().trim()))
            }
        }
        return options.toString()
    }

    fun save(context: Context) {
        preferenceFile(context).write(json().toString().toByteArray(Charsets.UTF_8))
    }

    companion object {
        private fun preferenceFile(context: Context) =
            AtomicFile(File(context.noBackupFilesDir, "preferences.json"))

        fun read(context: Context): VpnPreferences {
            val options = try {
                JSONObject(String(preferenceFile(context).readFully(), Charsets.UTF_8))
            } catch (_: FileNotFoundException) {
                return VpnPreferences()
            }
            val perApp = options.optJSONObject("perApp")
            val packages = perApp?.optJSONArray("packages") ?: JSONArray()
            val saved = options.optJSONArray("rules") ?: JSONArray()
            val rules = (0 until saved.length()).mapNotNull { index ->
                saved.optJSONObject(index)?.let { Rule(it.optString("type"), it.optString("value"), it.optString("action")) }
            }
            return VpnPreferences(
                options.optString("mode", "smart"),
                options.optString("tier", "auto"),
                options.optBoolean("ipv6", true),
                perApp?.optString("mode", "all") ?: "all",
                List(packages.length()) { packages.getString(it) },
                rules,
                options.optString("logLevel", "warn"),
            )
        }
    }
}

internal fun profileHasCdn(raw: String): Boolean =
    JSONObject(Mobile.parseLink(raw)).getString("cdn").isNotEmpty()

private fun AtomicFile.write(bytes: ByteArray) {
    val output = startWrite()
    try {
        output.write(bytes)
        finishWrite(output)
    } catch (error: Exception) {
        failWrite(output)
        throw error
    }
}
