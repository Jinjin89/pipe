// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.system.Os
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketException

internal data class DefaultNetworkRoute(
    val handle: Long,
    val name: String,
    val gateways: List<String>,
    val ipv4DefaultRoute: Boolean,
    val ipv6DefaultRoute: Boolean,
    val hasIPv4Address: Boolean,
)

internal data class AndroidNetworkSnapshot(val json: String, val defaultRoute: DefaultNetworkRoute?)

internal class DefaultNetworkChanges(
    private val initialPhysical: Long?,
    private var snapshot: AndroidNetworkSnapshot,
) {
    var physical = initialPhysical
        private set
    private var haveBaseline = false

    fun onCapabilities(handle: Long, isVpn: Boolean): Boolean {
        if (isVpn) return false
        physical = handle
        return true
    }

    fun onLost(handle: Long): Boolean {
        if (physical != handle) return false
        physical = null
        haveBaseline = true
        return true
    }

    // Null means the engine already has this snapshot.
    fun update(next: AndroidNetworkSnapshot): Boolean? {
        val initialBaseline = physical == initialPhysical && !haveBaseline
        if (next.defaultRoute != null) haveBaseline = true
        if (snapshot == next) return null
        val reset = resetNeeded(snapshot.defaultRoute, next.defaultRoute, initialBaseline)
        snapshot = next
        return reset
    }

    private fun resetNeeded(
        previous: DefaultNetworkRoute?,
        next: DefaultNetworkRoute?,
        initialBaseline: Boolean,
    ): Boolean {
        if (previous == null || next == null) return !initialBaseline && previous != next
        // IPv4 can become available between the startup snapshot and the first callback.
        if (previous.ipv4DefaultRoute != next.ipv4DefaultRoute || previous.hasIPv4Address != next.hasIPv4Address) {
            return true
        }
        if (initialBaseline) return false
        // Go handles IPv6 availability changes when it reads the snapshot.
        return previous.handle != next.handle || previous.name != next.name ||
            previous.gateways.any { it !in next.gateways } ||
            (previous.ipv6DefaultRoute && !next.ipv6DefaultRoute)
    }
}

internal fun ConnectivityManager.networkSnapshot(
    defaultNetwork: Network?,
    defaultProperties: LinkProperties? = null,
): AndroidNetworkSnapshot {
    val interfaces = sortedMapOf<String, JSONObject>()
    var defaultRoute: DefaultNetworkRoute? = null
    var defaultAddresses = emptyList<String>()
    var defaultIPv6Route = false
    @Suppress("DEPRECATION")
    val networks = allNetworks.toSet() + listOfNotNull(defaultNetwork)
    for (network in networks) {
        val capabilities = getNetworkCapabilities(network) ?: continue
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
        val isDefault = network == defaultNetwork
        val properties = (if (isDefault) defaultProperties else null)
            ?: getLinkProperties(network) ?: continue
        val name = properties.interfaceName ?: continue
        val index = Os.if_nametoindex(name)
        if (index <= 0) continue
        val type = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
        // These bits are Go's net.Flags. ConnectivityManager supplies the
        // active links and their media without a kernel interface dump.
        val flags = FLAG_UP or FLAG_RUNNING or when (type) {
            "wifi", "ethernet" -> FLAG_BROADCAST or FLAG_MULTICAST
            "cellular" -> FLAG_POINT_TO_POINT
            else -> 0
        }
        val linkAddresses = properties.linkAddresses
        val addresses = linkAddresses.mapNotNull { link ->
            link.address.hostAddress?.let { "${it.substringBefore('%')}/${link.prefixLength}" }
        }.sorted()
        val defaultRoutes = properties.routes.filter { it.isDefaultRoute }
        val gateways = defaultRoutes.mapNotNull { route ->
            route.gateway?.takeUnless { it.isAnyLocalAddress }?.hostAddress
        }.distinct().sorted()
        val hasIPv4 = linkAddresses.any { it.address.isUsableIPv4() }
        val clat = if (hasIPv4) null else findClat(name)
        val clatAddresses = clat?.interfaceAddresses.orEmpty().mapNotNull { link ->
            link.address?.takeIf { it.isUsableIPv4() }?.hostAddress?.let { "$it/${link.networkPrefixLength}" }
        }.sorted()
        val metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        val entry = JSONObject()
            .put("name", name)
            .put("index", index)
            .put("mtu", if (Build.VERSION.SDK_INT >= 29) properties.mtu else 0)
            .put("addresses", JSONArray(addresses))
            .put("flags", flags)
            .put("type", type)
            .put("dns", JSONArray(properties.dnsServers.mapNotNull { it.hostAddress }))
            .put("gateways", JSONArray(gateways))
            .put("metered", metered)
        if (isDefault) {
            interfaces[name] = entry
            defaultIPv6Route = defaultRoutes.any { it.destination.address is Inet6Address }
            defaultRoute = DefaultNetworkRoute(
                network.networkHandle,
                name,
                gateways,
                defaultRoutes.any { it.destination.address is Inet4Address },
                defaultIPv6Route,
                hasIPv4 || clatAddresses.isNotEmpty(),
            )
            defaultAddresses = (addresses + clatAddresses).sorted()
        } else {
            interfaces.putIfAbsent(name, entry)
        }
        if (clat != null && clatAddresses.isNotEmpty()) {
            val clatEntry = JSONObject()
                .put("name", clat.name)
                .put("index", clat.index)
                .put("addresses", JSONArray(clatAddresses))
                .put("flags", FLAG_UP or FLAG_RUNNING or FLAG_POINT_TO_POINT)
                .put("type", type)
                .put("metered", metered)
            if (isDefault) {
                interfaces[clat.name] = clatEntry
            } else {
                interfaces.putIfAbsent(clat.name, clatEntry)
            }
        }
    }
    val json = JSONObject()
        .put("defaultInterface", defaultRoute?.name)
        .put("defaultNetwork", defaultRoute?.handle)
        .put("defaultIPv6Route", defaultIPv6Route)
        .put("defaultAddresses", JSONArray(defaultAddresses))
        .put("interfaces", JSONArray(interfaces.values))
        .toString()
    return AndroidNetworkSnapshot(json, defaultRoute)
}

private fun findClat(baseName: String): NetworkInterface? {
    // Android names each CLAT device after its base link.
    val name = "v4-$baseName"
    if (Os.if_nametoindex(name) <= 0) return null
    return try {
        NetworkInterface.getByName(name)?.takeIf { it.index > 0 && it.isUp }
    } catch (_: SocketException) {
        null
    }
}

private fun InetAddress.isUsableIPv4(): Boolean =
    this is Inet4Address && !isAnyLocalAddress && !isLoopbackAddress && !isLinkLocalAddress && !isMulticastAddress

private const val FLAG_UP = 1
private const val FLAG_BROADCAST = 2
private const val FLAG_POINT_TO_POINT = 8
private const val FLAG_MULTICAST = 16
private const val FLAG_RUNNING = 32
