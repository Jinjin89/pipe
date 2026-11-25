// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

private val wifi = DefaultNetworkRoute(100, "wlan0", listOf("10.0.2.15/24"), listOf("10.0.2.2"))
private val cellular = DefaultNetworkRoute(101, "rmnet0", listOf("10.0.3.15/24"), listOf("10.0.3.2"))

fun main() {
    val initial = AndroidNetworkSnapshot("initial Wi-Fi", wifi)
    val changes = DefaultNetworkChanges(wifi.handle, initial)
    check(changes.onCapabilities(wifi.handle, isVpn = false))
    val baseline = AndroidNetworkSnapshot("initial Wi-Fi link properties", wifi.copy(addresses = listOf("10.0.2.16/24")))
    check(changes.update(baseline) == false) { "The first snapshot of the initial network reset the VPN" }
    check(changes.update(baseline) == null) { "An unchanged snapshot refreshed the engine" }
    check(changes.update(baseline.copy(json = "secondary network updated")) == false) {
        "A secondary network update reset the VPN"
    }
    check(changes.update(baseline.copy(json = "default network metered")) == false) {
        "A default capability update reset the VPN"
    }

    var route = checkNotNull(baseline.defaultRoute)
    for ((description, next) in listOf(
        "addresses" to route.copy(addresses = wifi.addresses),
        "gateway" to wifi.copy(gateways = listOf("10.0.2.1")),
        "interface" to wifi.copy(name = "wlan1", gateways = listOf("10.0.2.1")),
        "handle" to wifi.copy(handle = 102, name = "wlan1", gateways = listOf("10.0.2.1")),
    )) {
        check(changes.onCapabilities(next.handle, isVpn = false))
        check(changes.update(AndroidNetworkSnapshot(description, next)) == true) {
            "Changed default $description did not reset the VPN"
        }
        route = next
    }
    check(changes.onLost(route.handle))
    check(changes.update(AndroidNetworkSnapshot("offline", null)) == true)

    val early = DefaultNetworkChanges(wifi.handle, initial)
    check(early.onCapabilities(cellular.handle, isVpn = false))
    check(!early.onCapabilities(103, isVpn = true)) { "The VPN was accepted as the underlying network" }
    check(!early.onLost(103) && !early.onLost(wifi.handle) && early.physical == cellular.handle)
    check(early.update(AndroidNetworkSnapshot("early cellular", cellular)) == true) {
        "Switching to cellular before the Wi-Fi baseline did not reset the VPN"
    }
}
