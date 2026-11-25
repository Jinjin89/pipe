// SPDX-License-Identifier: GPL-3.0-or-later

package sysproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type gkey struct{ schema, key string }

var gnomeKeys = []gkey{
	{"org.gnome.system.proxy", "mode"},
	{"org.gnome.system.proxy", "ignore-hosts"},
	{"org.gnome.system.proxy.http", "host"},
	{"org.gnome.system.proxy.http", "port"},
	{"org.gnome.system.proxy.https", "host"},
	{"org.gnome.system.proxy.https", "port"},
	{"org.gnome.system.proxy.socks", "host"},
	{"org.gnome.system.proxy.socks", "port"},
}

// Gsettings drives the GNOME proxy settings.
type Gsettings struct{ Run Runner }

func (g Gsettings) Capture() (json.RawMessage, error) {
	saved := map[string]string{}
	for _, k := range gnomeKeys {
		out, err := g.Run("gsettings", "get", k.schema, k.key)
		if err != nil {
			return nil, err
		}
		saved[k.schema+" "+k.key] = trim(out)
	}
	return json.Marshal(saved)
}

func (g Gsettings) Apply(host string, port int) error {
	p := strconv.Itoa(port)
	list := "['localhost', '*.local'"
	for _, c := range bypassAddresses {
		list += ", '" + c + "'"
	}
	list += "]"
	for _, scheme := range []string{"http", "https", "socks"} {
		schema := "org.gnome.system.proxy." + scheme
		if _, err := g.Run("gsettings", "set", schema, "host", host); err != nil {
			return err
		}
		if _, err := g.Run("gsettings", "set", schema, "port", p); err != nil {
			return err
		}
	}
	if _, err := g.Run("gsettings", "set", "org.gnome.system.proxy", "ignore-hosts", list); err != nil {
		return err
	}
	_, err := g.Run("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
	return err
}

func (g Gsettings) IsApplied(host string, port int) bool {
	get := func(schema, key string) string {
		out, _ := g.Run("gsettings", "get", schema, key)
		return trim(out)
	}
	return get("org.gnome.system.proxy", "mode") == "'manual'" &&
		get("org.gnome.system.proxy.http", "host") == "'"+host+"'" &&
		get("org.gnome.system.proxy.http", "port") == strconv.Itoa(port)
}

func (g Gsettings) RestoreIfApplied(saved json.RawMessage, host string, port int) error {
	return restoreIfApplied(g, saved, host, port)
}

func (g Gsettings) Restore(raw json.RawMessage) error {
	var saved map[string]string
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	var first error
	// Restore mode last so a half-restored state is never "manual" with wrong hosts.
	for i := len(gnomeKeys) - 1; i >= 0; i-- {
		k := gnomeKeys[i]
		value, ok := saved[k.schema+" "+k.key]
		if !ok {
			continue
		}
		if _, err := g.Run("gsettings", "set", k.schema, k.key, value); err != nil && first == nil {
			first = fmt.Errorf("restore %s: %w", k.key, err)
		}
	}
	return first
}

// Kde drives kioslaverc through kwriteconfig5 or kwriteconfig6.
type Kde struct {
	Run         Runner
	Write, Read string // kwriteconfig6 / kreadconfig6, or the 5 variants
}

var kdeKeys = []string{"ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"}

func (k Kde) write(key, value string) error {
	_, err := k.Run(k.Write, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, value)
	return err
}

func (k Kde) Capture() (json.RawMessage, error) {
	saved := map[string]string{}
	for _, key := range kdeKeys {
		out, err := k.Run(k.Read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key)
		if err != nil {
			return nil, err
		}
		saved[key] = strings.TrimRight(out, "\r\n")
	}
	return json.Marshal(saved)
}

func (k Kde) Apply(host string, port int) error {
	addr := "http://" + host + " " + strconv.Itoa(port)
	no := "localhost,.local," + strings.Join(bypassAddresses, ",")
	values := [][2]string{
		{"httpProxy", addr}, {"httpsProxy", addr},
		{"socksProxy", "socks://" + host + " " + strconv.Itoa(port)},
		{"NoProxyFor", no}, {"ProxyType", "1"},
	}
	for _, v := range values {
		if err := k.write(v[0], v[1]); err != nil {
			return err
		}
	}
	k.notify()
	return nil
}

func (k Kde) IsApplied(host string, port int) bool {
	out, err := k.Run(k.Read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy")
	if err != nil || trim(out) != "http://"+host+" "+strconv.Itoa(port) {
		return false
	}
	kind, err := k.Run(k.Read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType")
	return err == nil && trim(kind) == "1"
}

func (k Kde) RestoreIfApplied(saved json.RawMessage, host string, port int) error {
	return restoreIfApplied(k, saved, host, port)
}

func (k Kde) Restore(raw json.RawMessage) error {
	var saved map[string]string
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	var first error
	for i := len(kdeKeys) - 1; i >= 0; i-- {
		key := kdeKeys[i]
		value := saved[key]
		if key == "ProxyType" && value == "" {
			value = "0" // it was unset: "no proxy"
		}
		if err := k.write(key, value); err != nil && first == nil {
			first = err
		}
	}
	k.notify()
	return first
}

// notify asks running KDE apps to reread the settings. Best effort.
func (k Kde) notify() {
	_, _ = k.Run("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:")
}

func detectLinux(desktop string, has func(string) bool, run Runner) Backend {
	desktop = strings.ToUpper(desktop)
	kde := strings.Contains(desktop, "KDE")
	if !kde && has("gsettings") {
		if _, err := run("gsettings", "get", "org.gnome.system.proxy", "mode"); err == nil {
			return Gsettings{Run: run}
		}
	}
	for _, v := range []string{"6", "5"} {
		if has("kwriteconfig"+v) && has("kreadconfig"+v) && (kde || !has("gsettings")) {
			return Kde{Run: run, Write: "kwriteconfig" + v, Read: "kreadconfig" + v}
		}
	}
	return nil
}
