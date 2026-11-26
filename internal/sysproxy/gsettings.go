// SPDX-License-Identifier: GPL-3.0-or-later

package sysproxy

import (
	"encoding/json"
	"errors"
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
	for _, scheme := range []string{"http", "https", "socks"} {
		schema := "org.gnome.system.proxy." + scheme
		if _, err := g.Run("gsettings", "set", schema, "host", host); err != nil {
			return err
		}
		if _, err := g.Run("gsettings", "set", schema, "port", p); err != nil {
			return err
		}
	}
	if _, err := g.Run("gsettings", "set", "org.gnome.system.proxy", "ignore-hosts", gnomeBypass()); err != nil {
		return err
	}
	_, err := g.Run("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
	return err
}

func gnomeBypass() string {
	return "['localhost', '*.local', '" + strings.Join(bypassAddresses, "', '") + "']"
}

func (g Gsettings) IsApplied(host string, port int) bool {
	return g.verifyCleared(host, port) != nil
}

func (g Gsettings) verifyCleared(host string, port int) error {
	modeOut, err := g.Run("gsettings", "get", "org.gnome.system.proxy", "mode")
	if err != nil {
		return fmt.Errorf("read GNOME proxy mode: %w", err)
	}
	if trim(modeOut) != "'manual'" {
		return nil
	}
	wantHost, wantPort := "'"+host+"'", strconv.Itoa(port)
	for _, scheme := range []string{"http", "https", "socks"} {
		schema := "org.gnome.system.proxy." + scheme
		hOut, err := g.Run("gsettings", "get", schema, "host")
		if err != nil {
			return fmt.Errorf("read GNOME %s proxy host: %w", scheme, err)
		}
		pOut, err := g.Run("gsettings", "get", schema, "port")
		if err != nil {
			return fmt.Errorf("read GNOME %s proxy port: %w", scheme, err)
		}
		if trim(hOut) == wantHost && trim(pOut) == wantPort {
			return fmt.Errorf("GNOME %s proxy still points to Pipe", scheme)
		}
	}
	return nil
}

func (g Gsettings) RestoreIfApplied(saved json.RawMessage, host string, port int) error {
	return g.restore(saved, map[string]string{
		"mode": "'manual'", "ignore-hosts": gnomeBypass(), "host": "'" + host + "'", "port": strconv.Itoa(port),
	})
}

func (g Gsettings) Restore(raw json.RawMessage) error {
	return g.restore(raw, nil)
}

func (g Gsettings) restore(raw json.RawMessage, applied map[string]string) error {
	var saved map[string]string
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	var result error
	// Restore mode last so a half-restored state is never "manual" with wrong hosts.
	for i := len(gnomeKeys) - 1; i >= 0; i-- {
		k := gnomeKeys[i]
		value, ok := saved[k.schema+" "+k.key]
		if !ok {
			continue
		}
		if applied != nil {
			out, err := g.Run("gsettings", "get", k.schema, k.key)
			result = errors.Join(result, err)
			if err != nil || trim(out) != applied[k.key] {
				continue
			}
		}
		if _, err := g.Run("gsettings", "set", k.schema, k.key, value); err != nil {
			result = errors.Join(result, fmt.Errorf("restore %s: %w", k.key, err))
		}
	}
	return result
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
	for _, v := range kdeProxyValues(host, port) {
		if err := k.write(v[0], v[1]); err != nil {
			return err
		}
	}
	k.notify()
	return nil
}

func kdeProxyValues(host string, port int) [][2]string {
	addr := "http://" + host + " " + strconv.Itoa(port)
	no := "localhost,.local," + strings.Join(bypassAddresses, ",")
	return [][2]string{
		{"httpProxy", addr}, {"httpsProxy", addr},
		{"socksProxy", "socks://" + host + " " + strconv.Itoa(port)},
		{"NoProxyFor", no}, {"ProxyType", "1"},
	}
}

func (k Kde) IsApplied(host string, port int) bool {
	return k.verifyCleared(host, port) != nil
}

func (k Kde) verifyCleared(host string, port int) error {
	kind, err := k.Run(k.Read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType")
	if err != nil {
		return fmt.Errorf("read KDE ProxyType: %w", err)
	}
	if trim(kind) != "1" {
		return nil
	}
	httpAddr := "http://" + host + " " + strconv.Itoa(port)
	socksAddr := "socks://" + host + " " + strconv.Itoa(port)
	for _, check := range [][2]string{
		{"httpProxy", httpAddr},
		{"httpsProxy", httpAddr},
		{"socksProxy", socksAddr},
	} {
		out, err := k.Run(k.Read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", check[0])
		if err != nil {
			return fmt.Errorf("read KDE %s: %w", check[0], err)
		}
		if trim(out) == check[1] {
			return fmt.Errorf("KDE %s still points to Pipe", check[0])
		}
	}
	return nil
}

func (k Kde) RestoreIfApplied(saved json.RawMessage, host string, port int) error {
	var values map[string]string
	if err := json.Unmarshal(saved, &values); err != nil {
		return err
	}
	var result error
	for _, v := range kdeProxyValues(host, port) {
		out, err := k.Run(k.Read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", v[0])
		if err == nil && trim(out) == v[1] {
			value := values[v[0]]
			if v[0] == "ProxyType" && value == "" {
				value = "0"
			}
			err = k.write(v[0], value)
		}
		result = errors.Join(result, err)
	}
	k.notify()
	return result
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
