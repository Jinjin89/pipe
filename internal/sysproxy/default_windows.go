// SPDX-License-Identifier: GPL-3.0-or-later
//go:build windows

package sysproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const internetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// Default returns the registry backend.
func Default() Backend { return winRegistry{} }

type winRegistry struct{}

type winSaved struct {
	Enable      uint32 `json:"enable"`
	HasEnable   bool   `json:"hasEnable"`
	Server      string `json:"server"`
	HasServer   bool   `json:"hasServer"`
	Override    string `json:"override"`
	HasOverride bool   `json:"hasOverride"`
}

func (winRegistry) Capture() (json.RawMessage, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	var s winSaved
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.Enable, s.HasEnable = uint32(v), true
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		s.Server, s.HasServer = v, true
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		s.Override, s.HasOverride = v, true
	}
	return json.Marshal(s)
}

func windowsBypass() string {
	list := []string{"<local>", "localhost", "127.*", "10.*"}
	for i := 16; i <= 31; i++ {
		list = append(list, "172."+strconv.Itoa(i)+".*")
	}
	return strings.Join(append(list,
		"192.168.*", "169.254.*", "*.local",
		// IPv6 loopback, link-local and ULA: ranges for Chromium-based browsers,
		// bracketed wildcards for WinINET (full addresses have no "::").
		"::1/128", "fe80::/10", "fc00::/7",
		"[::1]", "[fe8*]", "[fe9*]", "[fea*]", "[feb*]", "[fc*]", "[fd*]",
	), ";")
}

func (winRegistry) Apply(host string, port int) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("ProxyServer", fmt.Sprintf("%s:%d", host, port)); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", windowsBypass()); err != nil {
		return err
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	refresh()
	return nil
}

func (winRegistry) IsApplied(host string, port int) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	server, _, err2 := k.GetStringValue("ProxyServer")
	return err == nil && err2 == nil && enabled == 1 && server == fmt.Sprintf("%s:%d", host, port)
}

func (r winRegistry) RestoreIfApplied(saved json.RawMessage, host string, port int) error {
	return restoreIfApplied(r, saved, host, port)
}

func (winRegistry) Restore(raw json.RawMessage) error {
	var s winSaved
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	setOrDelete := func(name string, has bool, set func() error) {
		if has {
			_ = set()
		} else {
			_ = k.DeleteValue(name)
		}
	}
	setOrDelete("ProxyServer", s.HasServer, func() error { return k.SetStringValue("ProxyServer", s.Server) })
	setOrDelete("ProxyOverride", s.HasOverride, func() error { return k.SetStringValue("ProxyOverride", s.Override) })
	enable := uint32(0)
	if s.HasEnable {
		enable = s.Enable
	}
	err = k.SetDWordValue("ProxyEnable", enable)
	refresh()
	return err
}

// refresh tells wininet clients to reread the settings.
func refresh() {
	proc := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	const settingsChanged, refreshOption, proxyChanged = 39, 37, 95
	proc.Call(0, proxyChanged, 0, 0)
	proc.Call(0, settingsChanged, 0, 0)
	proc.Call(0, refreshOption, 0, 0)
}
