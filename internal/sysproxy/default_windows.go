// SPDX-License-Identifier: GPL-3.0-or-later
//go:build windows

package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
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
	s, err := captureRegistry(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func captureRegistry(k registry.Key) (winSaved, error) {
	var s winSaved
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.Enable, s.HasEnable = uint32(v), true
	} else if !errors.Is(err, registry.ErrNotExist) {
		return s, err
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		s.Server, s.HasServer = v, true
	} else if !errors.Is(err, registry.ErrNotExist) {
		return s, err
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		s.Override, s.HasOverride = v, true
	} else if !errors.Is(err, registry.ErrNotExist) {
		return s, err
	}
	return s, nil
}

func windowsBypass() string {
	return "<local>;localhost;*.local"
}

// Recognize snapshots left behind by earlier versions during crash repair.
const legacyWindowsBypass = "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;169.254.*;*.local;::1/128;fe80::/10;fc00::/7;[::1];[fe8*];[fe9*];[fea*];[feb*];[fc*];[fd*]"

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

func (winRegistry) RestoreIfApplied(saved json.RawMessage, host string, port int) error {
	return restoreRegistry(saved, fmt.Sprintf("%s:%d", host, port))
}

func (winRegistry) Restore(raw json.RawMessage) error {
	return restoreRegistry(raw, "")
}

func restoreRegistry(raw json.RawMessage, applied string) error {
	var s winSaved
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	var current winSaved
	if applied != "" {
		current, err = captureRegistry(k)
		if err != nil {
			return err
		}
	}
	setOrDelete := func(name string, has bool, set func() error) error {
		if has {
			return set()
		}
		err := k.DeleteValue(name)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	var result error
	if applied == "" || current.Override == windowsBypass() || current.Override == legacyWindowsBypass {
		result = errors.Join(result, setOrDelete("ProxyOverride", s.HasOverride, func() error { return k.SetStringValue("ProxyOverride", s.Override) }))
	}
	if applied == "" || current.Server == applied {
		var enableErr error
		if applied == "" || current.Enable == 1 {
			enableErr = setOrDelete("ProxyEnable", s.HasEnable, func() error { return k.SetDWordValue("ProxyEnable", s.Enable) })
		}
		result = errors.Join(result, enableErr)
		if enableErr == nil {
			result = errors.Join(result, setOrDelete("ProxyServer", s.HasServer, func() error { return k.SetStringValue("ProxyServer", s.Server) }))
		}
	}
	refresh()
	return result
}

// refresh tells wininet clients to reread the settings.
func refresh() {
	proc := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	const settingsChanged, refreshOption, proxyChanged = 39, 37, 95
	proc.Call(0, proxyChanged, 0, 0)
	proc.Call(0, settingsChanged, 0, 0)
	proc.Call(0, refreshOption, 0, 0)
}
