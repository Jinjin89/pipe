// SPDX-License-Identifier: GPL-3.0-or-later

// Package mobile provides the Android binding to the Pipe client.
package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"pipe/internal/link"
	"pipe/internal/logring"
	"pipe/internal/version"
)

// Platform is implemented by the Android VPN service. OpenTun returns a
// detached descriptor owned by Go. NetworkState returns the latest Android
// interfaces and default network as JSON. Callbacks may arrive on a background
// thread and must return without calling back into the VPN lifecycle.
type Platform interface {
	OpenTun(optionsJSON string) (int32, error)
	Protect(fd int32) bool
	NetworkState() string
	OnStatus(statusJSON string)
}

var client = bridge{newEngine: createEngine}

type linkSummary struct {
	Name            string `json:"name"`
	Domain          string `json:"domain"`
	CDN             string `json:"cdn"`
	KeyFingerprint  string `json:"keyFingerprint"`
	FastEndpoint    string `json:"fastEndpoint,omitempty"`
	StealthEndpoint string `json:"stealthEndpoint,omitempty"`
}

func ParseLink(raw string) (string, error) {
	profile, err := link.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	domain := profile.Host
	if port := profile.ServerPort(); port != link.DefaultPort {
		domain = net.JoinHostPort(domain, strconv.Itoa(int(port)))
	}
	fingerprint := sha256.Sum256(profile.PublicKey[:])
	summary := linkSummary{
		Name: profile.Name, Domain: domain, CDN: profile.CDNEndpoint(),
		KeyFingerprint: "SHA-256 " + hex.EncodeToString(fingerprint[:]),
	}
	if profile.FastPort != 0 || profile.StealthPort != 0 || profile.FastSNI != "" || profile.RealitySNI != "" ||
		profile.FastPin != "" || profile.FastHop != "" {
		summary.FastEndpoint = describeEndpoint(profile.Host, profile.FastEndpointPort(), profile.FastServerName())
		summary.StealthEndpoint = describeEndpoint(profile.Host, profile.StealthEndpointPort(), profile.StealthServerName())
	}
	body, err := json.Marshal(summary)
	return string(body), err
}

func describeEndpoint(host string, port uint16, name string) string {
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if !strings.EqualFold(host, name) {
		address += " (TLS name " + name + ")"
	}
	return address
}

func Start(profile, prefsJSON string, platform Platform) error {
	return client.start(profile, prefsJSON, platform)
}

func Stop()                     { client.stop() }
func Status() string            { return client.statusJSON() }
func SetTier(tier string) error { return client.setTier(tier) }
func SetMode(mode string) error { return client.setMode(mode) }
func ApplyPreferences(prefsJSON string) error {
	return client.applyPreferences(prefsJSON)
}
func RefreshNetwork() { client.networkChanged(false) }
func NetworkChanged() { client.networkChanged(true) }
func Version() string { return version.Version }

var logs = logring.New(0)

// Logs returns {"next":N,"entries":[...]} with entries newer than after. When
// many are pending it returns the newest ones, keeping the reply under 64 KB.
func Logs(after int64) string {
	cursor := uint64(0)
	if after > 0 {
		cursor = uint64(after)
	}
	for limit := 200; ; limit /= 2 {
		entries, next := logs.Since(cursor, limit)
		body, _ := json.Marshal(struct {
			Next    uint64          `json:"next"`
			Entries []logring.Entry `json:"entries"`
		}{next, entries})
		if len(body) <= 60*1024 || limit <= 1 {
			return string(body)
		}
	}
}

func ClearLogs() { logs.Clear() }

// TestRoutes probes each available route once (12 s at most) and returns a
// JSON map of route to {ms, ok, at}. Results also appear in Status.
func TestRoutes() string { return client.testRoutes() }
