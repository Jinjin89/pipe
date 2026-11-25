// SPDX-License-Identifier: GPL-3.0-or-later

package webview

import (
	"errors"
	"net/url"
	"strings"
)

const (
	maxProvisionalRetries  = 3
	errCodeCancelled       = -999 // NSURLErrorCancelled
	errCodePolicyInterrupt = 102  // WKErrorFrameLoadInterruptedByPolicyChange
)

// Origin is the single loopback HTTP origin a webview window is locked to.
type Origin struct {
	Host string // "127.0.0.1:<port>"
}

// ParseOrigin validates that rawURL targets http://127.0.0.1:<port> with no
// userinfo and returns its locked Origin.
func ParseOrigin(rawURL string) (Origin, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Origin{}, errors.New("webview: invalid URL")
	}
	if !strings.EqualFold(u.Scheme, "http") || u.User != nil {
		return Origin{}, errors.New("webview: URL must be loopback http without userinfo")
	}
	portStr := u.Port()
	if u.Hostname() != "127.0.0.1" || portStr == "" || portStr[0] == '0' {
		return Origin{}, errors.New("webview: URL must target 127.0.0.1 with a valid port")
	}
	port := 0
	for i := 0; i < len(portStr); i++ {
		c := portStr[i]
		if c < '0' || c > '9' {
			return Origin{}, errors.New("webview: invalid port")
		}
		port = port*10 + int(c-'0')
		if port > 65535 {
			return Origin{}, errors.New("webview: invalid port")
		}
	}
	if port == 0 {
		return Origin{}, errors.New("webview: invalid port")
	}
	return Origin{Host: "127.0.0.1:" + portStr}, nil
}

// DecideNavigation reports whether targetURL matches the locked
// http://127.0.0.1:<port> origin. Everything else is denied.
func (o Origin) DecideNavigation(targetURL string) bool {
	if o.Host == "" || targetURL == "" {
		return false
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.User != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "http") && strings.EqualFold(u.Host, o.Host)
}

// shouldRetryProvisional reports whether a failed provisional load with error
// code errCode should trigger another reload given prior consecutive retries.
func shouldRetryProvisional(retries, errCode int) bool {
	if errCode == errCodeCancelled || errCode == errCodePolicyInterrupt {
		return false
	}
	return retries < maxProvisionalRetries
}
