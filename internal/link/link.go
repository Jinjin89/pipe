// SPDX-License-Identifier: GPL-3.0-or-later

// Package link encodes device profiles and derives their protocol credentials.
//
// A pipe link has the form:
//
//	pipe://<seed>@<host>[:<port>]?pbk=<key>[&cdn=...&wsp=...&sub=...&fp=...&sp=...&rsni=...&fsni=...&pin=...&fh=...&hp=<host>[:<port>]]#<name>
//
// Unknown query parameters are rejected so clients fail closed; adding a new
// key such as hp (HTTPS proxy address, port defaulting to DefaultPort) is
// therefore a link format addition that older clients will not accept.
package link

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const DefaultPort = 443

var keyEncoding = base64.RawURLEncoding.Strict()

type Profile struct {
	Seed        [32]byte
	PublicKey   [32]byte
	Host        string
	Port        uint16 // Zero uses DefaultPort.
	FastPort    uint16 // Zero uses ServerPort.
	StealthPort uint16 // Zero uses ServerPort.
	RealitySNI  string
	FastSNI     string
	FastPin     string
	FastHop     string
	HTTPSProxy  string // Optional HTTPS proxy address (hp=<host>[:<port>]); port defaults to DefaultPort.
	CDN         string
	WSPath      string
	SubID       string
	Name        string
}

func (p Profile) FastEndpointPort() uint16 {
	if p.FastPort != 0 {
		return p.FastPort
	}
	return p.ServerPort()
}

func (p Profile) StealthEndpointPort() uint16 {
	if p.StealthPort != 0 {
		return p.StealthPort
	}
	return p.ServerPort()
}

func (p Profile) FastServerName() string {
	if p.FastSNI != "" {
		return p.FastSNI
	}
	return p.Host
}

func (p Profile) StealthServerName() string {
	if p.RealitySNI != "" {
		return p.RealitySNI
	}
	if ValidDNSName(p.Host) {
		return p.Host
	}
	return p.FastServerName()
}

func (p Profile) ServerPort() uint16 {
	if p.Port == 0 {
		return DefaultPort
	}
	return p.Port
}

// Parse never includes the input URL or its secrets in an error.
func Parse(raw string) (Profile, error) {
	var profile Profile
	if !strings.HasPrefix(raw, "pipe://") {
		return profile, errors.New("link must begin with pipe://")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.Host == "" || u.Path != "" {
		return profile, errors.New("invalid pipe link authority or path")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return profile, errors.New("link user information must contain only the seed")
	}
	profile.Seed, err = DecodeKey(u.User.Username())
	if err != nil {
		return Profile{}, fmt.Errorf("invalid seed: %w", err)
	}
	profile.Host = u.Hostname()
	if strings.HasPrefix(u.Host, "[") != strings.Contains(profile.Host, ":") {
		return Profile{}, errors.New("IPv6 server hosts must be enclosed in brackets")
	}
	if port := u.Port(); port != "" || strings.HasSuffix(u.Host, ":") {
		n, err := parsePort(port)
		if err != nil {
			return Profile{}, err
		}
		if n != DefaultPort {
			profile.Port = n
		}
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, errors.New("invalid pipe link query")
	}
	for key, values := range query {
		if len(values) != 1 || values[0] == "" {
			return Profile{}, errors.New("link parameters must have one non-empty value each")
		}
		switch key {
		case "pbk", "cdn", "wsp", "sub", "fp", "sp", "rsni", "fsni", "pin", "fh", "hp":
		default:
			return Profile{}, errors.New("unknown pipe link parameter")
		}
	}
	profile.PublicKey, err = DecodeKey(query.Get("pbk"))
	if err != nil {
		return Profile{}, fmt.Errorf("invalid REALITY public key (pbk): %w", err)
	}
	profile.CDN, profile.WSPath = query.Get("cdn"), query.Get("wsp")
	profile.SubID, profile.Name = query.Get("sub"), u.Fragment
	profile.RealitySNI, profile.FastSNI = query.Get("rsni"), query.Get("fsni")
	profile.FastPin, profile.FastHop = query.Get("pin"), query.Get("fh")
	profile.HTTPSProxy = query.Get("hp")
	for key, target := range map[string]*uint16{"fp": &profile.FastPort, "sp": &profile.StealthPort} {
		if v := query.Get(key); v != "" {
			port, err := parsePort(v)
			if err != nil {
				return Profile{}, fmt.Errorf("invalid %s: %w", key, err)
			}
			if port != profile.ServerPort() {
				*target = port
			}
		}
	}
	if err := profile.validate(); err != nil {
		return Profile{}, err
	}
	if strings.EqualFold(profile.RealitySNI, profile.Host) {
		profile.RealitySNI = ""
	}
	if strings.EqualFold(profile.FastSNI, profile.Host) {
		profile.FastSNI = ""
	}
	if profile.HTTPSProxy != "" {
		profile.HTTPSProxy, _ = canonicalHTTPSProxy(profile.HTTPSProxy)
	}
	return profile, nil
}

func (p Profile) Encode() (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	host := p.Host
	if p.ServerPort() != DefaultPort {
		host = net.JoinHostPort(host, strconv.Itoa(int(p.Port)))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	query := url.Values{"pbk": {EncodeKey(p.PublicKey)}}
	for key, value := range map[string]string{
		"cdn": p.CDN, "wsp": p.WSPath, "sub": p.SubID, "pin": p.FastPin, "fh": p.FastHop,
	} {
		if value != "" {
			query.Set(key, value)
		}
	}
	for key, name := range map[string]string{"rsni": p.RealitySNI, "fsni": p.FastSNI} {
		if name != "" && !strings.EqualFold(name, p.Host) {
			query.Set(key, name)
		}
	}
	for key, port := range map[string]uint16{"fp": p.FastEndpointPort(), "sp": p.StealthEndpointPort()} {
		if port != p.ServerPort() {
			query.Set(key, strconv.Itoa(int(port)))
		}
	}
	if hp, _ := canonicalHTTPSProxy(p.HTTPSProxy); hp != "" {
		query.Set("hp", hp)
	}
	u := url.URL{
		Scheme: "pipe", Host: host, User: url.User(EncodeKey(p.Seed)),
		RawQuery: query.Encode(), Fragment: p.Name,
	}
	return u.String(), nil
}

func (p Profile) validate() error {
	if !ValidHost(p.Host) {
		return errors.New("server host must be a DNS name or IP address")
	}
	if !ValidDNSName(p.Host) && p.FastSNI == "" {
		return errors.New("an IP server host requires fsni")
	}
	for key, value := range map[string]string{"rsni": p.RealitySNI, "fsni": p.FastSNI} {
		if value != "" && !ValidDNSName(value) {
			return fmt.Errorf("%s must be a DNS name", key)
		}
	}
	if p.FastPin != "" {
		if _, err := DecodeKey(p.FastPin); err != nil {
			return fmt.Errorf("invalid Fast pin: %w", err)
		}
	}
	if p.FastHop != "" {
		if _, _, err := ParseHop(p.FastHop); err != nil {
			return err
		}
	}
	if p.HTTPSProxy != "" {
		if _, _, err := parseHTTPSProxy(p.HTTPSProxy); err != nil {
			return err
		}
	}
	if p.CDN != "" && !ValidHost(p.CDN) {
		return errors.New("cdn must be a DNS name or IP address without a port")
	}
	if p.WSPath != "" && !ValidWSPath(p.WSPath) {
		return errors.New("wsp must be an absolute WebSocket path without a query or fragment")
	}
	if p.SubID != "" && (len(p.SubID) > 128 || strings.IndexFunc(p.SubID, func(r rune) bool {
		return !asciiAlnum(r) && !strings.ContainsRune("-._~", r)
	}) >= 0) {
		return errors.New("sub must be a URL-safe identifier of at most 128 bytes")
	}
	if !ValidName(p.Name) {
		return errors.New("device name must contain 1–128 bytes of printable text")
	}
	return nil
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	if value != strconv.FormatUint(n, 10) {
		return 0, errors.New("port must be written without leading zeros")
	}
	return uint16(n), nil
}

func ParseHop(value string) (uint16, uint16, error) {
	first, last, _ := strings.Cut(value, "-")
	start, startErr := parsePort(first)
	end, endErr := parsePort(last)
	if startErr != nil || endErr != nil || start >= end ||
		value != fmt.Sprintf("%d-%d", start, end) {
		return 0, 0, errors.New("Fast hop must be an ascending port range such as 20000-40000")
	}
	return start, end, nil
}

func ValidDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.IndexFunc(label, func(r rune) bool { return !asciiAlnum(r) && r != '-' }) >= 0 {
			return false
		}
	}
	last := host[strings.LastIndexByte(host, '.')+1:]
	return strings.IndexFunc(last, func(r rune) bool { return r < '0' || r > '9' }) >= 0
}

func ValidName(name string) bool {
	return name != "" && len(name) <= 128 && utf8.ValidString(name) &&
		strings.TrimSpace(name) == name && strings.IndexFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	}) < 0
}

func ValidWSPath(path string) bool {
	return len(path) <= 256 && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") &&
		utf8.ValidString(path) && !strings.ContainsAny(path, "?#\\") &&
		strings.IndexFunc(path, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}

func ValidHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == ""
	}
	return ValidDNSName(host)
}

func asciiAlnum(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9'
}

func EncodeKey(key [32]byte) string { return keyEncoding.EncodeToString(key[:]) }

func DecodeKey(text string) ([32]byte, error) {
	var key [32]byte
	if len(text) != keyEncoding.EncodedLen(len(key)) {
		return key, errors.New("expected 32 bytes encoded as unpadded base64url")
	}
	decoded, err := keyEncoding.DecodeString(text)
	if err != nil || len(decoded) != len(key) || keyEncoding.EncodeToString(decoded) != text {
		return key, errors.New("expected 32 bytes encoded as unpadded base64url")
	}
	copy(key[:], decoded)
	return key, nil
}

type Credentials struct {
	VLESSUUID          string `json:"vless_uuid"`
	HY2Password        string `json:"hy2_password"`
	VMessUUID          string `json:"vmess_uuid"`
	RealitySID         string `json:"reality_sid"`
	DeviceID           string `json:"device_id"`
	HTTPSProxyPassword string `json:"https_proxy_password,omitempty"`
}

func Derive(seed [32]byte) Credentials {
	derive := func(label string, size int) []byte {
		key, err := hkdf.Key(sha256.New, seed[:], []byte("pipe/v1"), label, size)
		if err != nil {
			// All sizes and the input key length are fixed and valid for SHA-256.
			panic(err)
		}
		return key
	}
	return Credentials{
		VLESSUUID:          uuid4(derive("vless-uuid", 16)),
		HY2Password:        keyEncoding.EncodeToString(derive("hy2-password", 32)),
		VMessUUID:          uuid4(derive("vmess-uuid", 16)),
		RealitySID:         hex.EncodeToString(derive("reality-sid", 8)),
		DeviceID:           hex.EncodeToString(derive("device-id", 8)),
		HTTPSProxyPassword: keyEncoding.EncodeToString(derive("https-proxy", 32)),
	}
}

func uuid4(key []byte) string {
	key[6] = key[6]&0x0f | 0x40
	key[8] = key[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", key[:4], key[4:6], key[6:8], key[8:10], key[10:])
}

func parseHTTPSProxy(value string) (string, uint16, error) {
	host, rawPort, hasPort := strings.Cut(value, ":")
	if !ValidDNSName(host) {
		return "", 0, errors.New("hp must be a DNS name with an optional port")
	}
	if !hasPort {
		return host, DefaultPort, nil
	}
	port, err := parsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("invalid hp: %w", err)
	}
	return host, port, nil
}

func canonicalHTTPSProxy(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	host, port, err := parseHTTPSProxy(value)
	if err != nil {
		return "", err
	}
	if port == DefaultPort {
		return host, nil
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// FormatProxyURL formats a shell-safe HTTPS proxy URL for one device.
func FormatProxyURL(authority, name, password string) string {
	return "https://" + escapeProxyUser(name) + ":" + password + "@" + authority
}

// ProxyExport is the shell line that sends a terminal's HTTPS and plain HTTP
// requests through proxyURL. It is empty when proxyURL is.
func ProxyExport(proxyURL string) string {
	if proxyURL == "" {
		return ""
	}
	return "export https_proxy=" + proxyURL + " http_proxy=" + proxyURL
}

// ProxyURL derives the HTTPS proxy URL for p, or returns false when p has no
// valid HTTPS proxy address (hp).
func ProxyURL(p Profile) (string, bool) {
	if p.HTTPSProxy == "" || !ValidName(p.Name) {
		return "", false
	}
	host, port, err := parseHTTPSProxy(p.HTTPSProxy)
	if err != nil {
		return "", false
	}
	authority := net.JoinHostPort(host, strconv.Itoa(int(port)))
	return FormatProxyURL(authority, p.Name, Derive(p.Seed).HTTPSProxyPassword), true
}

func escapeProxyUser(name string) string {
	const digits = "0123456789ABCDEF"
	var escaped strings.Builder
	for i := range len(name) {
		c := name[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.ContainsRune("-._~", rune(c)) {
			escaped.WriteByte(c)
			continue
		}
		escaped.WriteByte('%')
		escaped.WriteByte(digits[c>>4])
		escaped.WriteByte(digits[c&15])
	}
	return escaped.String()
}
