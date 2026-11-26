// SPDX-License-Identifier: GPL-3.0-or-later

package link

import (
	"bytes"
	"encoding/hex"
	"image/png"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"rsc.io/qr"
)

func TestRoundTrip(t *testing.T) {
	for _, p := range []Profile{
		{Host: "example.test", Name: "phone"},
		{Host: "example.test", HTTPSProxy: "proxy.example.test", Name: "default hp"},
		{Host: "example.test", Port: 18443, HTTPSProxy: "proxy.example.test:9443", CDN: "cdn.example.test", WSPath: "/private/path", SubID: "abc-123", Name: "a phone 📱"},
		{Host: "2001:db8::1", FastSNI: "origin.example.test", Name: "ipv6"},
		{Host: "2001:db8::1", FastSNI: "origin.example.test", Port: 9443, Name: "ipv6 port"},
		{Host: "direct.example.test", FastPort: 24443, StealthPort: 8443, FastSNI: "fast.example.test",
			RealitySNI: "cover.example.test", FastPin: EncodeKey([32]byte{4}), FastHop: "20000-40000",
			HTTPSProxy: "cover.example.test:9443", CDN: "static.example.test", CDNPort: 2053, WSPath: "/ws/path", Name: "shared"},
	} {
		p.Seed[0], p.PublicKey[31] = 123, 45
		t.Run(p.Name, func(t *testing.T) {
			encoded, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(encoded)
			if err != nil || got != p {
				t.Fatalf("Parse(Encode(profile)) failed: %v", err)
			}
		})
	}
}

func TestBadLink(t *testing.T) {
	key := EncodeKey([32]byte{1, 2, 3})
	stem := "pipe://" + key + "@example.test"
	for _, test := range []struct{ name, input, message string }{
		{"scheme", "https://example.test", "begin with pipe://"},
		{"seed", "pipe://short@example.test?pbk=" + key + "#phone", "invalid seed"},
		{"padded seed", "pipe://" + key + "=@example.test?pbk=" + key + "#phone", "invalid seed"},
		{"password", "pipe://" + key + ":secret@example.test?pbk=" + key + "#phone", "only the seed"},
		{"missing key", stem + "#phone", "public key"},
		{"bad key", stem + "?pbk=abc#phone", "public key"},
		{"duplicate", stem + "?pbk=" + key + "&pbk=" + key + "#phone", "one non-empty"},
		{"query", stem + "?pbk=" + key + "&bogus=1#phone", "unknown"},
		{"empty", stem + "?pbk=" + key + "&cdn=#phone", "one non-empty"},
		{"path", stem + "/?pbk=" + key + "#phone", "authority or path"},
		{"port", stem + ":0?pbk=" + key + "#phone", "port"},
		{"leading zero authority port", stem + ":0443?pbk=" + key + "#phone", "leading zeros"},
		{"empty port", stem + ":?pbk=" + key + "#phone", "port"},
		{"host", "pipe://" + key + "@-example.test?pbk=" + key + "#phone", "server host"},
		{"IP needs SNI", "pipe://" + key + "@127.0.0.1?pbk=" + key + "#phone", "requires fsni"},
		{"noncanonical IPv4 authority", "pipe://" + key + "@127.1?pbk=" + key + "&fsni=example.test#phone", "server host"},
		{"fast port", stem + "?pbk=" + key + "&fp=0#phone", "invalid fp"},
		{"stealth port", stem + "?pbk=" + key + "&sp=65536#phone", "invalid sp"},
		{"leading zero fast port", stem + "?pbk=" + key + "&fp=0443#phone", "leading zeros"},
		{"leading zero stealth port", stem + "?pbk=" + key + "&sp=08443#phone", "leading zeros"},
		{"fast SNI", stem + "?pbk=" + key + "&fsni=127.0.0.1#phone", "fsni must"},
		{"numeric fast SNI", stem + "?pbk=" + key + "&fsni=2130706433#phone", "fsni must"},
		{"reality SNI", stem + "?pbk=" + key + "&rsni=host.invalid:443#phone", "rsni must"},
		{"numeric REALITY SNI", stem + "?pbk=" + key + "&rsni=0177.0.0.1#phone", "rsni must"},
		{"pin length", stem + "?pbk=" + key + "&pin=abc#phone", "invalid Fast pin"},
		{"padded pin", stem + "?pbk=" + key + "&pin=" + key + "%3D#phone", "invalid Fast pin"},
		{"invalid hop", stem + "?pbk=" + key + "&fh=40000-20000#phone", "Fast hop"},
		{"hp ip", stem + "?pbk=" + key + "&hp=127.0.0.1:9443#phone", "hp must"},
		{"hp ipv6", stem + "?pbk=" + key + "&hp=[::1]:9443#phone", "hp must"},
		{"hp numeric label", stem + "?pbk=" + key + "&hp=proxy.123:9443#phone", "hp must"},
		{"hp trailing colon", stem + "?pbk=" + key + "&hp=proxy.example.test:#phone", "invalid hp"},
		{"hp zero port", stem + "?pbk=" + key + "&hp=proxy.example.test:0#phone", "invalid hp"},
		{"hp overflow port", stem + "?pbk=" + key + "&hp=proxy.example.test:65536#phone", "invalid hp"},
		{"hp leading zero port", stem + "?pbk=" + key + "&hp=proxy.example.test:0443#phone", "leading zeros"},
		{"hp extra colon", stem + "?pbk=" + key + "&hp=proxy.example.test:9443:1#phone", "invalid hp"},
		{"hp userinfo", stem + "?pbk=" + key + "&hp=u@proxy.example.test:9443#phone", "hp must"},
		{"hp path", stem + "?pbk=" + key + "&hp=proxy.example.test/x#phone", "hp must"},
		{"hp scheme", stem + "?pbk=" + key + "&hp=https://proxy.example.test:9443#phone", "invalid hp"},
		{"hp empty", stem + "?pbk=" + key + "&hp=#phone", "one non-empty"},
		{"cdn ip", stem + "?pbk=" + key + "&cdn=127.0.0.1#phone", "cdn must"},
		{"cdn ipv6", stem + "?pbk=" + key + "&cdn=[::1]:2053#phone", "cdn must"},
		{"cdn port without name", stem + "?pbk=" + key + "&cdn=:2053#phone", "cdn must"},
		{"cdn path", stem + "?pbk=" + key + "&cdn=cdn.example.test/x#phone", "cdn must"},
		{"cdn empty port", stem + "?pbk=" + key + "&cdn=cdn.example.test:#phone", "invalid cdn"},
		{"cdn zero port", stem + "?pbk=" + key + "&cdn=cdn.example.test:0#phone", "invalid cdn"},
		{"cdn overflow port", stem + "?pbk=" + key + "&cdn=cdn.example.test:65536#phone", "invalid cdn"},
		{"cdn leading zero port", stem + "?pbk=" + key + "&cdn=cdn.example.test:02053#phone", "leading zeros"},
		{"cdn extra colon", stem + "?pbk=" + key + "&cdn=cdn.example.test:2053:443#phone", "invalid cdn"},
		{"ws", stem + "?pbk=" + key + "&wsp=relative#phone", "absolute WebSocket path"},
		{"sub", stem + "?pbk=" + key + "&sub=a%20b#phone", "URL-safe"},
		{"fragment", stem + "?pbk=" + key, "device name"},
		{"bidi override", stem + "?pbk=" + key + "#phone%E2%80%AE", "device name"},
		{"invisible format", stem + "?pbk=" + key + "#phone%E2%80%8B", "device name"},
		{"redaction", "pipe://" + key + "@%not-a-host", "authority"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.input)
			if err == nil || !strings.Contains(err.Error(), test.message) || strings.Contains(err.Error(), key) {
				t.Fatalf("want an error containing %q with secrets redacted, got %v", test.message, err)
			}
		})
	}
}

func TestDerive(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	got := Derive(seed)
	for _, id := range []string{got.VLESSUUID, got.VMessUUID} {
		b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(b) != 16 || b[6]>>4 != 4 || b[8]>>6 != 2 {
			t.Fatal("invalid version 4 UUID")
		}
	}
	if got.VLESSUUID == got.VMessUUID || got.RealitySID == got.DeviceID || Derive(seed) != got {
		t.Fatal("credentials must be deterministic and separated by purpose")
	}
	if len(got.HY2Password) != 43 || len(got.RealitySID) != 16 || len(got.DeviceID) != 16 ||
		len(got.HTTPSProxyPassword) != 43 || got.HTTPSProxyPassword == got.HY2Password {
		t.Fatal("incorrect credential length")
	}
}

func TestEndpointDefaultPorts(t *testing.T) {
	p := Profile{Host: "origin.example", Port: 8443, FastPort: 8443, StealthPort: 443, Name: "phone"}
	encoded, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "fp=") || !strings.Contains(encoded, "sp=443") {
		t.Fatal("Fast is redundant with the authority port, Stealth is not")
	}
	got, err := Parse(encoded)
	if err != nil || got.FastEndpointPort() != 8443 || got.StealthEndpointPort() != 443 {
		t.Fatalf("wrong effective ports: %v", err)
	}
}

func TestDefaultAuthorityPortIsCanonical(t *testing.T) {
	key := EncodeKey([32]byte{1, 2, 3})
	for _, host := range []string{"origin.example", "[2001:db8::1]"} {
		stem := "pipe://" + key + "@" + host
		query := "?fsni=fast.example&pbk=" + key
		profile, err := Parse(stem + ":443" + query + "&fp=443&sp=443#phone")
		if err != nil || profile.Port != 0 || profile.FastPort != 0 || profile.StealthPort != 0 {
			t.Fatalf("default ports did not normalize: %v", err)
		}
		profile.Port, profile.FastPort, profile.StealthPort = 443, 443, 443
		got, err := profile.Encode()
		if err != nil || got != stem+query+"#phone" {
			t.Fatalf("encoder did not omit the redundant ports: %v", err)
		}
	}
}

func TestDefaultCDNPortIsCanonical(t *testing.T) {
	key := EncodeKey([32]byte{1, 2, 3})
	prefix := "pipe://" + key + "@origin.example:8443?cdn=cdn.example"
	suffix := "&pbk=" + key + "#phone"
	profile, err := Parse(prefix + ":443" + suffix)
	if err != nil || profile.CDN != "cdn.example" || profile.CDNPort != 0 || profile.CDNEndpointPort() != 443 {
		t.Fatalf("default CDN port did not normalize: %v", err)
	}
	for _, port := range []uint16{0, 443} {
		profile.CDNPort = port
		got, err := profile.Encode()
		if err != nil || got != prefix+suffix {
			t.Fatalf("encoder did not omit default CDN port %d: %v", port, err)
		}
	}
}

func TestEncodeRejectsInvalidCDN(t *testing.T) {
	for _, test := range []struct {
		host string
		port uint16
	}{
		{host: "", port: 2053},
		{host: "127.0.0.1"},
		{host: "cdn.example:2053"},
	} {
		p := Profile{Host: "origin.example", Name: "phone", CDN: test.host, CDNPort: test.port}
		if _, err := p.Encode(); err == nil {
			t.Errorf("encoded invalid CDN host %q or port %d", test.host, test.port)
		}
	}
}

func TestDNSNamesRejectNumericFinalLabels(t *testing.T) {
	for _, value := range []string{"127.1", "0177.0.0.1", "2130706433", "host.123", "127.0.0.1", "::1", "123"} {
		if ValidDNSName(value) {
			t.Errorf("accepted %s as a DNS name", value)
		}
	}
	for _, value := range []string{"123.example", "example.a123"} {
		if !ValidDNSName(value) {
			t.Errorf("rejected DNS name %s", value)
		}
	}
}

func FuzzParse(f *testing.F) {
	valid, err := (Profile{Host: "example.test", HTTPSProxy: "proxy.example.test:9443", CDN: "cdn.example.test", WSPath: "/ws", Name: "phone"}).Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add("pipe://invalid")
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := Parse(raw)
		if err != nil {
			return
		}
		encoded, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(encoded)
		if err != nil || got != p {
			t.Fatalf("valid profile failed to round-trip: %v", err)
		}
	})
}

func TestHTTPSProxyCanonicalAndProxyURL(t *testing.T) {
	key := EncodeKey([32]byte{7, 8, 9})
	raw := "pipe://" + key + "@origin.example?pbk=" + key + "&hp=proxy.example:443#phone%3A%20%24%26%27%F0%9F%93%B1"
	p, err := Parse(raw)
	if err != nil || p.HTTPSProxy != "proxy.example" {
		t.Fatalf("hp default port did not normalize: %q %v", p.HTTPSProxy, err)
	}
	encoded, err := p.Encode()
	if err != nil || strings.Contains(encoded, "%3A443") || !strings.Contains(encoded, "hp=proxy.example") {
		t.Fatalf("encoded link did not omit default hp port: %q %v", encoded, err)
	}
	proxyURL, ok := ProxyURL(p)
	if !ok {
		t.Fatal("ProxyURL returned false for valid hp")
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u.Scheme != "https" || u.Host != "proxy.example:443" || u.User.Username() != p.Name ||
		strings.ContainsAny(proxyURL, " $&'") {
		t.Fatalf("invalid or shell-unsafe ProxyURL: %q %v", proxyURL, err)
	}
	if pw, has := u.User.Password(); !has || pw != Derive(p.Seed).HTTPSProxyPassword {
		t.Fatal("ProxyURL did not derive HTTPSProxyPassword")
	}

	p.HTTPSProxy = "proxy.example:9443"
	proxyURL, ok = ProxyURL(p)
	if !ok || !strings.HasSuffix(proxyURL, "@proxy.example:9443") {
		t.Fatalf("unexpected ProxyURL with custom port: %q %v", proxyURL, ok)
	}

	p.HTTPSProxy = ""
	if got, ok := ProxyURL(p); ok || got != "" {
		t.Fatalf("expected false for empty hp, got %q %v", got, ok)
	}
	p.HTTPSProxy = "127.0.0.1:9443"
	if got, ok := ProxyURL(p); ok || got != "" {
		t.Fatalf("expected false for invalid hp, got %q %v", got, ok)
	}
}

func TestQRSVGAndQRPNG(t *testing.T) {
	if QRSVG("") != "" || QRPNG("") != nil {
		t.Fatal("empty text must produce empty QR output")
	}
	if QRSVG(strings.Repeat("a", 5000)) != "" || QRPNG(strings.Repeat("a", 5000)) != nil {
		t.Fatal("oversized text must fail cleanly")
	}
	sample, err := (Profile{Host: "example.test", HTTPSProxy: "proxy.example.test:9443", Name: "phone"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	svg := QRSVG(sample)
	if !strings.HasPrefix(svg, `<svg xmlns="http://www.w3.org/2000/svg"`) || !strings.HasSuffix(svg, `</svg>`) ||
		!strings.Contains(svg, `shape-rendering="crispEdges"`) {
		t.Fatalf("unexpected SVG wrapper: %q", svg[:min(120, len(svg))])
	}
	if len(svg) > 6000 {
		t.Fatalf("SVG unexpectedly large: %d bytes", len(svg))
	}
	// Verify every dark module in the SVG path matches rsc.io/qr exactly.
	code, err := qr.Encode(sample, QRLevel)
	if err != nil {
		t.Fatal(err)
	}
	_, tail, ok := strings.Cut(svg, ` d="`)
	if !ok {
		t.Fatal("missing SVG path data")
	}
	pathData, _, ok := strings.Cut(tail, `"`)
	if !ok {
		t.Fatal("unterminated SVG path data")
	}
	grid := make([][]bool, code.Size)
	for y := range grid {
		grid[y] = make([]bool, code.Size)
	}
	readInt := func(s string) (int, string) {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		n, err := strconv.Atoi(s[:i])
		if err != nil {
			t.Fatalf("bad number in path %q: %v", s, err)
		}
		return n, s[i:]
	}
	cx, cy := 0, 0
	for rest := pathData; rest != ""; {
		cmd := rest[0]
		rest = rest[1:]
		switch cmd {
		case 'M':
			cx, rest = readInt(rest)
			if rest[0] != ' ' {
				t.Fatalf("expected space in M: %q", rest)
			}
			cy, rest = readInt(rest[1:])
		case 'm':
			var dx, dy int
			dx, rest = readInt(rest)
			if rest[0] != ' ' {
				t.Fatalf("expected space in m: %q", rest)
			}
			dy, rest = readInt(rest[1:])
			cx, cy = cx+dx, cy+dy
		case 'h':
			var w int
			w, rest = readInt(rest)
			for x := cx; x < cx+w; x++ {
				grid[cy][x] = true
			}
			cx += w
		default:
			t.Fatalf("unexpected SVG command %q in %q", cmd, rest)
		}
	}
	for y := range code.Size {
		for x := range code.Size {
			if grid[y][x] != code.Black(x, y) {
				t.Fatalf("module mismatch at (%d,%d): svg=%v qr=%v", x, y, grid[y][x], code.Black(x, y))
			}
		}
	}

	pngBytes := QRPNG(sample)
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil || img.Bounds().Dx() <= code.Size || img.Bounds().Dx() != img.Bounds().Dy() {
		t.Fatalf("invalid QRPNG output: %v", err)
	}
}
