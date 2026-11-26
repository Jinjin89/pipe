// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic && with_utls

package config

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"pipe/internal/engine"
	"pipe/internal/link"
)

func TestGeneratedClientOptions(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := &link.Profile{Host: "origin.example", CDN: "cdn.example", WSPath: "/ws", Name: "test", PublicKey: [32]byte(key.PublicKey().Bytes())}
	for _, mode := range []string{Smart, Global, Direct} {
		for _, tun := range []bool{false, true} {
			options, err := BuildClient(ClientOptions{
				Profile: profile,
				Preferences: Preferences{Mode: mode, TUN: tun, IPv6: false, Rules: []Rule{
					{"domain", "blocked.example", "block"},
					{"domain_suffix", "direct.example", "direct"},
					{"process_name", "curl", "proxy"},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			instance, err := engine.New(t.Context(), options)
			if err != nil {
				t.Fatalf("sing-box rejected mode %s with TUN %t: %v", mode, tun, err)
			}
			instance.Close()
		}
	}
}

func TestGeneratedProbeOptions(t *testing.T) {
	for _, options := range []ProbeOptions{
		{Profile: link.Profile{Host: "192.0.2.1"}},
		{
			Profile: link.Profile{Host: "origin.example", CDN: "cdn.example", FastPin: link.EncodeKey([32]byte{1})},
			Relay:   "relay.example:8444/444", IPv6: true, Interface: "uplink0",
		},
	} {
		compiled, err := BuildProbe(options)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := engine.New(t.Context(), compiled)
		if err != nil {
			t.Fatalf("sing-box rejected probe options for %s: %v", options.Profile.Host, err)
		}
		if err := instance.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGeneratedClientHTTPSFakeIPAndExemptions(t *testing.T) {
	prefs := Defaults()
	prefs.Mode, prefs.TUN = Global, true
	prefs.Rules = []Rule{{Field: "domain", Match: "blocked.pipe-test.com", Action: "block"}}
	options, err := BuildClient(ClientOptions{Preferences: prefs, Profile: &link.Profile{Host: "origin.example"}})
	if err != nil {
		t.Fatal(err)
	}
	dnsOptions := options.Config["dns"].(engine.Object)
	dnsRules := dnsOptions["rules"].([]engine.Object)
	private := privateDomains()
	private["server"] = privateLocalDNS
	if len(dnsRules) < 2 || !reflect.DeepEqual(dnsRules[0], private) || dnsRules[1]["rcode"] != "NXDOMAIN" {
		t.Fatalf("private and blocked DNS rules must precede fake-IP rules: %v", dnsRules)
	}
	// These fallback answers make an accidental fake-IP match visible without
	// sending the exempt names to an external resolver in the test.
	dnsRules = append(dnsRules,
		engine.Object{"domain_suffix": "pool.ntp.org", "action": "predefined", "rcode": "NXDOMAIN"},
		engine.Object{"domain_suffix": "pipe-test.net", "action": "predefined", "rcode": "NXDOMAIN"},
		engine.Object{"domain_suffix": "connectivitycheck.gstatic.com", "action": "predefined", "rcode": "NXDOMAIN"},
	)
	dnsOptions["rules"] = dnsRules
	ctx := service.ContextWithDefaultRegistry(t.Context())
	instance, err := engine.New(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	router := service.FromContext[adapter.DNSRouter](ctx)
	if router == nil {
		t.Fatal("missing DNS router")
	}
	scope := adapter.NewScope(t.Context(), boxlog.NewNOPFactory().NewLogger("dns-test"))
	if err := router.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scope.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, queryType := range []uint16{mDNS.TypeHTTPS, mDNS.TypeSVCB} {
		for _, test := range []struct {
			host  string
			rcode int
			count int
		}{
			{"fake.pipe-test.com", mDNS.RcodeSuccess, 0},
			{"blocked.pipe-test.com", mDNS.RcodeNameError, 0},
			{"time.pool.ntp.org", mDNS.RcodeNameError, 0},
			{"stun.pipe-test.net", mDNS.RcodeNameError, 0},
			{"connectivitycheck.gstatic.com", mDNS.RcodeNameError, 0},
		} {
			t.Run(test.host+"/"+mDNS.TypeToString[queryType], func(t *testing.T) {
				query := new(mDNS.Msg).SetQuestion(test.host+".", queryType)
				queryCtx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				response, err := router.Exchange(queryCtx, query, adapter.DNSQueryOptions{})
				if err != nil {
					t.Fatalf("%s query failed: %v", mDNS.TypeToString[queryType], err)
				}
				if response == nil || response.Rcode != test.rcode || len(response.Answer) != test.count {
					t.Fatalf("%s query returned response=%v; want rcode=%v and %d answers", mDNS.TypeToString[queryType], response, test.rcode, test.count)
				}
			})
		}
	}
}

func TestDNSCIDRRuleOrderWithRecordedResolvers(t *testing.T) {
	seen := make(chan string, 2)
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		var query mDNS.Msg
		if err != nil || query.Unpack(data) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		seen <- r.URL.Path
		reply, err := new(mDNS.Msg).SetReply(&query).Pack()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(reply)
	}))
	defer fixture.Close()
	host, rawPort, err := net.SplitHostPort(fixture.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	const name = "home.pipe-test.net"
	direct := Rule{Field: "domain", Match: name, Action: "direct"}
	cidr := Rule{Field: "ip_cidr", Match: "192.0.2.0/24", Action: "proxy"}
	for _, tc := range []struct {
		rules []Rule
		want  string
	}{{[]Rule{direct, cidr}, "/direct"}, {[]Rule{cidr, direct}, "/proxy"}} {
		t.Run(tc.want, func(t *testing.T) {
			prefs := Defaults()
			prefs.TUN, prefs.Rules = true, tc.rules
			opts, err := BuildClient(ClientOptions{Preferences: prefs, Profile: &link.Profile{Host: "origin.example"}})
			if err != nil {
				t.Fatal(err)
			}
			// The fixture uses loopback in a namespace without an uplink.
			opts.Config["route"].(engine.Object)["auto_detect_interface"] = false
			paths := map[string]string{domesticDoH: "/direct", "proxy-doh": "/proxy"}
			for _, server := range opts.Config["dns"].(engine.Object)["servers"].([]engine.Object) {
				if path, ok := paths[server["tag"].(string)]; ok {
					server["server"], server["server_port"], server["path"] = host, port, path
					server["tls"] = engine.Object{"enabled": true, "insecure": true}
					delete(server, "detour")
				}
			}
			ctx := service.ContextWithDefaultRegistry(t.Context())
			instance, err := engine.New(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			router := service.FromContext[adapter.DNSRouter](ctx)
			scope := adapter.NewScope(t.Context(), boxlog.NewNOPFactory().NewLogger("dns-order-fixture"))
			defer scope.Close()
			if err := router.Start(adapter.StartStateStart, scope); err != nil {
				t.Fatal(err)
			}
			query := new(mDNS.Msg).SetQuestion(name+".", mDNS.TypeTXT)
			queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if _, err := router.Exchange(queryCtx, query, adapter.DNSQueryOptions{}); err != nil {
				t.Fatal(err)
			}
			select {
			case path := <-seen:
				if path != tc.want {
					t.Fatalf("TXT query reached %s, want %s", path, tc.want)
				}
			default:
				t.Fatal("recording resolver saw no query")
			}
		})
	}
}
