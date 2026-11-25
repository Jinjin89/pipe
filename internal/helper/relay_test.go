// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"pipe/internal/clientctl"
)

func TestRelayWireOptions(t *testing.T) {
	opts := testOptions(t)
	opts.Relay = "[2001:db8::2]:8444/30000-39999"
	wire, err := EncodeOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	if wire.Relay != opts.Relay {
		t.Fatalf("wire relay = %q", wire.Relay)
	}
	decoded, err := DecodeOptions(wire)
	if err != nil || decoded.Relay != opts.Relay || !decoded.TUN {
		t.Fatalf("decoded options = %+v, %v", decoded, err)
	}
	for _, bad := range []string{"http://relay.example.test", "relay.example.test:0", "relay.example.test:8444/444,30000-39999", opts.Profile.Host + ":8444/444"} {
		wire.Relay = bad
		if _, err := DecodeOptions(wire); err == nil {
			t.Errorf("accepted relay %q", bad)
		}
	}
}

func TestRelayHelperRequestAndStatus(t *testing.T) {
	session := &fakeSession{}
	s := &server{opts: ServeOptions{Version: "1.2.3", Session: session, DNS: &fakeSystemDNS{}, FirstHold: time.Minute}}
	t.Cleanup(s.disarmLease)
	r := relayTestRemote(t, s.dispatch)
	opts := testOptions(t)
	opts.Relay = "[2001:db8::2]/30000-39999"
	if err := r.sessionCall("start", opts); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	startedCode := session.started.Relay
	session.mu.Unlock()
	if startedCode != opts.Relay {
		t.Fatalf("helper started with relay code %q, want %q", startedCode, opts.Relay)
	}
	for _, state := range []string{"", "pending", "via", "direct"} {
		session.mu.Lock()
		session.relayState = state
		session.mu.Unlock()
		if st := r.Status(); st.State != clientctl.StateOn || st.Relay != "2001:db8::2" || st.RelayState != state {
			t.Fatalf("status for %q = %+v", state, st)
		}
	}
	opts.Relay = ""
	if err := r.sessionCall("apply", opts); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); st.State != clientctl.StateOn || st.Relay != "" || st.RelayState != "" {
		t.Fatalf("disabled relay status = %+v", st)
	}
}

func TestRelayHelperRejectsOlderProtocol(t *testing.T) {
	var protocol atomic.Int32
	protocol.Store(ProtocolVersion)
	r := relayTestRemote(t, func(_ context.Context, req Request) (any, string) {
		if req.Method != "hello" {
			t.Errorf("sent %q to old helper", req.Method)
			return nil, "unexpected method"
		}
		return map[string]any{"version": "1.2.3", "protocol": protocol.Load()}, ""
	})
	if info := r.Info(); info.State != StateOK {
		t.Fatalf("initial helper info = %+v", info)
	}
	protocol.Store(ProtocolVersion - 1)
	opts := testOptions(t)
	opts.Relay = "relay.example.test:8444/444"
	for _, call := range []func(clientctl.Options) error{r.Start, r.Apply} {
		if err := call(opts); err == nil || err.Error() != msgOutdated {
			t.Fatalf("old helper returned %v", err)
		}
	}
	if info := r.Info(); info.State != StateOutdated || info.Note != msgOutdated {
		t.Fatalf("old helper info = %+v", info)
	}
}

func relayTestRemote(t *testing.T, dispatch func(context.Context, Request) (any, string)) *Remote {
	t.Helper()
	r := newRemote("test-helper", "1.2.3", nil)
	r.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			line, err := readLine(peer)
			if err != nil {
				t.Error(err)
				return
			}
			var req Request
			if err := json.Unmarshal(line, &req); err != nil {
				t.Error(err)
				return
			}
			res, errText := dispatch(ctx, req)
			reply(peer, res, errText)
		}()
		return client, nil
	}
	return r
}
