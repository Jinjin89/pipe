// SPDX-License-Identifier: GPL-3.0-or-later
//go:build with_quic

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fakeHysteriaPacketOutbound struct {
	conn  net.PacketConn
	dest  M.Socksaddr
	calls int
	err   error
}

func (o *fakeHysteriaPacketOutbound) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.dest = destination
	o.calls++
	return o.conn, o.err
}

type recordedPacketConn struct {
	writeTo        []M.Socksaddr
	writePacket    []M.Socksaddr
	readFromAddr   net.Addr
	readPacketAddr M.Socksaddr
}

func (c *recordedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n := copy(p, []byte("reply"))
	return n, c.readFromAddr, nil
}

func (c *recordedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeTo = append(c.writeTo, M.SocksaddrFromNet(addr))
	return len(p), nil
}

func (c *recordedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, _ = buffer.Write([]byte("reply"))
	return c.readPacketAddr, nil
}

func (c *recordedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.writePacket = append(c.writePacket, destination)
	return nil
}

func (c *recordedPacketConn) Close() error                     { return nil }
func (c *recordedPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *recordedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordedPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*recordedPacketConn)(nil)
var _ N.NetPacketConn = (*recordedPacketConn)(nil)

func TestFastPacketNameSelection(t *testing.T) {
	address := M.ParseSocksaddrHostPort("2001:db8::10", 443)
	other := M.ParseSocksaddrHostPort("2001:db8::20", 443)
	name := M.ParseSocksaddrHostPort("www.example.test", 443)
	addresses := []netip.Addr{address.Addr, other.Addr}
	ctx := func(inbound, protocol string, destination M.Socksaddr, domain string, resolved []netip.Addr) context.Context {
		return adapter.WithContext(t.Context(), &adapter.InboundContext{
			InboundType: inbound, Protocol: protocol, Destination: destination, Domain: domain,
			DestinationAddresses: resolved,
		})
	}
	tunQUIC := ctx(C.TypeTun, C.ProtocolQUIC, address, "www.example.test", nil)
	lookedUp := ctx(C.TypeMixed, "", name, "", addresses)
	wrongPort := ctx(C.TypeMixed, "", M.ParseSocksaddrHostPort("www.example.test", 8443), "", addresses)
	notResolved := ctx(C.TypeMixed, "", name, "", []netip.Addr{other.Addr})
	noQUICName := ctx(C.TypeTun, C.ProtocolQUIC, address, "203.0.113.7", nil)

	tests := []struct {
		name        string
		ctx         context.Context
		destination M.Socksaddr
		want        M.Socksaddr
		wantErr     error
	}{
		{"IP rule lookup sends the name", lookedUp, address, name, nil},
		{"TUN QUIC SNI sends the name", tunQUIC, address, name, nil},
		{"failed QUIC sniff keeps the address", adapter.WithContext(t.Context(), &adapter.InboundContext{
			InboundType: C.TypeTun, Protocol: C.ProtocolQUIC, Destination: address, Domain: "cached.example.test",
			SniffError: errors.New("need more data"),
		}), address, address, nil},
		{"IP rule lookup retries only once by name", lookedUp, other, other, errNamedOnce},
		{"no metadata", t.Context(), address, address, nil},
		{"SOCKS inbound QUIC keeps address", ctx(C.TypeSOCKS, C.ProtocolQUIC, address, "www.example.test", nil), address, address, nil},
		{"HTTP inbound QUIC keeps address", ctx(C.TypeHTTP, C.ProtocolQUIC, address, "www.example.test", nil), address, address, nil},
		{"DNS keeps address", ctx(C.TypeTun, C.ProtocolDNS, address, "www.example.test", nil), address, address, nil},
		{"non-QUIC UDP keeps address", ctx(C.TypeTun, "", address, "www.example.test", nil), address, address, nil},
		{"IP-only SNI keeps address", noQUICName, address, address, nil},
		{"non-TUN QUIC keeps address", ctx(C.TypeMixed, C.ProtocolQUIC, address, "www.example.test", nil), address, address, nil},
		{"different destination keeps address", ctx(C.TypeTun, C.ProtocolQUIC, other, "www.example.test", nil), address, address, nil},
		{"different port keeps address", wrongPort, address, address, nil},
		{"address absent from rule lookup keeps address", notResolved, address, address, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeConn := &recordedPacketConn{}
			fakeOutbound := &fakeHysteriaPacketOutbound{conn: fakeConn}
			reports := 0
			conn, err := listenFastPacket(test.ctx, test.destination, fakeOutbound.ListenPacket, func(context.Context, error) {
				reports++
			})
			if test.wantErr != nil {
				if err != test.wantErr {
					t.Fatalf("got error %v, want %v", err, test.wantErr)
				}
				if fakeOutbound.calls != 0 || reports != 0 {
					t.Fatalf("named retry opened a packet conn or reported success: calls=%d reports=%d", fakeOutbound.calls, reports)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if fakeOutbound.dest != test.want {
				t.Fatalf("outbound destination = %v, want %v", fakeOutbound.dest, test.want)
			}
			if reports != 1 {
				t.Fatalf("reports = %d, want 1", reports)
			}
			if test.want == test.destination && conn != fakeConn {
				t.Fatal("unchanged destination unexpectedly wrapped")
			}
			if test.want != test.destination {
				if _, ok := conn.(*fastNamedPacketConn); !ok {
					t.Fatalf("renamed destination returned %T, want fastNamedPacketConn", conn)
				}
			}
		})
	}
}

func TestFastPacketConnRenamesOnlyItsDestinationAndMapsReplies(t *testing.T) {
	original := M.ParseSocksaddrHostPort("2001:db8::10", 443)
	other := M.ParseSocksaddrHostPort("2001:db8::20", 443)
	name := M.ParseSocksaddrHostPort("www.example.test", 443)
	ctx := adapter.WithContext(t.Context(), &adapter.InboundContext{
		InboundType: C.TypeTun, Destination: original, Protocol: C.ProtocolQUIC, Domain: name.Fqdn,
	})
	fakeConn := &recordedPacketConn{}
	fakeOutbound := &fakeHysteriaPacketOutbound{conn: fakeConn}
	conn, err := listenFastPacket(ctx, original, fakeOutbound.ListenPacket, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fakeOutbound.dest != name {
		t.Fatalf("Hysteria2 ListenPacket destination = %v, want %v", fakeOutbound.dest, name)
	}

	if _, err := conn.WriteTo([]byte("one"), original.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("two"), other.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	packetConn, ok := conn.(N.NetPacketConn)
	if !ok {
		t.Fatalf("packet conn has type %T, want N.NetPacketConn", conn)
	}
	for _, destination := range []M.Socksaddr{original, other} {
		buffer := buf.NewPacket()
		_, _ = buffer.Write([]byte("packet"))
		if err := packetConn.WritePacket(buffer, destination); err != nil {
			t.Fatal(err)
		}
	}
	if len(fakeConn.writeTo) != 2 || fakeConn.writeTo[0] != name || fakeConn.writeTo[1] != other {
		t.Fatalf("WriteTo destinations = %v, want [%v %v]", fakeConn.writeTo, name, other)
	}
	if len(fakeConn.writePacket) != 2 || fakeConn.writePacket[0] != name || fakeConn.writePacket[1] != other {
		t.Fatalf("WritePacket destinations = %v, want [%v %v]", fakeConn.writePacket, name, other)
	}

	fakeConn.readFromAddr = name
	_, from, err := conn.ReadFrom(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	if got := M.SocksaddrFromNet(from); got != original {
		t.Fatalf("ReadFrom source = %v, want original %v", got, original)
	}
	fakeConn.readPacketAddr = name
	buffer := buf.NewPacket()
	from, err = packetConn.ReadPacket(buffer)
	buffer.Release()
	if err != nil {
		t.Fatal(err)
	}
	if from != original {
		t.Fatalf("ReadPacket source = %v, want original %v", from, original)
	}

	fakeConn.readFromAddr = other.UDPAddr()
	_, from, err = conn.ReadFrom(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	if got := M.SocksaddrFromNet(from); got != other {
		t.Fatalf("other ReadFrom source = %v, want %v", got, other)
	}
	fakeConn.readPacketAddr = other
	buffer = buf.NewPacket()
	from, err = packetConn.ReadPacket(buffer)
	buffer.Release()
	if err != nil {
		t.Fatal(err)
	}
	if from != other {
		t.Fatalf("other ReadPacket source = %v, want %v", from, other)
	}
}

func TestFastPacketNamingLeavesTCPRequestedNamePathUnchanged(t *testing.T) {
	address := M.ParseSocksaddrHostPort("2001:db8::10", 443)
	name := M.ParseSocksaddrHostPort("www.example.test", 443)
	ctx := adapter.WithContext(t.Context(), &adapter.InboundContext{
		InboundType: C.TypeTun, Destination: address, Protocol: C.ProtocolTLS, Domain: name.Fqdn,
	})
	if got, err := requestedName(ctx, "tcp", address); err != nil || got != name {
		t.Fatalf("TCP requestedName = %v (%v), want %v", got, err, name)
	}
}

// Go builds IPv4 net.IPs in their 16-byte form; they still match the flow.
func TestFastPacketConnMatchesIPv4InIPv6Form(t *testing.T) {
	original := M.ParseSocksaddrHostPort("93.184.216.34", 443)
	name := M.ParseSocksaddrHostPort("www.example.test", 443)
	ctx := adapter.WithContext(t.Context(), &adapter.InboundContext{
		InboundType: C.TypeTun, Destination: original, Protocol: C.ProtocolQUIC, Domain: name.Fqdn,
	})
	fakeConn := &recordedPacketConn{}
	conn, err := listenFastPacket(ctx, original, (&fakeHysteriaPacketOutbound{conn: fakeConn}).ListenPacket, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("one"), &net.UDPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}); err != nil {
		t.Fatal(err)
	}
	buffer := buf.NewPacket()
	_, _ = buffer.Write([]byte("two"))
	mapped := M.SocksaddrFrom(netip.AddrFrom16(original.Addr.As16()), 443)
	if err := conn.(N.NetPacketConn).WritePacket(buffer, mapped); err != nil {
		t.Fatal(err)
	}
	if len(fakeConn.writeTo) != 1 || fakeConn.writeTo[0] != name || len(fakeConn.writePacket) != 1 || fakeConn.writePacket[0] != name {
		t.Fatalf("destinations = %v %v, want %v", fakeConn.writeTo, fakeConn.writePacket, name)
	}
}
