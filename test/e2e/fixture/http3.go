// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

func fetchHTTP3(address, url, trustFile, host string) error {
	certificate, err := os.ReadFile(trustFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		// Shared Fast stores its self-signed certificate in DER form.
		cert, err := x509.ParseCertificate(certificate)
		if err != nil {
			return err
		}
		roots.AddCert(cert)
	}
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, address, tlsConfig, config)
		},
	}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if host != "" {
		request.Host = host
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ProtoMajor != 3 || response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP/3 fixture received %s %s", response.Proto, response.Status)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("HTTP/3 fixture received no TLS certificate")
	}
	leaf := response.TLS.PeerCertificates[0]
	if len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 0 || !strings.EqualFold(leaf.DNSNames[0], request.URL.Hostname()) {
		return fmt.Errorf("HTTP/3 fixture received the wrong certificate identity for %s", request.URL.Hostname())
	}
	_, err = io.Copy(os.Stdout, response.Body)
	return err
}
