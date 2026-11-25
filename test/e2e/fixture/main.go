// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("use cert, serve or fetch-http3")
	}
	switch os.Args[1] {
	case "cert":
		if len(os.Args) != 4 {
			log.Fatal("use cert CA_DIR HOST")
		}
		if err := issue(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
	case "serve":
		serve(os.Args[2:])
	case "fetch-http3":
		if len(os.Args) != 5 {
			log.Fatal("use fetch-http3 ADDRESS URL TRUST_FILE")
		}
		if err := fetchHTTP3(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("unknown fixture command")
	}
}

func issue(dir, host string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	now := time.Now()
	rootCert, rootKey := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if _, err := os.Stat(rootCert); errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		root := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Pipe E2E CA"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		}
		if _, err := writePair(rootCert, rootKey, root, root, key, key); err != nil {
			return err
		}
	}
	ca, err := tls.LoadX509KeyPair(rootCert, rootKey)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{host}
	}
	leaf, err := writePair(filepath.Join(dir, host+".pem"), filepath.Join(dir, host+"-key.pem"), cert, ca.Leaf, key, ca.PrivateKey)
	if err != nil {
		return err
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	fmt.Println("sha256//" + base64.StdEncoding.EncodeToString(pin[:]))
	return nil
}

func writePair(certFile, keyFile string, cert, issuer *x509.Certificate, key *ecdsa.PrivateKey, issuerKey any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func serve(args []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := flags.String("listen", "", "TLS address")
	httpListen := flags.String("http", "", "optional HTTP listener")
	certDir := flags.String("ca", "", "fixture certificate directory")
	host := flags.String("host", "", "certificate name")
	site := flags.String("body", "", "response body")
	state := flags.String("state", "", "Pipe server.json for the Rescue route")
	backend := flags.String("rescue", "", "private Rescue address")
	_ = flags.Parse(args)
	rescue := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&url.URL{Scheme: "http", Host: *backend})
			r.Out.Host = r.In.Host
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *state != "" {
			var settings struct {
				Path string `json:"ws_path"`
			}
			data, err := os.ReadFile(*state)
			if err == nil && json.Unmarshal(data, &settings) == nil && settings.Path == r.URL.EscapedPath() {
				rescue.ServeHTTP(w, r)
				return
			}
		}
		if r.Header.Get("Proxy-Authorization") != "" {
			http.Error(w, "proxy credentials reached the target", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, *site)
	})
	tlsListener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if *httpListen != "" {
		listener, err := net.Listen("tcp", *httpListen)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Fatal((&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(listener))
		}()
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}},
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(*certDir, *host+".pem"), filepath.Join(*certDir, *host+"-key.pem"))
	if err != nil {
		log.Fatal(err)
	}
	server.TLSConfig.Certificates = []tls.Certificate{certificate}
	fmt.Println("TLS fixture ready")
	log.Fatal(server.ServeTLS(tlsListener, "", ""))
}
