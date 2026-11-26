// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const nextVersion = "0.7.6-alpha"

var desktopTarget = Target{OS: "linux", ABI: "amd64"}

func updateTestDir(t *testing.T) string {
	t.Helper()
	// macOS can put TMPDIR behind the system's /var symlink.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func manifestFor(version string, target Target, body string) string {
	parsed, _ := parseVersion(version)
	return fmt.Sprintf("%s\nversion %s\nchannel %s\n%s %s %s %d %x\n", manifestHeader,
		version, parsed.channel, target.OS, target.ABI, target.filename(), len(body), sha256.Sum256([]byte(body)))
}

func signingKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	key, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer
}

func tlsFixture(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, signer := signingKey(t)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"api.github.com", "github.com", "release-assets.githubusercontent.com"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, key, signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: signer, Leaf: leaf}, pool
}

func TestSignedManifestRejectsUnboundOrAmbiguousEntries(t *testing.T) {
	key, signer := signingKey(t)
	_, wrongSigner := signingKey(t)
	good := manifestFor(nextVersion, desktopTarget, "archive")
	for _, tc := range []struct {
		name   string
		body   string
		signer ed25519.PrivateKey
		target Target
	}{
		{"old signed sums on a new tag", strings.Replace(good, nextVersion, "0.7.5-alpha", 1), signer, desktopTarget},
		{"wrong channel", strings.Replace(good, "channel alpha", "channel beta", 1), signer, desktopTarget},
		{"wrong signer", good, wrongSigner, desktopTarget},
		{"wrong Android ABI", manifestFor(nextVersion, Target{"android", "x86_64"}, "apk"), signer, Target{"android", "arm64-v8a"}},
		{"wrong filename", strings.Replace(good, desktopTarget.filename(), "../archive", 1), signer, desktopTarget},
		{"duplicate target", good + strings.Split(good, "\n")[3] + "\n", signer, desktopTarget},
		{"overlong digest", good[:len(good)-1] + "0000\n", signer, desktopTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			asset, err := verifyManifest(key, body, ed25519.Sign(tc.signer, body), nextVersion, "alpha", tc.target)
			if err == nil || asset.name != "" {
				t.Fatalf("invalid input accepted: %+v %v", asset, err)
			}
		})
	}
	body := []byte(good)
	if a, err := verifyManifest(key, body, ed25519.Sign(signer, body), nextVersion, "alpha", desktopTarget); err != nil || a.length != 7 {
		t.Fatalf("valid manifest rejected: %+v %v", a, err)
	}
}

type releaseFixture struct {
	server *httptest.Server
	key    ed25519.PublicKey
	dial   DialFunc
	client func(context.Context, DialFunc) (releaseClient, *http.Transport)
	mu     sync.Mutex
	calls  []string
	offer  fixtureOffer
}

type fixtureOffer struct {
	version    string
	manifest   string
	prerelease bool
}

func (f *releaseFixture) publish(offer fixtureOffer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offer = offer
}

func (f *releaseFixture) manager(t *testing.T, dir string) *Manager {
	t.Helper()
	m := newManager("0.7.5-alpha", desktopTarget, dir, f.key, asset.checkFile)
	m.makeClient = f.client
	t.Cleanup(m.Close)
	return m
}

type inMemoryListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
}

func (l *inMemoryListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *inMemoryListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *inMemoryListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

func (l *inMemoryListener) dial(ctx context.Context) (net.Conn, error) {
	local, peer := net.Pipe()
	select {
	case l.connections <- peer:
		return local, nil
	case <-ctx.Done():
		local.Close()
		peer.Close()
		return nil, ctx.Err()
	case <-l.closed:
		local.Close()
		peer.Close()
		return nil, net.ErrClosed
	}
}

func fixture(t *testing.T, body, redirect string, assetHandler http.HandlerFunc) *releaseFixture {
	t.Helper()
	key, signer := signingKey(t)
	releaseData := func(tag string, prerelease, draft bool) map[string]any {
		return map[string]any{"tag_name": tag, "prerelease": prerelease, "draft": draft}
	}
	f := &releaseFixture{key: key, offer: fixtureOffer{nextVersion, manifestFor(nextVersion, desktopTarget, body), true}}
	listener := &inMemoryListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Host+r.URL.Path)
		offer := f.offer
		f.mu.Unlock()
		switch r.Host {
		case "api.github.com":
			if r.URL.Path != "/repos/"+repository+"/releases" {
				t.Errorf("unexpected release API path: %s", r.URL.Path)
			}
			base := "https://github.com/" + repository + "/releases/download/v" + offer.version + "/"
			valid := releaseData("v"+offer.version, offer.prerelease, false)
			var assets []map[string]string
			for _, name := range []string{manifestName, signatureName, desktopTarget.filename()} {
				assets = append(assets, map[string]string{"name": name, "browser_download_url": base + name})
			}
			valid["assets"] = assets
			_ = json.NewEncoder(w).Encode([]any{
				releaseData("v0.8.0", false, false), releaseData("v0.8.0-beta", true, false),
				releaseData("v0.7.7-alpha", true, true), valid, releaseData("v0.7.5-alpha", true, false),
			})
		case "github.com":
			switch filepath.Base(r.URL.Path) {
			case signatureName:
				_, _ = w.Write(ed25519.Sign(signer, []byte(offer.manifest)))
			case manifestName:
				_, _ = io.WriteString(w, offer.manifest)
			case desktopTarget.filename():
				http.Redirect(w, r, redirect, http.StatusFound)
			default:
				t.Error("unexpected release asset path")
			}
		case "release-assets.githubusercontent.com":
			assetHandler(w, r)
		default:
			t.Errorf("unexpected destination: %s", r.Host)
		}
	})
	cert, pool := tlsFixture(t)
	f.server = &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler},
		TLS: &tls.Config{Certificates: []tls.Certificate{cert}}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if !AllowedAddress(address) {
			t.Errorf("dial outside release allowlist: %s", address)
			return nil, errRedirect
		}
		return listener.dial(ctx)
	}
	f.client = func(ctx context.Context, dial DialFunc) (releaseClient, *http.Transport) {
		transport := releaseTransport(ctx, dial)
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
		return releaseClient{http: releaseHTTPClient(transport), key: key}, transport
	}
	return f
}

func TestPublishedAlphaAndChannelIsolation(t *testing.T) {
	f := fixture(t, "archive", "", nil)
	const alpha = "0.9.0-alpha"
	f.publish(fixtureOffer{alpha, manifestFor(alpha, desktopTarget, "archive"), false})
	ctx := context.Background()
	c, transport := f.client(ctx, f.dial)
	defer transport.CloseIdleConnections()
	got, err := c.check(ctx, "0.7.5-alpha", desktopTarget, nil)
	if err != nil || got == nil || got.version != alpha {
		t.Fatalf("ordinary published alpha was skipped: %v %v", got, err)
	}
	for _, installed := range []string{"0.8.0", "0.8.0-beta"} {
		if got, err := c.check(ctx, installed, desktopTarget, nil); err != nil || got != nil {
			t.Fatalf("update crossed channels for %s: %v %v", installed, got, err)
		}
	}
}

func TestVerifiedReleaseRejectsRollbackAndManifestSubstitution(t *testing.T) {
	const newer = "0.7.8-alpha"
	const body = "archive"
	for _, tc := range []struct {
		name, version, manifest, message string
	}{
		{"rollback", nextVersion, manifestFor(nextVersion, desktopTarget, body), "older"},
		{"substitution", newer, manifestFor(newer, desktopTarget, body) +
			strings.Split(manifestFor(newer, Target{"linux", "arm64"}, body), "\n")[3] + "\n", "manifest changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t, body, "", nil)
			base := filepath.Join(updateTestDir(t), "updates")
			f.publish(fixtureOffer{newer, manifestFor(newer, desktopTarget, body), true})
			m := f.manager(t, base)
			route := TunnelRoute(context.Background(), f.dial)
			m.Check(route, false)
			waitStatus(t, m, "available")
			m.Close()
			restarted := f.manager(t, base)
			f.publish(fixtureOffer{tc.version, tc.manifest, true})
			restarted.Check(route, false)
			if st := waitStatus(t, restarted, "error"); st.Version != newer || !strings.Contains(st.Error, tc.message) {
				t.Fatalf("lost the authenticated offer: %+v", st)
			}
		})
	}
}

func TestDownloadRefreshPersistsNewerOfferWithoutDownloadingIt(t *testing.T) {
	const newer = "0.7.8-alpha"
	const body = "verified bytes"
	f := fixture(t, body, "", func(http.ResponseWriter, *http.Request) {
		t.Error("downloaded an update before a new user decision")
	})
	base := filepath.Join(updateTestDir(t), "updates")
	m := f.manager(t, base)
	route := TunnelRoute(context.Background(), f.dial)
	m.Check(route, false)
	waitStatus(t, m, "available")
	f.publish(fixtureOffer{newer, manifestFor(newer, desktopTarget, body), false})
	m.Download(route)
	if st := waitStatus(t, m, "available"); st.Version != newer || st.Artifact != "" {
		t.Fatalf("download did not offer the newly verified release: %+v", st)
	}
	if restored := f.manager(t, base).Status(); restored.Version != newer || restored.State != "available" {
		t.Fatalf("new offer was not saved: %+v", restored)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 6 {
		t.Fatalf("unexpected requests during recheck: %v", f.calls)
	}
}

func TestSavedOfferIsScopedAndReverified(t *testing.T) {
	f := fixture(t, "archive", "", nil)
	base := filepath.Join(updateTestDir(t), "updates")
	m := f.manager(t, base)
	route := TunnelRoute(context.Background(), f.dial)
	m.Check(route, false)
	waitStatus(t, m, "available")
	for _, tc := range []struct {
		installed string
		target    Target
	}{
		{"0.7.5", desktopTarget},
		{"0.7.5-alpha", Target{OS: "linux", ABI: "arm64"}},
	} {
		other := newManager(tc.installed, tc.target, base, f.key, asset.checkFile)
		t.Cleanup(other.Close)
		if st := other.Status(); st.State != "idle" || st.CheckedAt != nil || st.Version != "" {
			t.Fatalf("saved state crossed its channel or target: %+v", st)
		}
	}
	restarted := f.manager(t, base)
	restarted.Download(DirectRoute())
	if st := waitStatus(t, restarted, "error"); st.Error != ErrTunnelStopped.Error() {
		t.Fatalf("restart lost the offer's tunnel requirement: %+v", st)
	}
	path := filepath.Join(base, m.stateFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state storedUpdate
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Release.Signature[0] ^= 1
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if st := f.manager(t, base).Status(); st.State != "error" || st.Version != "" || st.Artifact != "" {
		t.Fatalf("restored an unauthenticated offer: %+v", st)
	}
}

func waitStatus(t *testing.T, m *Manager, want string) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := m.Status()
		if got.State == want {
			return got
		}
		if got.State != "checking" && got.State != "downloading" {
			t.Fatalf("want %s, got %+v", want, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("want %s, got %+v", want, m.Status())
	return Status{}
}

func TestQueuedUpdateResolvesRouteAfterRestore(t *testing.T) {
	for _, action := range []string{"check", "download"} {
		t.Run(action, func(t *testing.T) {
			f := savedAPK(t)
			connected := make(chan struct{})
			m := newManager("0.7.5-alpha", f.target, f.dir, f.key, func(_ asset, ctx context.Context, _, _ string) bool {
				select {
				case <-connected:
				case <-ctx.Done():
				}
				return false // stage needs to be downloaded again
			})
			t.Cleanup(m.Close)
			dialed := make(chan string, 1)
			resolve := func() Route {
				select {
				case <-m.restored:
				default:
					t.Error("selected a route before startup verification completed")
					return UnavailableRoute(errors.New("disconnected fixture route"))
				}
				return TunnelRoute(t.Context(), func(_ context.Context, _, address string) (net.Conn, error) {
					dialed <- address
					return nil, ErrTunnelUnavailable
				})
			}
			if action == "check" {
				m.CheckWithRoute(resolve, false)
			} else {
				m.DownloadWithRoute(resolve)
			}
			close(connected)
			if st := waitStatus(t, m, "error"); st.Error != ErrTunnelUnavailable.Error() {
				t.Fatalf("queued %s did not use the new tunnel: %+v", action, st)
			}
			select {
			case addr := <-dialed:
				if addr != "api.github.com:443" {
					t.Fatalf("tunnel dialed %q", addr)
				}
			default:
				t.Fatal("queued update did not reach the tunnel dialer")
			}
		})
	}
}

func TestCancelDirectAbortsDirectDialAndPreservesTunnel(t *testing.T) {
	for _, tunneled := range []bool{false, true} {
		name := "direct"
		if tunneled {
			name = "tunnel"
		}
		t.Run(name, func(t *testing.T) {
			m := NewManager("0.7.5-alpha", desktopTarget, filepath.Join(updateTestDir(t), "updates"))
			t.Cleanup(m.Close)
			dialing := make(chan context.Context, 1)
			finish := make(chan struct{})
			dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialing <- ctx
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-finish:
					return nil, ErrTunnelUnavailable
				}
			}
			route := Route{dial: dial}
			if tunneled {
				route = TunnelRoute(t.Context(), dial)
			}
			if st := m.Check(route, false); st.State != "checking" {
				t.Fatalf("check did not start: %+v", st)
			}
			var dialCtx context.Context
			select {
			case dialCtx = <-dialing:
			case <-time.After(time.Second):
				t.Fatal("update did not reach the dialer")
			}
			m.CancelDirect()
			want := errUpdateCancelled
			if tunneled {
				if err := dialCtx.Err(); err != nil {
					t.Fatalf("CancelDirect cancelled a tunnel dial: %v", err)
				}
				close(finish)
				want = ErrTunnelUnavailable
			} else if !errors.Is(dialCtx.Err(), context.Canceled) {
				t.Fatal("the direct dial was not cancelled when CancelDirect returned")
			}
			if st := waitStatus(t, m, "error"); st.Error != want.Error() || !tunneled && st.CheckedAt != nil {
				t.Fatalf("wrong status after CancelDirect: %+v", st)
			}
		})
	}
}

func TestCancelDirectCoversRouteResolution(t *testing.T) {
	m := NewManager("0.7.5-alpha", desktopTarget, filepath.Join(updateTestDir(t), "updates"))
	t.Cleanup(m.Close)
	resolving, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	m.CheckWithRoute(func() Route {
		close(resolving)
		<-release
		return Route{dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("a direct dial started after cancellation")
			return nil, ErrTunnelUnavailable
		}}
	}, false)
	select {
	case <-resolving:
	case <-time.After(time.Second):
		t.Fatal("route resolver was not called")
	}
	m.CancelDirect()
	unblock()
	if st := waitStatus(t, m, "error"); st.Error != errUpdateCancelled.Error() {
		t.Fatalf("a cancelled direct route was used: %+v", st)
	}
}

func TestReleaseCheckDownloadAndPersistentSchedule(t *testing.T) {
	const body = "verified archive"
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	f := fixture(t, body, "https://release-assets.githubusercontent.com/download", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	base := filepath.Join(updateTestDir(t), "updates")
	m := f.manager(t, base)
	m.Check(TunnelRoute(ctx, f.dial), false)
	if st := waitStatus(t, m, "available"); st.Version != nextVersion || st.Artifact != "" {
		t.Fatalf("invalid available status: %+v", st)
	}
	m.Close()
	m = f.manager(t, base)
	if st := m.Check(Route{}, true); st.State != "available" || st.CheckedAt == nil || st.Version != nextVersion {
		t.Errorf("daily check and verified offer did not survive restart: %+v", st)
	}
	if _, err := m.Resolve("../" + desktopTarget.filename()); err == nil {
		t.Fatal("resolved an unverified artifact")
	}
	m.Download(TunnelRoute(ctx, f.dial))
	st := waitStatus(t, m, "ready")
	m.Close()
	ready := f.manager(t, base)
	waitRestore(t, ready)
	if restored := ready.Status(); restored.State != "ready" || restored.Artifact != st.Artifact {
		t.Errorf("ready artifact did not survive restart: %+v", restored)
	}
	path, err := ready.Resolve(st.Artifact)
	if err != nil || st.Artifact == "" || strings.Contains(path, ".download") || filepath.Base(path) != desktopTarget.filename() {
		t.Fatalf("invalid handoff for %+v: %s %v", st, path, err)
	}
	data, err := os.ReadFile(path)
	if string(data) != body || err != nil {
		t.Fatalf("handoff bytes: %q %v", data, err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", len(body))), 0600); err != nil {
		t.Fatal(err)
	}
	ready.Close()
	tampered := f.manager(t, base)
	waitRestore(t, tampered)
	if restored := tampered.Status(); restored.State != "available" || restored.Version != nextVersion || restored.Artifact != "" {
		t.Errorf("tampered file did not fall back to the verified offer: %+v", restored)
	}
	if _, err := tampered.Resolve(st.Artifact); err == nil {
		t.Fatal("a changed file remained eligible for handoff")
	}
	if saved, err := readStoredUpdate(filepath.Join(base, tampered.stateFile)); err != nil || saved.Artifact != "" {
		t.Fatalf("the invalid handle remained in saved state: %q, %v", saved.Artifact, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 8 || !strings.HasPrefix(f.calls[7], "release-assets.githubusercontent.com/") {
		t.Fatalf("unexpected tunnel requests: %v", f.calls)
	}
}

func TestInvalidBytesAndRedirectCannotReachHandoff(t *testing.T) {
	const good = "verified archive"
	for _, tc := range []struct {
		name, body, redirect string
	}{
		{"wrong length", "short", "https://release-assets.githubusercontent.com/download"},
		{"wrong hash", strings.Repeat("x", len(good)), "https://release-assets.githubusercontent.com/download"},
		{"foreign redirect", good, "https://other.example/download"},
		{"HTTPS downgrade", good, "http://release-assets.githubusercontent.com/download"},
		{"unapproved port", good, "https://release-assets.githubusercontent.com:444/download"},
		{"wrong TLS identity at an approved host", good, "https://objects.githubusercontent.com/download"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t, good, tc.redirect, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			})
			base := filepath.Join(updateTestDir(t), "updates")
			m := f.manager(t, base)
			route := TunnelRoute(context.Background(), f.dial)
			m.Check(route, false)
			waitStatus(t, m, "available")
			m.Download(route)
			st := waitStatus(t, m, "error")
			files, err := os.ReadDir(base)
			if st.Artifact != "" || err != nil || len(files) != 2 || files[0].Name() != stateLockFilename || files[1].Name() != m.stateFile {
				t.Fatalf("unverified download escaped staging: %+v %v %v", st, files, err)
			}
		})
	}
}

func TestTunnelDropStopsDownloadWithoutDirectRetry(t *testing.T) {
	const body = "verified archive"
	started := make(chan struct{})
	f := fixture(t, body, "https://release-assets.githubusercontent.com/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = io.WriteString(w, body[:1])
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	})
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	m := f.manager(t, filepath.Join(updateTestDir(t), "updates"))
	route := TunnelRoute(ctx, f.dial)
	m.Check(route, false)
	waitStatus(t, m, "available")
	m.Download(route)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("asset transfer never started")
	}
	stop()
	if st := waitStatus(t, m, "error"); st.Artifact != "" || st.Error != ErrTunnelStopped.Error() {
		t.Fatalf("tunnel failure left a handoff: %+v", st)
	}
	m.Download(DirectRoute())
	if st := waitStatus(t, m, "error"); st.Error != ErrTunnelStopped.Error() || st.Artifact != "" {
		t.Fatalf("a disconnected retry started a direct download: %+v", st)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 8 {
		t.Fatalf("after tunnel stop, requests = %v", f.calls)
	}
}

func TestVersionOrderingAndRollback(t *testing.T) {
	order := []string{"0.7.5-alpha", "0.7.5-alpha.2", "0.7.5-alpha.10", "0.7.5", "0.7.10-alpha"}
	for i := 1; i < len(order); i++ {
		a, _ := parseVersion(order[i-1])
		b, _ := parseVersion(order[i])
		if a.compare(b) != -1 {
			t.Fatalf("incorrect release order %s, %s", order[i-1], order[i])
		}
	}
	f := fixture(t, "archive", "https://release-assets.githubusercontent.com/download", func(http.ResponseWriter, *http.Request) {
		t.Error("rollback attempted an asset request")
	})
	c, transport := f.client(t.Context(), f.dial)
	defer transport.CloseIdleConnections()
	candidate, err := c.check(context.Background(), nextVersion, desktopTarget, nil)
	f.mu.Lock()
	defer f.mu.Unlock()
	if candidate != nil || err != nil || !slices.Equal(f.calls, []string{"api.github.com/repos/" + repository + "/releases"}) {
		t.Fatalf("rollback rejected incorrectly: %v %v %v", candidate, err, f.calls)
	}
	if err := (&Manager{}).run(t.Context(), UnavailableRoute(ErrTunnelUnavailable), time.Second, nil); !errors.Is(err, ErrTunnelUnavailable) {
		t.Fatalf("unavailable route did not fail closed: %v", err)
	}
}
