// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"pipe/internal/localfile"
)

const (
	cliInstalled = "0.7.5-alpha"
	cliPayload   = "the signed staging fixture"
)

func writeOfflineRelease(t *testing.T, dir, ver, body string, signer ed25519.PrivateKey) string {
	t.Helper()
	archive := filepath.Join(dir, desktopTarget.Filename())
	manifest := []byte(manifestFor(ver, desktopTarget, body))
	writeFixtureFile(t, archive, []byte(body))
	writeFixtureFile(t, filepath.Join(dir, manifestName), manifest)
	writeFixtureFile(t, filepath.Join(dir, signatureName), ed25519.Sign(signer, manifest))
	return archive
}

func writeFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func offlineOptions(t *testing.T, dir string, key ed25519.PublicKey) ResolveOptions {
	t.Helper()
	return ResolveOptions{Installed: cliInstalled, Target: desktopTarget, From: dir, Key: key,
		Route: Route{dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("offline resolution attempted a network dial")
			return nil, errors.New("unexpected network request")
		}},
	}
}

func TestResolveOfflineStagesVerifiedCopy(t *testing.T) {
	for _, mode := range []string{"directory", "archive"} {
		t.Run(mode, func(t *testing.T) {
			key, signer := signingKey(t)
			dir := updateTestDir(t)
			archive := writeOfflineRelease(t, dir, nextVersion, cliPayload, signer)
			opts := offlineOptions(t, dir, key)
			opts.StateDir = filepath.Join(updateTestDir(t), "state")
			if mode == "archive" {
				opts.From, opts.CheckOnly = archive, true
			}
			offer, err := Resolve(t.Context(), opts)
			if err != nil || offer.Cleanup == nil {
				t.Fatalf("resolve offline: %v", err)
			}
			t.Cleanup(offer.Cleanup)
			if offer.Current || offer.StateUnverified || offer.Version != nextVersion || offer.Channel != "alpha" ||
				offer.AssetName != desktopTarget.Filename() || offer.AssetSize != int64(len(cliPayload)) ||
				offer.SHA256 != sha256.Sum256([]byte(cliPayload)) {
				t.Fatalf("unexpected release metadata: %+v", offer)
			}
			stage := filepath.Dir(offer.ArchivePath)
			if filepath.Dir(stage) != opts.StateDir || !strings.HasPrefix(filepath.Base(stage), cliStagePrefix) {
				t.Fatalf("unexpected staging directory: %q", stage)
			}
			if err := inspectPrivateDir(stage, false); err != nil {
				t.Fatal(err)
			}
			manager := newManager(cliInstalled, desktopTarget, opts.StateDir, key, asset.checkFile)
			defer manager.Close()
			waitRestore(t, manager)
			if manager.Status().Version != nextVersion {
				t.Fatalf("manager did not restore the CLI floor: %+v", manager.Status())
			}
			if err := os.Rename(archive, archive+".old"); err != nil {
				t.Fatal(err)
			}
			writeFixtureFile(t, archive, []byte("replacement"))
			writeFixtureFile(t, archive+".old", []byte("edited original"))
			if body, err := os.ReadFile(offer.ArchivePath); err != nil || string(body) != cliPayload {
				t.Fatalf("verified copy changed: %q, %v", body, err)
			}
			offer.Cleanup()
			if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staging directory survived cleanup: %v", err)
			}
		})
	}
}

func TestResolveOfflineLoneArchiveRequiresVerifiedFloor(t *testing.T) {
	key, signer := signingKey(t)
	dir := updateTestDir(t)
	archive := writeOfflineRelease(t, dir, nextVersion, cliPayload, signer)
	opts := offlineOptions(t, archive, key)
	opts.StateDir = filepath.Join(updateTestDir(t), "state")
	first, err := Resolve(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	first.Cleanup()
	if err := os.Remove(filepath.Join(dir, manifestName)); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve(t.Context(), opts); err == nil || !strings.Contains(err.Error(), manifestName) || got.ArchivePath != "" {
		got.Cleanup()
		t.Fatalf("incomplete sidecars were accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, signatureName)); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(t.Context(), opts)
	if err != nil || got.Version != nextVersion || got.ArchivePath == "" {
		t.Fatalf("saved manifest could not authenticate lone archive: %v", err)
	}
	got.Cleanup()
	ops := opts
	ops.StateDir = ""
	got, err = Resolve(t.Context(), ops)
	got.Cleanup()
	if err == nil || !strings.Contains(err.Error(), "open "+manifestName+":") || !strings.Contains(err.Error(), "open "+signatureName+":") {
		t.Fatalf("missing sidecars were not both named: %v", err)
	}
	state := filepath.Join(opts.StateDir, stateFilename("alpha", opts.Target))
	writeFixtureFile(t, state, []byte(`null`))
	got, err = Resolve(t.Context(), opts)
	got.Cleanup()
	if !errors.Is(err, errStateRead) {
		t.Fatalf("corrupt floor was accepted: %v", err)
	}
}

func TestResolveOfflineRejectsCorruptInputs(t *testing.T) {
	key, signer := signingKey(t)
	for _, tc := range []struct {
		name, file string
		data       []byte
		want       string
	}{
		{"manifest altered", manifestName, []byte(manifestFor(nextVersion, desktopTarget, "different signed bytes")), "signature is invalid"},
		{"manifest too large", manifestName, make([]byte, maxManifest+1), manifestName + " exceeds"},
		{"signature altered", signatureName, make([]byte, ed25519.SignatureSize), "signature is invalid"},
		{"signature truncated", signatureName, make([]byte, ed25519.SignatureSize-1), signatureName + " must contain exactly"},
		{"signature missing", signatureName, nil, "open " + signatureName + ":"},
		{"archive truncated", desktopTarget.Filename(), []byte("short"), "does not match"},
		{"archive enlarged", desktopTarget.Filename(), []byte(cliPayload + "!"), "does not match"},
		{"archive hash mismatch", desktopTarget.Filename(), []byte(strings.Repeat("x", len(cliPayload))), "does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := updateTestDir(t)
			writeOfflineRelease(t, dir, nextVersion, cliPayload, signer)
			path := filepath.Join(dir, tc.file)
			if tc.data == nil {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFixtureFile(t, path, tc.data)
			}
			opts := offlineOptions(t, dir, key)
			opts.StateDir = filepath.Join(updateTestDir(t), "state")
			got, err := Resolve(t.Context(), opts)
			got.Cleanup()
			if err == nil || !strings.Contains(err.Error(), tc.want) || got.ArchivePath != "" {
				t.Fatalf("unexpected verification result: %v", err)
			}
			entries, err := os.ReadDir(opts.StateDir)
			if (!errors.Is(err, os.ErrNotExist) && err != nil) || len(entries) != 0 {
				t.Fatalf("invalid input left a floor or stage: %v, %v", entries, err)
			}
		})
	}
}

func TestResolveOfflineRejectsSourceSymlinks(t *testing.T) {
	key, signer := signingKey(t)
	for _, name := range []string{manifestName, signatureName, desktopTarget.Filename()} {
		t.Run(name, func(t *testing.T) {
			dir := updateTestDir(t)
			archive := writeOfflineRelease(t, dir, nextVersion, cliPayload, signer)
			path := filepath.Join(dir, name)
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("Windows symlink privilege is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			from := dir
			if name == desktopTarget.Filename() {
				from = archive
			}
			got, err := Resolve(t.Context(), offlineOptions(t, from, key))
			got.Cleanup()
			if err == nil || !strings.Contains(err.Error(), name) || got.ArchivePath != "" {
				t.Fatalf("symlink was accepted: %v", err)
			}
		})
	}
}

func TestOfflineSourcePinsDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows retains the directory handle and prevents its rename")
	}
	dir := updateTestDir(t)
	name := desktopTarget.Filename()
	writeFixtureFile(t, filepath.Join(dir, name), []byte(cliPayload))
	source, err := openLocalSourceDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := os.Rename(dir, dir+"-moved"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir + "-moved") })
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(dir, name), []byte("replacement"))
	f, _, err := source.OpenRegular(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if body, err := io.ReadAll(f); err != nil || string(body) != cliPayload {
		t.Fatalf("read escaped the pinned source directory: %q, %v", body, err)
	}
}

func TestResolveOfflineEnforcesNewestAndFloor(t *testing.T) {
	key, signer := signingKey(t)
	dir := updateTestDir(t)
	opts := offlineOptions(t, dir, key)
	opts.StateDir = filepath.Join(updateTestDir(t), "state")
	ops := opts
	ops.Newest = "0.7.7-alpha"
	writeOfflineRelease(t, dir, nextVersion, cliPayload, signer)
	got, err := Resolve(t.Context(), ops)
	got.Cleanup()
	if err == nil || !strings.Contains(err.Error(), "older than an installed copy") {
		t.Fatalf("candidate below the newest installed copy was accepted: %v", err)
	}
	opts.Newest = nextVersion
	got, err = Resolve(t.Context(), opts)
	got.Cleanup()
	if err != nil || got.Current || got.Version != nextVersion {
		t.Fatalf("matching the newest copy should upgrade the oldest: %+v, %v", got, err)
	}
	for _, tc := range []struct {
		ver  string
		want error
	}{{cliInstalled, errOlderRelease}, {nextVersion, errChangedManifest}} {
		writeOfflineRelease(t, dir, tc.ver, "separately signed fixture", signer)
		got, err := Resolve(t.Context(), opts)
		got.Cleanup()
		if !errors.Is(err, tc.want) {
			t.Fatalf("rollback/substitution at %s: got %v, want %v", tc.ver, err, tc.want)
		}
	}
}

func TestStagedReleaseVerifyFloor(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		want          error
	}{
		{"newer recorded offer", "0.7.7-alpha", errOlderRelease},
		{"same version with a different manifest", nextVersion, errChangedManifest},
		{"invalid recorded signature", nextVersion, errStateRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, signer := signingKey(t)
			dir := updateTestDir(t)
			writeOfflineRelease(t, dir, nextVersion, cliPayload, signer)
			opts := offlineOptions(t, dir, key)
			opts.StateDir = filepath.Join(updateTestDir(t), "state")
			staged, err := Resolve(t.Context(), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer staged.Cleanup()
			if err := staged.VerifyFloor(); err != nil {
				t.Fatalf("fresh stage did not match the persisted floor: %v", err)
			}

			body := []byte(manifestFor(tc.version, opts.Target, "another archive"))
			signed := signedRelease{Tag: "v" + tc.version, Manifest: body, Signature: ed25519.Sign(signer, body), Digest: sha256.Sum256(body)}
			if tc.want == errStateRead {
				signed.Signature[0] ^= 1
			}
			raw, err := json.Marshal(storedUpdate{Release: &signed})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(opts.StateDir, stateFilename("alpha", opts.Target))
			if err := localfile.WritePrivateAtomicSyncDir(path, raw); err != nil {
				t.Fatal(err)
			}
			if err := staged.VerifyFloor(); !errors.Is(err, tc.want) {
				t.Fatalf("VerifyFloor got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResolveOfflineCurrentStillVerifiesArchive(t *testing.T) {
	key, signer := signingKey(t)
	dir := updateTestDir(t)
	archive := writeOfflineRelease(t, dir, cliInstalled, cliPayload, signer)
	opts := offlineOptions(t, dir, key)
	opts.CheckOnly, opts.ReadOnlyState = true, true
	opts.StateDir = filepath.Join(updateTestDir(t), "state")
	got, err := Resolve(t.Context(), opts)
	got.Cleanup()
	if err != nil || !got.Current || got.ArchivePath != "" {
		t.Fatalf("unexpected current release: %+v, %v", got, err)
	}
	if _, err := os.Stat(opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only check touched persistent state: %v", err)
	}
	writeFixtureFile(t, archive, []byte("tampered"))
	got, err = Resolve(t.Context(), opts)
	got.Cleanup()
	if !errors.Is(err, errAssetMismatch) {
		t.Fatalf("current release did not validate supplied archive: %v", err)
	}
}

func TestResolveValidatesInstalledAndTarget(t *testing.T) {
	for _, opts := range []ResolveOptions{
		{Installed: "bad", Target: desktopTarget},
		{Installed: cliInstalled, Target: Target{OS: "linux", ABI: "unsupported"}},
		{Installed: cliInstalled, Newest: "bad", Target: desktopTarget},
		{Installed: cliInstalled, Newest: "0.8.0-beta", Target: desktopTarget},
		{Installed: cliInstalled, Newest: "0.7.4-alpha", Target: desktopTarget},
	} {
		got, err := Resolve(t.Context(), opts)
		if err == nil || errors.Is(err, ErrTunnelUnavailable) || got.Cleanup == nil {
			t.Fatalf("invalid input reached discovery: %+v, %v", opts, err)
		}
		got.Cleanup()
	}
}

func TestResolveOnlineCheckAndDownload(t *testing.T) {
	for _, check := range []bool{true, false} {
		t.Run(fmt.Sprintf("check=%t", check), func(t *testing.T) {
			var payloadRequests atomic.Int32
			var state releaseState
			f := fixture(t, cliPayload, "https://release-assets.githubusercontent.com/archive", func(w http.ResponseWriter, _ *http.Request) {
				payloadRequests.Add(1)
				if floor, err := state.load(); err != nil || floor == nil || floor.version != nextVersion {
					t.Errorf("download began before the signed offer was saved: %v", err)
				}
				_, _ = io.WriteString(w, cliPayload)
			})
			state = releaseState{dir: filepath.Join(updateTestDir(t), "state"), channel: "alpha", target: desktopTarget, key: f.key}
			opts := ResolveOptions{Installed: cliInstalled, Newest: nextVersion, Target: desktopTarget, StateDir: state.dir,
				Route: Route{dial: f.dial}, CheckOnly: check, Key: f.key}
			got, err := resolveWithTransport(t.Context(), opts, func(ctx context.Context, route Route) *http.Transport {
				_, transport := f.client(ctx, route.dial)
				return transport
			})
			defer got.Cleanup()
			if err != nil || got.Current || got.Version != nextVersion || got.SHA256 != sha256.Sum256([]byte(cliPayload)) {
				t.Fatalf("unexpected online offer: %+v, %v", got, err)
			}
			if floor, err := state.load(); err != nil || floor == nil || floor.version != nextVersion {
				t.Fatalf("verified online offer was lost: %v", err)
			}
			if check {
				if got.ArchivePath != "" || payloadRequests.Load() != 0 {
					t.Fatal("metadata check downloaded an archive")
				}
			} else if body, err := os.ReadFile(got.ArchivePath); err != nil || string(body) != cliPayload || payloadRequests.Load() != 1 {
				t.Fatalf("online download did not stage the signed archive: %v", err)
			}
		})
	}
}

func TestResolveSharesFloorWithManager(t *testing.T) {
	key, signer := signingKey(t)
	state := releaseState{dir: filepath.Join(updateTestDir(t), "state"), channel: "alpha", target: desktopTarget, key: key}
	dir := updateTestDir(t)
	image := linuxFixtureImage("amd64", nextVersion, 1)
	archive := linuxFixtureArchive(t, image, nil, "")
	writeOfflineRelease(t, dir, nextVersion, string(archive), signer)
	opts := offlineOptions(t, dir, key)
	opts.StateDir = state.dir
	got, err := Resolve(t.Context(), opts)
	got.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	old, err := state.load()
	if err != nil || old == nil {
		t.Fatalf("initial floor could not be loaded: %v", err)
	}
	handle := rand.Text()
	stage := filepath.Join(state.dir, handle)
	if err := privateDir(stage); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(stage, desktopTarget.Filename()), archive)
	if err := state.save(t.Context(), old, storedUpdate{Artifact: handle}, false); err != nil {
		t.Fatal(err)
	}
	m := newManager(cliInstalled, desktopTarget, state.dir, key, asset.checkFile)
	defer m.Close()
	waitRestore(t, m)
	f, _, cleanup, err := m.ExtractVerifiedLinuxBinary(handle)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(f); err != nil || !bytes.Equal(body, image) {
		t.Fatalf("desktop extraction did not use the signed bytes: %v", err)
	}
	cleanup()
	const newer = "0.7.7-alpha"
	writeOfflineRelease(t, dir, newer, "new signed release", signer)
	got, err = Resolve(t.Context(), opts)
	got.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(handle); !errors.Is(err, errOlderRelease) {
		t.Fatalf("desktop revealed a stage below the CLI floor: %v", err)
	}
	if _, _, discard, err := m.ExtractVerifiedLinuxBinary(handle); !errors.Is(err, errOlderRelease) {
		if discard != nil {
			discard()
		}
		t.Fatalf("desktop extracted a stage below the CLI floor: %v", err)
	}
	m.mu.Lock()
	err = m.save(old, artifact{handle: handle}, false)
	m.mu.Unlock()
	if !errors.Is(err, errOlderRelease) {
		t.Fatalf("stale manager write replaced the shared floor: %v", err)
	}
}

func TestResolveReadOnlyUnreadableState(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("fixture requires an unprivileged Unix user")
	}
	key, signer := signingKey(t)
	dir := updateTestDir(t)
	writeOfflineRelease(t, dir, nextVersion, cliPayload, signer)
	opts := offlineOptions(t, dir, key)
	opts.StateDir, opts.ReadOnlyState, opts.CheckOnly = updateTestDir(t), true, true
	if err := os.Chmod(opts.StateDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(opts.StateDir, 0700) })
	got, err := Resolve(t.Context(), opts)
	got.Cleanup()
	if err != nil || !got.StateUnverified || got.Version != nextVersion {
		t.Fatalf("read-only preview with inaccessible state: %+v, %v", got, err)
	}
	opts.ReadOnlyState = false
	got, err = Resolve(t.Context(), opts)
	got.Cleanup()
	if !errors.Is(err, errStateRead) {
		t.Fatalf("writable resolve accepted inaccessible state: %v", err)
	}
}

func TestProxyRouteValidationAndRedaction(t *testing.T) {
	for _, tc := range []struct{ raw, address, scheme string }{
		{"http://proxy.example", "proxy.example:80", "http"},
		{"HTTPS://proxy.example:8443/", "proxy.example:8443", "https"},
		{"socks5://[::1]", "[::1]:1080", "socks5"},
		{"socks5h://name:p%40ss@proxy.example", "proxy.example:1080", "socks5h"},
	} {
		route, err := ProxyRoute(tc.raw)
		if err != nil || route.proxyAddr != tc.address || route.proxyURL.Scheme != tc.scheme {
			t.Errorf("proxy route for %s: %v", tc.address, err)
		}
	}
	for i, raw := range []string{
		"ftp://user:fixture-secret@proxy.example",
		"http://user:fixture-secret@",
		"http://user:fixture-secret@proxy.example:0",
		"http://user:fixture-secret@proxy.example:70000",
		"http://user:fixture-secret@proxy.example:",
		"http://user:fixture-secret@proxy.example/path",
		"http://user:fixture-secret@proxy.example?query",
		"http://user:fixture-secret@proxy.example#fragment",
		"http://user:fixture-secret@proxy.example:%xx",
		"  ",
	} {
		if _, err := ProxyRoute(raw); err == nil || strings.Contains(err.Error(), "fixture-secret") {
			t.Errorf("invalid proxy case %d leaked credentials or succeeded: %v", i, err)
		}
	}
}

func TestEnvProxyRoutePinsReleaseAPIChoice(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "proxy.example:8080")
	t.Setenv("no_proxy", "")
	t.Setenv("NO_PROXY", "github.com")
	route, err := EnvProxyRoute()
	if err != nil || route.proxyURL != nil {
		t.Fatal("the release API should bypass the environment proxy")
	}
	t.Setenv("NO_PROXY", "release-assets.githubusercontent.com")
	route, err = EnvProxyRoute()
	if err != nil || route.proxyAddr != "proxy.example:8080" {
		t.Fatalf("environment proxy not selected for the release API: %v", err)
	}
	transport := releaseTransportForRoute(t.Context(), route)
	for _, destination := range []string{releases, "https://release-assets.githubusercontent.com/archive"} {
		req, err := http.NewRequest(http.MethodGet, destination, nil)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := transport.Proxy(req)
		if err != nil || proxy != route.proxyURL {
			t.Fatalf("pinned proxy changed for %s: %v", destination, err)
		}
	}
	t.Setenv("HTTPS_PROXY", "http://name:fixture-secret@[")
	if _, err := EnvProxyRoute(); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("invalid proxy environment did not fail safely: %v", err)
	}
}

func TestProxyTransportChecksDestinationAndRedactsErrors(t *testing.T) {
	route, err := ProxyRoute("http://name:fixture-secret@proxy.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	addresses := make(chan string, 2)
	route.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		addresses <- address
		return nil, errors.New("fixture-secret")
	}
	transport := releaseTransportForRoute(t.Context(), route)
	defer transport.CloseIdleConnections()
	if _, err := transport.DialContext(t.Context(), "tcp", "api.github.com:443"); !errors.Is(err, errRedirect) {
		t.Fatalf("socket layer allowed a direct GitHub dial in proxy mode: %v", err)
	}
	c := releaseClient{http: releaseHTTPClient(transport)}
	if _, err := c.get(t.Context(), "https://unexpected.invalid/"); !errors.Is(err, errRedirect) {
		t.Fatalf("proxy transport accepted an unapproved origin: %v", err)
	}
	if _, err := c.get(t.Context(), releases); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("proxy transport did not redact the dial error: %v", err)
	}
	if len(addresses) != 1 || <-addresses != "proxy.example:8080" {
		t.Fatal("release fetch attempted to dial outside the pinned proxy")
	}
}

func TestExtractLinuxBinary(t *testing.T) {
	for _, tc := range []struct {
		name, abi, ver string
		markers        int
		entry          *tar.Header
		trailing       string
		want           string
	}{
		{name: "valid", abi: "amd64", ver: nextVersion, markers: 1},
		{name: "extra file", abi: "amd64", ver: nextVersion, markers: 1, entry: &tar.Header{Name: "extra"}, want: "unexpected entry"},
		{name: "symlink", abi: "amd64", ver: nextVersion, markers: 1, entry: &tar.Header{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "pipe"}, want: "unsupported entry"},
		{name: "wrong architecture", abi: "arm64", ver: nextVersion, markers: 1, want: "wrong CPU architecture"},
		{name: "wrong version", abi: "amd64", ver: cliInstalled, markers: 1, want: "does not match"},
		{name: "duplicate identity", abi: "amd64", ver: nextVersion, markers: 2, want: "does not match"},
		{name: "trailing entry bytes", abi: "amd64", ver: nextVersion, markers: 1, trailing: "unlisted", want: "invalid trailing data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := updateTestDir(t)
			image := linuxFixtureImage(tc.abi, tc.ver, tc.markers)
			path := filepath.Join(dir, desktopTarget.Filename())
			writeFixtureFile(t, path, linuxFixtureArchive(t, image, tc.entry, tc.trailing))
			output := filepath.Join(dir, "output")
			if err := privateDir(output); err != nil {
				t.Fatal(err)
			}
			f, cleanup, err := ExtractLinuxBinary(path, "amd64", nextVersion, output)
			if cleanup != nil {
				defer cleanup()
			}
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || f != nil {
					t.Fatalf("incorrect extraction result: %v", err)
				}
				if entries, err := os.ReadDir(output); err != nil || len(entries) != 0 {
					t.Fatalf("failed extraction left files behind: %v, %v", entries, err)
				}
				return
			}
			if err != nil || f == nil || cleanup == nil {
				t.Fatalf("valid Linux archive could not be extracted: %v", err)
			}
			if data, err := io.ReadAll(f); err != nil || !bytes.Equal(data, image) {
				t.Fatalf("extracted image did not match or was not rewound: %v", err)
			}
			if info, err := f.Stat(); runtime.GOOS != "windows" && (err != nil || info.Mode().Perm() != 0700) {
				t.Fatalf("incorrect extracted executable mode: %v, %v", info, err)
			}
		})
	}
}

func linuxFixtureImage(abi, ver string, markers int) []byte {
	data := make([]byte, 64)
	copy(data, "\x7fELF\x02\x01\x01")
	machine := uint16(62)
	if abi == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], machine)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	marker := fmt.Sprintf("%cpipe-desktop-release-v1 linux %s %s%c", 0, abi, ver, 0)
	return append(data, strings.Repeat(marker, markers)...)
}

func linuxFixtureArchive(t *testing.T, image []byte, extra *tar.Header, trailing string) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"pipe", image}, {"README.txt", []byte("test fixture")}} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0755, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		if err := tw.WriteHeader(extra); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(gz, trailing); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}
