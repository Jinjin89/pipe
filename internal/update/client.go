// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	repository = "Jinjin89/pipe"
	releases   = "https://api.github.com/repos/" + repository + "/releases"
	pageSize   = 100
	maxPages   = 10
)

var (
	ErrTunnelUnavailable = errors.New("No tunnel route is available for updates. Connect to a proxy tier and retry.")
	ErrTunnelStopped     = errors.New("The tunnel stopped during the update. Check for updates again to retry.")
	errRedirect          = errors.New("The release redirected to an unapproved address.")
	errOlderRelease      = errors.New("The release server offered an older version than the one already verified.")
	errChangedManifest   = errors.New("The signed manifest changed for a version already verified.")
)

type DialFunc func(context.Context, string, string) (net.Conn, error)

// Route holds the transport and lifetime selected when an update job starts.
// Its zero value fails closed.
type Route struct {
	ctx      context.Context
	dial     DialFunc
	tunneled bool
	err      error
}

func DirectRoute() Route {
	d := net.Dialer{Timeout: 15 * time.Second}
	return Route{dial: d.DialContext}
}

func TunnelRoute(ctx context.Context, dial DialFunc) Route {
	return Route{ctx: ctx, dial: dial, tunneled: true}
}

func UnavailableRoute(err error) Route {
	return Route{err: err, tunneled: true}
}

func approvedHost(host string) bool {
	switch strings.ToLower(host) {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com",
		"objects.githubusercontent.com", "github-releases.githubusercontent.com":
		return true
	}
	return false
}

// AllowedAddress is also used at the Helper's privileged stream boundary.
func AllowedAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	return err == nil && port == "443" && approvedHost(host)
}

func approvedURL(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return false
	}
	return approvedHost(u.Hostname()) && (u.Port() == "" || u.Port() == "443")
}

type releaseClient struct {
	http *http.Client
	key  ed25519.PublicKey
}

func releaseTransport(job context.Context, dial DialFunc) *http.Transport {
	return &http.Transport{
		DialContext: func(request context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" || !AllowedAddress(addr) {
				return nil, errRedirect
			}
			// Transport can keep dialing after a request is cancelled.
			// Tie the dial to the update job as well.
			ctx, cancel := context.WithTimeout(job, 20*time.Second)
			defer cancel()
			defer context.AfterFunc(request, cancel)()
			if err := request.Err(); err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return dial(ctx, network, addr)
		},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
	}
}

func releaseHTTPClient(transport *http.Transport) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !approvedURL(req.URL) {
			return errRedirect
		}
		req.Header.Del("Referer")
		return nil
	}}
}

func (c releaseClient) get(ctx context.Context, address string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil || !approvedURL(req.URL) {
		return nil, errRedirect
	}
	req.Header.Set("User-Agent", "Pipe Updater")
	if req.URL.Host == "api.github.com" {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, errRedirect):
			return nil, errRedirect
		case errors.Is(err, ErrTunnelStopped):
			return nil, ErrTunnelStopped
		case errors.Is(err, ErrTunnelUnavailable):
			return nil, ErrTunnelUnavailable
		case ctx.Err() != nil:
			return nil, ctx.Err()
		default:
			return nil, errors.New("Could not reach the release server.")
		}
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("The release server returned HTTP %d.", resp.StatusCode)
	}
	return resp, nil
}

func (c releaseClient) read(ctx context.Context, address string, limit int64) ([]byte, error) {
	resp, err := c.get(ctx, address)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("Could not read the release metadata.")
	}
	return data, nil
}

// scanPage streams a JSON array of GitHub releases without buffering the full page in memory.
func (c releaseClient) scanPage(ctx context.Context, address string, visit func(githubRelease) error) (int, error) {
	const limit = 8 << 20
	resp, err := c.get(ctx, address)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	limited := &io.LimitedReader{R: resp.Body, N: limit + 1}
	dec := json.NewDecoder(limited)
	tok, err := dec.Token()
	if err != nil {
		if limited.N == 0 {
			return 0, errors.New("Could not read the release metadata.")
		}
		return 0, errors.New("The release list is invalid.")
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return 0, errors.New("The release list is invalid.")
	}
	count := 0
	for dec.More() {
		count++
		if count > pageSize {
			return 0, errors.New("The release list is invalid.")
		}
		var item githubRelease
		if err := dec.Decode(&item); err != nil {
			if limited.N == 0 {
				return 0, errors.New("Could not read the release metadata.")
			}
			return 0, errors.New("The release list is invalid.")
		}
		if err := visit(item); err != nil {
			return 0, err
		}
	}
	if tok, err := dec.Token(); err != nil {
		if limited.N == 0 {
			return 0, errors.New("Could not read the release metadata.")
		}
		return 0, errors.New("The release list is invalid.")
	} else if delim, ok := tok.(json.Delim); !ok || delim != ']' {
		return 0, errors.New("The release list is invalid.")
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, errors.New("The release list is invalid.")
	}
	// Confirm the response did not exceed limit with trailing whitespace.
	_, _ = io.Copy(io.Discard, limited)
	if limited.N == 0 {
		return 0, errors.New("Could not read the release metadata.")
	}
	return count, nil
}

type githubRelease struct {
	Tag    string `json:"tag_name"`
	Draft  bool   `json:"draft"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (r githubRelease) assetURL(name string) (string, error) {
	expected := releaseURL(r.Tag, name)
	found := false
	for _, a := range r.Assets {
		if a.Name == name {
			if found || a.URL != expected {
				return "", errors.New("The release asset list is invalid.")
			}
			found = true
		}
	}
	if !found {
		return "", errors.New("The release is missing a required file.")
	}
	return expected, nil
}

func releaseURL(tag, name string) string {
	return "https://github.com/" + repository + "/releases/download/" + tag + "/" + name
}

type signedRelease struct {
	Tag       string            `json:"tag"`
	Manifest  []byte            `json:"manifest"`
	Signature []byte            `json:"signature"`
	Digest    [sha256.Size]byte `json:"manifestSHA256"`
}

type release struct {
	version string
	asset   asset
	url     string
	signed  signedRelease
}

func (r *release) same(other *release) bool {
	return r != nil && other != nil && r.version == other.version && r.signed.Digest == other.signed.Digest
}

func (s signedRelease) verify(key ed25519.PublicKey, channel string, target Target) (*release, error) {
	version := strings.TrimPrefix(s.Tag, "v")
	parsed, ok := parseVersion(version)
	if !ok || parsed.channel != channel || len(s.Manifest) > maxManifest || sha256.Sum256(s.Manifest) != s.Digest {
		return nil, errors.New("The release identity is invalid.")
	}
	a, err := verifyManifest(key, s.Manifest, s.Signature, version, channel, target)
	if err != nil {
		return nil, err
	}
	return &release{version: version, asset: a, url: releaseURL(s.Tag, a.name), signed: s}, nil
}

// check returns a nil release when the installed version is current.
func (c releaseClient) check(ctx context.Context, installed string, target Target, verified *release) (*release, error) {
	current, ok := parseVersion(installed)
	if !ok || target.filename() == "" {
		return nil, errors.New("Updates are unavailable for this build.")
	}
	var latest githubRelease
	newest := current
	seen := make(map[string]bool)
	for page := 1; ; page++ {
		count, err := c.scanPage(ctx, fmt.Sprintf("%s?per_page=%d&page=%d", releases, pageSize, page), func(item githubRelease) error {
			version := strings.TrimPrefix(item.Tag, "v")
			v, ok := parseVersion(version)
			if item.Draft || !ok || v.channel != current.channel || v.compare(current) <= 0 {
				return nil
			}
			if seen[version] {
				return errors.New("The release list repeats a version.")
			}
			seen[version] = true
			if v.compare(newest) > 0 {
				latest = item
				newest = v
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if count < pageSize {
			break
		}
		if page == maxPages {
			return nil, errors.New("The release list is too long.")
		}
	}
	if verified != nil {
		floor, _ := parseVersion(verified.version)
		if newest.compare(floor) < 0 {
			return nil, errOlderRelease
		}
	}
	if latest.Tag == "" {
		return nil, nil
	}
	sigURL, err := latest.assetURL(signatureName)
	if err != nil {
		return nil, err
	}
	manifestURL, err := latest.assetURL(manifestName)
	if err != nil {
		return nil, err
	}
	sig, err := c.read(ctx, sigURL, ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	body, err := c.read(ctx, manifestURL, maxManifest)
	if err != nil {
		return nil, err
	}
	signed := signedRelease{Tag: latest.Tag, Manifest: body, Signature: sig, Digest: sha256.Sum256(body)}
	selected, err := signed.verify(c.key, current.channel, target)
	if err != nil {
		return nil, err
	}
	if verified != nil && selected.version == verified.version && !selected.same(verified) {
		return nil, errChangedManifest
	}
	if _, err := latest.assetURL(selected.asset.name); err != nil {
		return nil, err
	}
	return selected, nil
}
