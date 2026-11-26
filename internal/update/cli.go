// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

type ResolveOptions struct {
	Installed     string
	Newest        string // defaults to Installed when every copy has the same version
	Target        Target
	StateDir      string
	From          string // offline directory or canonical archive file
	Route         Route  // used for online updates only
	CheckOnly     bool
	ReadOnlyState bool              // permits a preview when the saved state is unreadable
	Key           ed25519.PublicKey // defaults to the embedded release key
}

type StagedRelease struct {
	Version         string
	Channel         string
	AssetName       string
	ArchivePath     string // empty for a current release or an online check
	AssetSize       int64
	SHA256          [32]byte
	Current         bool
	StateUnverified bool
	Cleanup         func() // always non-nil

	state  releaseState
	signed *signedRelease
}

// VerifyFloor checks the staged offer against the current signed rollback floor.
// Call it under the publication lock before replacing any executables.
func (s StagedRelease) VerifyFloor() error {
	if s.state.dir == "" || s.Current {
		return nil
	}
	if s.signed == nil {
		return errors.New("The staged release is missing its verified manifest.")
	}
	return withUpdateStateLock(context.Background(), s.state.dir, func() error {
		floor, err := s.state.load()
		if err != nil {
			return errStateRead
		}
		selected, err := s.signed.verify(s.state.key, s.state.channel, s.state.target)
		if err != nil {
			return err
		}
		return selected.checkFloor(floor)
	})
}

const cliStagePrefix = "cli-stage-"

// Resolve verifies a Pipe release and stages its archive when needed.
func Resolve(ctx context.Context, opts ResolveOptions) (StagedRelease, error) {
	return resolveWithTransport(ctx, opts, releaseTransportForRoute)
}

func resolveWithTransport(ctx context.Context, opts ResolveOptions, makeTransport func(context.Context, Route) *http.Transport) (result StagedRelease, err error) {
	result.Cleanup = func() {}
	installed, ok := parseVersion(opts.Installed)
	if !ok || opts.Target.Filename() == "" {
		return result, errors.New("Updates are unavailable for this build.")
	}
	newest := installed
	if opts.Newest != "" {
		newest, ok = parseVersion(opts.Newest)
		if !ok || newest.channel != installed.channel || newest.compare(installed) < 0 {
			return result, errors.New("The installed versions must be ordered and on the same release channel.")
		}
	}
	if len(opts.Key) == 0 {
		opts.Key = embeddedKey()
	} else {
		opts.Key = slices.Clone(opts.Key)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if opts.StateDir != "" {
		opts.StateDir, err = filepath.Abs(opts.StateDir)
		if err != nil {
			return result, errStateRead
		}
	}
	result.Channel = installed.channel
	state := releaseState{dir: opts.StateDir, channel: result.Channel, target: opts.Target, key: opts.Key}
	floor, err := state.load()
	if opts.ReadOnlyState && errors.Is(err, os.ErrPermission) {
		result.StateUnverified = true
	} else if err != nil {
		return result, errStateRead
	}
	stageDir := opts.StateDir
	if opts.ReadOnlyState {
		stageDir = ""
	}

	var candidate *release
	if opts.From == "" {
		if opts.Route.err != nil {
			return result, opts.Route.err
		}
		if opts.Route.dial == nil {
			return result, ErrTunnelUnavailable
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if opts.Route.ctx != nil {
			if opts.Route.ctx.Err() != nil {
				return result, ErrTunnelStopped
			}
			defer context.AfterFunc(opts.Route.ctx, cancel)()
		}
		transport := makeTransport(ctx, opts.Route)
		defer transport.CloseIdleConnections()
		client := releaseClient{http: releaseHTTPClient(transport), key: opts.Key}
		check, cancelCheck := context.WithTimeout(ctx, 45*time.Second)
		candidate, err = client.check(check, opts.Installed, opts.Target, floor)
		cancelCheck()
		if err != nil {
			return result, err
		}
		if candidate == nil {
			result.Version, result.Current = opts.Installed, true
			return result, nil
		}
		if err := requireNewest(candidate, newest); err != nil {
			return result, err
		}
		result.setRelease(state, candidate)
		if !opts.ReadOnlyState {
			if err := state.raise(ctx, candidate, opts.Route.tunneled); err != nil {
				return result, err
			}
		}
		if opts.CheckOnly {
			return result, nil
		}
		source, err := client.assetBody(ctx, candidate)
		if err != nil {
			return result, err
		}
		defer source.Close()
		result.ArchivePath, result.Cleanup, err = stageCLIAsset(ctx, stageDir, candidate.asset, source)
		return result, err
	}

	dir, err := openOfflineSource(opts.From, opts.Target.Filename())
	if err != nil {
		return result, err
	}
	defer dir.Close()
	candidate, err = readOfflineRelease(dir, state, floor)
	if err != nil {
		return result, err
	}
	if err := requireNewest(candidate, newest); err != nil {
		return result, err
	}
	file, _, err := dir.OpenRegular(candidate.asset.name)
	if err != nil {
		return result, fmt.Errorf("open %s: %w", candidate.asset.name, err)
	}
	defer file.Close()
	path, cleanup, err := stageCLIAsset(ctx, stageDir, candidate.asset, file)
	if err != nil {
		return result, err
	}
	if !opts.ReadOnlyState {
		if err := state.raise(ctx, candidate, false); err != nil {
			cleanup()
			return result, err
		}
	}
	result.setRelease(state, candidate)
	current, _ := parseVersion(candidate.version)
	if current.compare(installed) <= 0 {
		result.Current = true
		cleanup()
	} else {
		result.ArchivePath, result.Cleanup = path, cleanup
	}
	return result, nil
}

func (r *StagedRelease) setRelease(state releaseState, candidate *release) {
	r.Version = candidate.version
	r.AssetName, r.AssetSize, r.SHA256 = candidate.asset.name, candidate.asset.length, candidate.asset.digest
	r.state, r.signed = state, &candidate.signed
}

func requireNewest(candidate *release, newest releaseVersion) error {
	if v, _ := parseVersion(candidate.version); v.compare(newest) < 0 {
		return errors.New("The release is older than an installed copy of Pipe.")
	}
	return nil
}

func openOfflineSource(from, filename string) (*localSourceDir, error) {
	info, err := os.Stat(from)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return openLocalSourceDir(from)
	}
	if filepath.Base(from) != filename {
		return nil, fmt.Errorf("the offline source must be a directory or a file named %s", filename)
	}
	return openLocalSourceDir(filepath.Dir(from))
}

func readOfflineRelease(dir *localSourceDir, state releaseState, floor *release) (*release, error) {
	body, bodyErr := readSidecar(dir, manifestName, maxManifest)
	sig, sigErr := readSidecar(dir, signatureName, ed25519.SignatureSize)
	if errors.Is(bodyErr, os.ErrNotExist) && errors.Is(sigErr, os.ErrNotExist) && floor != nil {
		return floor, nil
	}
	if err := errors.Join(bodyErr, sigErr); err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%s must contain exactly %d bytes", signatureName, ed25519.SignatureSize)
	}
	_, lines, _ := strings.Cut(string(body), "\n")
	line, _, _ := strings.Cut(lines, "\n")
	version, ok := strings.CutPrefix(line, "version ")
	if !ok {
		return nil, fmt.Errorf("%s has an invalid release version header", manifestName)
	}
	signed := signedRelease{Tag: "v" + version, Manifest: body, Signature: sig, Digest: sha256.Sum256(body)}
	candidate, err := signed.verify(state.key, state.channel, state.target)
	if err != nil {
		return nil, err
	}
	if err := candidate.checkFloor(floor); err != nil {
		return nil, err
	}
	return candidate, nil
}

func readSidecar(dir *localSourceDir, name string, limit int64) ([]byte, error) {
	f, info, err := dir.OpenRegular(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer f.Close()
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return data, nil
}

func stageCLIAsset(ctx context.Context, base string, a asset, source io.Reader) (string, func(), error) {
	noop := func() {}
	if base == "" {
		var err error
		base, err = filepath.EvalSymlinks(os.TempDir())
		if err != nil {
			return "", noop, err
		}
		base, err = filepath.Abs(base)
		if err != nil {
			return "", noop, err
		}
		anchor, err := directoryAnchor(filepath.Join(base, cliStagePrefix))
		if err != nil {
			return "", noop, err
		}
		if err := inspectAncestors(base, anchor, false); err != nil {
			return "", noop, err
		}
	} else if err := privateDir(base); err != nil {
		return "", noop, err
	}
	stage := filepath.Join(base, cliStagePrefix+rand.Text())
	if err := mkdirPrivate(stage); err != nil {
		return "", noop, err
	}
	cleanup := sync.OnceFunc(func() { _ = os.RemoveAll(stage) })
	path := filepath.Join(stage, a.name)
	if err := writeCLIAsset(ctx, path, a, source); err != nil {
		cleanup()
		return "", noop, err
	}
	return path, cleanup, nil
}

func writeCLIAsset(ctx context.Context, path string, a asset, source io.Reader) error {
	if err := inspectPrivateDir(filepath.Dir(path), false); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := a.copyVerified(ctx, file, source); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return ctx.Err()
}
