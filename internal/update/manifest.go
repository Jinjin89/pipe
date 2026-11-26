// SPDX-License-Identifier: GPL-3.0-or-later

// Package update discovers and verifies Pipe release artifacts.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	releasePublicKey  = "7evMPdWmNXKsBfAyKYviEzA3mzwJb3PV2ZJggn/GCDI="
	manifestName      = "SHA256SUMS"
	signatureName     = "SHA256SUMS.sig"
	ManifestFilename  = manifestName
	SignatureFilename = signatureName
	manifestHeader    = "pipe-sha256sums-v1"
	maxManifest       = 16 * 1024
	maxAssetSize      = 256 << 20
)

type Target struct{ OS, ABI string }

// Filename returns the canonical release asset filename for t, or "".
func (t Target) Filename() string { return t.filename() }

func (t Target) filename() string {
	switch t.OS {
	case "linux":
		if t.ABI == "amd64" || t.ABI == "arm64" {
			return "pipe-linux-" + t.ABI + ".tar.gz"
		}
	case "darwin":
		if t.ABI == "amd64" || t.ABI == "arm64" {
			return "pipe-macos-" + t.ABI + ".zip"
		}
	case "windows":
		if t.ABI == "amd64" {
			return "pipe-windows-amd64.zip"
		}
	case "android":
		switch t.ABI {
		case "arm64-v8a":
			return "pipe-android-arm64.apk"
		case "x86_64":
			return "pipe-android-x86_64.apk"
		}
	}
	return ""
}

type asset struct {
	name   string
	length int64
	digest [sha256.Size]byte
}

func verifyManifest(key ed25519.PublicKey, body, sig []byte, version, channel string, target Target) (asset, error) {
	bad := errors.New("The signed release manifest is invalid.")
	if len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, body, sig) {
		return asset{}, errors.New("The release signature is invalid.")
	}
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) < 4 || lines[0] != manifestHeader || lines[1] != "version "+version || lines[2] != "channel "+channel {
		return asset{}, bad
	}
	seen := make(map[Target]bool)
	var selected asset
	for _, line := range lines[3:] {
		parts := strings.Split(line, " ")
		if len(parts) != 5 {
			return asset{}, bad
		}
		entry := Target{OS: parts[0], ABI: parts[1]}
		filename := entry.filename()
		if filename == "" || parts[2] != filename || seen[entry] {
			return asset{}, bad
		}
		seen[entry] = true
		length, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil || length <= 0 || length > maxAssetSize || strconv.FormatInt(length, 10) != parts[3] {
			return asset{}, bad
		}
		var digest [sha256.Size]byte
		if len(parts[4]) != hex.EncodedLen(len(digest)) {
			return asset{}, bad
		}
		n, err := hex.Decode(digest[:], []byte(parts[4]))
		if err != nil || n != len(digest) || hex.EncodeToString(digest[:]) != parts[4] {
			return asset{}, bad
		}
		if entry == target {
			selected = asset{name: filename, length: length, digest: digest}
		}
	}
	if selected.name == "" {
		return asset{}, errors.New("The signed release has no asset for this device.")
	}
	return selected, nil
}

func embeddedKey() ed25519.PublicKey {
	key, _ := base64.StdEncoding.DecodeString(releasePublicKey)
	return key
}
