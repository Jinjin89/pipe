// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"pipe/internal/link"
	"pipe/internal/localfile"

	"rsc.io/qr"
)

const (
	settingsFile = "server.json"
	devicesFile  = "devices.json"
)

type Ports struct {
	HTTPS         uint16 `json:"https"` // REALITY TCP and Hysteria2 UDP.
	Fast          uint16 `json:"fast,omitempty"`
	Stealth       uint16 `json:"stealth,omitempty"`
	HTTP          uint16 `json:"http"`
	Decoy         uint16 `json:"decoy"`
	VMess         uint16 `json:"vmess"`
	RealityOrigin uint16 `json:"reality_origin"`
	RealityCDN    uint16 `json:"reality_cdn"`
}

func TestPorts() Ports {
	return Ports{HTTPS: 18443, HTTP: 18080, Decoy: 18444, VMess: 18001, RealityOrigin: 18445, RealityCDN: 18446}
}

type Settings struct {
	Mode               DeployMode                `json:"mode"`
	Domain             string                    `json:"domain"`
	BlockEgressIPs     []netip.Addr              `json:"block_egress_ips,omitempty"`
	CDNDomain          string                    `json:"cdn_domain,omitempty"`
	RealityPrivateKey  string                    `json:"reality_private_key"`
	RealityPublicKey   string                    `json:"reality_public_key"`
	WSPath             string                    `json:"ws_path"`
	Ports              Ports                     `json:"ports"`
	RealityDest        string                    `json:"reality_dest,omitempty"`
	RealitySNI         string                    `json:"reality_sni,omitempty"`
	RealityAddress     string                    `json:"reality_address,omitempty"`
	RescueListen       string                    `json:"rescue_listen,omitempty"` // retired
	Rescue             *RescueConfig             `json:"rescue,omitempty"`
	FastSNI            string                    `json:"fast_sni,omitempty"`
	FastHop            string                    `json:"fast_hop,omitempty"`
	FastPrivateKey     []byte                    `json:"fast_private_key,omitempty"`
	FastCertificate    []byte                    `json:"fast_certificate,omitempty"`
	HTTPSProxy         *bool                     `json:"https_proxy,omitempty"`
	HTTPSProxyListener *httpsProxyListenerConfig `json:"https_proxy_listener,omitempty"`
	LastProxyDomain    string                    `json:"last_proxy_domain,omitempty"`

	// realityBlocked records why Stealth cannot borrow the HTTPS proxy at run time.
	realityBlocked string
}

type Device struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	link.Credentials
}

func Init(dir, domain, cdn string) error {
	return InitWithOptions(dir, domain, cdn, InitOptions{Mode: Standalone})
}

func InitWithOptions(dir, domain, cdn string, options InitOptions) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Lstat(filepath.Join(dir, settingsFile)); err == nil {
		return errors.New("server is already initialized")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	settings, err := deployment(strings.ToLower(domain), strings.ToLower(cdn), options)
	if err != nil {
		return err
	}
	devices, err := ReadDevices(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := writeJSON(dir, devicesFile, []Device{}); err != nil {
			return err
		}
	case err != nil:
		return err
	case len(devices) != 0:
		return errors.New("cannot initialize over existing device credentials")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var pathSecret [16]byte
	rand.Read(pathSecret[:])
	settings.RealityPrivateKey = link.EncodeKey([32]byte(key.Bytes()))
	settings.RealityPublicKey = link.EncodeKey([32]byte(key.PublicKey().Bytes()))
	settings.WSPath = "/ws/" + hex.EncodeToString(pathSecret[:])
	if err := settings.storeRescueFiles(dir); err != nil {
		return err
	}
	if err := writeJSON(dir, settingsFile, settings); err != nil {
		return errors.Join(err, removeRescueFiles(dir, settings.Rescue))
	}
	return nil
}

func ReadSettings(dir string) (Settings, error) {
	var settings Settings
	if err := readJSON(filepath.Join(dir, settingsFile), &settings); err != nil {
		return settings, err
	}
	if settings.Mode == "" { // M1 state predates deploy modes.
		settings.Mode = Standalone
	}
	if err := settings.normalizeDeployment(); err != nil {
		return settings, err
	}
	if settings.Mode == Shared {
		if err := settings.validateSharedState(); err != nil {
			return settings, err
		}
	}
	privateKey, err := link.DecodeKey(settings.RealityPrivateKey)
	if err != nil {
		return settings, fmt.Errorf("invalid server REALITY private key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil || settings.RealityPublicKey != link.EncodeKey([32]byte(key.PublicKey().Bytes())) {
		return settings, errors.New("REALITY key pair does not match")
	}
	if tail, ok := strings.CutPrefix(settings.WSPath, "/ws/"); !ok || !isHex(tail, 16) {
		return settings, errors.New("invalid server WebSocket path")
	}
	return settings, nil
}

func ReadDevices(dir string) ([]Device, error) {
	var devices []Device
	if err := readJSON(filepath.Join(dir, devicesFile), &devices); err != nil {
		return nil, err
	}
	if devices == nil {
		return nil, errors.New("devices.json must contain a JSON array")
	}
	names := make(map[string]bool, len(devices))
	credentials := make(map[link.Credentials]bool, len(devices))
	for i, d := range devices {
		_, passwordErr := link.DecodeKey(d.HY2Password)
		proxyKey := d.HTTPSProxyPassword
		if proxyKey != "" {
			if _, err := link.DecodeKey(proxyKey); err != nil {
				return nil, fmt.Errorf("invalid HTTPS proxy credential at index %d in %s", i, devicesFile)
			}
		}
		d.HTTPSProxyPassword = ""
		if !link.ValidName(d.Name) || d.CreatedAt.IsZero() || passwordErr != nil ||
			!isHex(d.DeviceID, 8) || !isHex(d.RealitySID, 8) ||
			!isUUID(d.VLESSUUID) || !isUUID(d.VMessUUID) || names[d.Name] || credentials[d.Credentials] {
			return nil, fmt.Errorf("invalid or duplicate device at index %d in %s", i, devicesFile)
		}
		names[d.Name], credentials[d.Credentials] = true, true
	}
	return devices, nil
}

func isHex(text string, bytes int) bool {
	if len(text) != bytes*2 {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil
}

func isUUID(text string) bool {
	parts := strings.Split(text, "-")
	if len(parts) != 5 {
		return false
	}
	for i, length := range []int{4, 2, 2, 2, 6} {
		if !isHex(parts[i], length) {
			return false
		}
	}
	return true
}

func Add(dir, name string, testPorts bool) (string, *qr.Code, error) {
	encoded, code, _, err := AddWithProxy(dir, name, testPorts)
	return encoded, code, err
}

func AddWithProxy(dir, name string, testPorts bool) (string, *qr.Code, string, error) {
	return addWithDelivery(dir, name, testPorts, nil)
}

// EnrollSetupDevice writes an unattended link to the open output descriptor
// before committing the device. Setup removes the file if enrollment fails.
func EnrollSetupDevice(dir, name string, file *os.File) error {
	if file == nil {
		return errors.New("enrollment requires an output descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 0 {
		return errors.New("enrollment requires a new owner-only regular file")
	}
	_, _, _, err = addWithDelivery(dir, name, false, func(encoded string) error {
		if _, err := fmt.Fprintln(file, encoded); err != nil {
			return err
		}
		return file.Sync()
	})
	return err
}

func addWithDelivery(dir, name string, testPorts bool, deliver func(string) error) (string, *qr.Code, string, error) {
	if !link.ValidName(name) {
		return "", nil, "", errors.New("device name must contain 1–128 bytes of printable text")
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return "", nil, "", err
	}
	defer unlock()
	settings, err := ReadSettings(dir)
	if err != nil {
		return "", nil, "", err
	}
	devices, err := ReadDevices(dir)
	if err != nil {
		return "", nil, "", err
	}
	if deviceIndex(devices, name) >= 0 {
		return "", nil, "", errors.New("device name is already in use")
	}
	publicKey, err := link.DecodeKey(settings.RealityPublicKey)
	if err != nil {
		return "", nil, "", err
	}
	profile := link.Profile{PublicKey: publicKey, Host: settings.Domain, Name: name}
	if testPorts && settings.Mode == Standalone {
		settings.Ports = TestPorts()
	}
	// M1 clients keep working with legacy links when both ports are equal.
	if settings.Mode == Standalone && settings.fastPort() == settings.stealthPort() && settings.fastPort() != link.DefaultPort {
		profile.Port = settings.fastPort()
	}
	if port := settings.rescuePort(); port != 0 {
		profile.CDN, profile.WSPath = settings.CDNDomain, settings.WSPath
		if port != link.DefaultPort {
			profile.CDNPort = port
		}
	}
	profile.FastPort, profile.StealthPort = settings.fastPort(), settings.stealthPort()
	profile.FastHop, profile.FastSNI = settings.FastHop, settings.FastSNI
	profile.RealitySNI = settings.stealthName()
	if settings.Mode == Shared {
		profile.FastPin, err = settings.fastPin()
		if err != nil {
			return "", nil, "", err
		}
	}
	authority := settings.proxyAuthority()
	if authority != "" {
		profile.HTTPSProxy = authority
	}
	rand.Read(profile.Seed[:])
	encoded, err := profile.Encode()
	if err != nil {
		return "", nil, "", err
	}
	code, err := qr.Encode(encoded, link.QRLevel)
	if err != nil {
		return "", nil, "", fmt.Errorf("encode device QR: %w", err)
	}
	credentials := link.Derive(profile.Seed)
	var proxyURL string
	if authority != "" {
		proxyURL = link.FormatProxyURL(authority, name, credentials.HTTPSProxyPassword)
	}
	devices = append(devices, Device{Name: name, CreatedAt: time.Now().UTC(), Credentials: credentials})
	if deliver != nil {
		if err := deliver(encoded); err != nil {
			return "", nil, "", fmt.Errorf("write device enrollment file: %w", err)
		}
	}
	if err := writeJSON(dir, devicesFile, devices); err != nil {
		return "", nil, "", err
	}
	return encoded, code, proxyURL, nil
}

func (s Settings) proxyAuthority() string {
	domain, port := s.proxyEndpoint()
	if domain == "" {
		return ""
	}
	if s.Mode == Standalone || port != link.DefaultPort {
		return addrPort(domain, port)
	}
	return domain
}

func Revoke(dir, name string) error {
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	devices, err := ReadDevices(dir)
	if err != nil {
		return err
	}
	index := deviceIndex(devices, name)
	if index < 0 {
		return errors.New("device does not exist")
	}
	return writeJSON(dir, devicesFile, slices.Delete(devices, index, index+1))
}

func deviceIndex(devices []Device, name string) int {
	return slices.IndexFunc(devices, func(d Device) bool { return d.Name == name })
}

func readJSON(path string, value any) error {
	data, err := localfile.Read(path, localfile.MaxConfigBytes, true)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		// Decoder errors can include raw credential material.
		return fmt.Errorf("invalid JSON in %s", filepath.Base(path))
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected data after JSON in %s", filepath.Base(path))
	}
	return nil
}

func writeJSON(dir, name string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded)+1 > localfile.MaxConfigBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, localfile.MaxConfigBytes)
	}
	return writeAtomic(dir, name, append(encoded, '\n'), 0600)
}

func writeAtomic(dir, name string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, name))
}
