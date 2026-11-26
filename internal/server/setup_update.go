// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"pipe/internal/link"
)

const ApplySetupUpdateCommand = "--apply-setup"

type setupInitialSettings struct {
	Mode                  DeployMode
	Domain, FastSNI, Hop  string
	FastPort, StealthPort uint16
}

type setupProxyUpdate struct {
	Enabled  bool
	Listener *httpsProxyListenerConfig
	DNSFile  string
}

type setupUpdate struct {
	Initial  *setupInitialSettings
	Expected string
	Rescue   *SetupRescue
	Proxy    *setupProxyUpdate
	VMess    uint16
}

func settingsDigest(s Settings) string {
	data, _ := json.Marshal(s)
	sum := sha256.Sum256(data)
	clear(data)
	return hex.EncodeToString(sum[:])
}

func (u setupUpdate) proposed(saved Settings, probeVMess func(uint16) error) (Settings, error) {
	s := saved
	if i := u.Initial; i != nil {
		s = Settings{Mode: i.Mode, Domain: i.Domain, FastSNI: i.FastSNI, FastHop: i.Hop,
			Ports: Ports{HTTPS: 443, HTTP: 80, Fast: i.FastPort, Stealth: i.StealthPort}, HTTPSProxy: new(i.Mode == Standalone)}
		if s.Mode == Shared && s.Ports.Stealth == 0 {
			s.Ports.Stealth = 8443
		}
	}
	if u.Rescue != nil {
		r := u.Rescue
		s.CDNDomain = strings.ToLower(r.SNI)
		if s.CDNDomain != "" {
			if err := checkSetupRescueName(s.fastName(), s.CDNDomain); err != nil {
				return s, err
			}
		}
		if s.Mode == Shared {
			s.RescueListen, s.Rescue = "", nil
			if s.CDNDomain == "" {
				s.Ports.VMess = 0
			} else {
				cfg := RescueConfig{Port: r.Port, Cert: r.Cert, Key: r.Key}
				if cfg.Cert == "" && cfg.Key == "" && saved.Rescue != nil && equalDNS(s.CDNDomain, saved.CDNDomain) {
					cfg.Cert, cfg.Key = saved.Rescue.Cert, saved.Rescue.Key
				}
				if cfg.Cert == "" || cfg.Key == "" {
					return s, errors.New("shared Rescue requires rescue.cert and rescue.key (or --rescue-cert and --rescue-key)")
				}
				var err error
				if cfg.Cert, err = filepath.Abs(cfg.Cert); err != nil {
					return s, err
				}
				if cfg.Key, err = filepath.Abs(cfg.Key); err != nil {
					return s, err
				}
				if cfg.Port == 0 {
					cfg.Port = DefaultRescuePort
				}
				s.Rescue = &cfg
			}
		}
	}
	if u.Proxy != nil {
		if s.Mode == Standalone {
			s.HTTPSProxy = new(u.Proxy.Enabled)
		} else {
			s.HTTPSProxyListener = u.Proxy.Listener
			if s.HTTPSProxyListener == nil {
				if old := saved.HTTPSProxyListener; old != nil {
					s.LastProxyDomain = old.Domain
				}
			} else {
				s.LastProxyDomain = ""
				if s.RealityDest == "" || s.RealityDest == realitySelf {
					s.borrowProxySite()
				}
			}
		}
	}
	if s.Mode == Standalone {
		s.assignInternalPorts()
	} else if s.sharedRescuePort() != 0 {
		port := s.Ports.VMess
		s.Ports.VMess = 0
		if err := s.validateSharedTCPPorts(s.HTTPSProxyListener); err != nil {
			return s, err
		}
		s.Ports.VMess = port
		if u.VMess != 0 {
			s.Ports.VMess = u.VMess
		} else if port == 0 || s.validateSharedTCPPorts(s.HTTPSProxyListener) != nil {
			if probeVMess == nil {
				return s, errors.New("setup update is missing its Rescue VMess port")
			}
			if err := s.allocateRescueVMess(s.HTTPSProxyListener, probeVMess); err != nil {
				return s, err
			}
		}
	}
	err := s.normalizeDeployment()
	return s, err
}

// ApplySetupUpdate runs only in the unprivileged child. The argument contains
// file paths and requested changes, with a digest of the state seen by root.
func ApplySetupUpdate(ctx context.Context, dir, encoded string) error {
	if os.Geteuid() <= 0 || runtime.GOOS != "linux" {
		return errors.New("the setup update must run as the unprivileged service user")
	}
	var update setupUpdate
	if err := json.Unmarshal([]byte(encoded), &update); err != nil {
		return errors.New("invalid setup update")
	}
	return applySetupUpdate(ctx, dir, update, realProxySetup(), func(warning string) {
		fmt.Fprintln(os.Stderr, "Warning:", warning)
	})
}

func readSetupUpdateBase(dir string, update setupUpdate) (Settings, error) {
	if update.Initial != nil {
		_, err := os.Lstat(filepath.Join(dir, settingsFile))
		switch {
		case err == nil:
			return Settings{}, errors.New("server state already exists; run setup again")
		case errors.Is(err, os.ErrNotExist):
			return Settings{}, nil
		default:
			return Settings{}, err
		}
	}
	saved, err := ReadSettings(dir)
	if err != nil {
		return saved, err
	}
	if settingsDigest(saved) != update.Expected {
		return saved, errors.New("server settings changed during setup; run setup again")
	}
	return saved, nil
}

func applySetupUpdate(ctx context.Context, dir string, update setupUpdate, proxy proxySetup, warn func(string)) error {
	saved, err := readSetupUpdateBase(dir, update)
	if err != nil {
		return err
	}
	final, err := update.proposed(saved, nil)
	if err != nil {
		return err
	}
	if update.Initial != nil {
		if err := generateSetupKeys(&final); err != nil {
			return err
		}
	}
	committed := false
	if port := final.sharedRescuePort(); port != 0 {
		if update.Rescue != nil && update.Rescue.Cert != "" {
			if err := final.storeRescueFiles(dir); err != nil {
				return err
			}
			defer func() {
				if !committed {
					_ = removeRescueFiles(dir, final.Rescue)
				}
			}()
		} else if _, err := loadRescuePEM(final, time.Now()); err != nil {
			return err
		}
	}
	var newDNS []byte
	if change := update.Proxy; change != nil && change.Listener != nil {
		cfg := final.HTTPSProxyListener
		source := change.DNSFile
		if cfg.method() == "dns" && source == "" && saved.HTTPSProxyListener != nil &&
			cfg.DNSSecret == saved.HTTPSProxyListener.DNSSecret {
			source = filepath.Join(dir, cfg.DNSSecret)
		}
		secret, err := prepareProxyCertificate(ctx, dir, cfg, saved.HTTPSProxyListener, source, ProxyEnableOptions{Warn: warn}, proxy)
		if err != nil {
			return err
		}
		defer clear(secret)
		newDNS = secret
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := readSetupUpdateBase(dir, update); err != nil {
		return err
	}
	devices, err := ReadDevices(dir)
	missingDevices := update.Initial != nil && errors.Is(err, os.ErrNotExist)
	if err != nil && !missingDevices {
		return err
	}
	if update.Initial != nil && len(devices) != 0 {
		return errors.New("cannot initialize over existing device credentials")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(newDNS) != 0 {
		if err := writeAtomic(dir, final.HTTPSProxyListener.DNSSecret, newDNS, 0600); err != nil {
			return err
		}
		defer func() {
			if !committed {
				_ = removeProxyDNSSecret(dir, final.HTTPSProxyListener)
			}
		}()
	}
	if missingDevices {
		if err := writeJSON(dir, devicesFile, []Device{}); err != nil {
			return err
		}
		defer func() {
			if !committed {
				_ = os.Remove(filepath.Join(dir, devicesFile))
			}
		}()
	}
	if err := writeJSON(dir, settingsFile, final); err != nil {
		return err
	}
	committed = true
	if update.Proxy != nil && final.HTTPSProxyListener != nil {
		warnMissingProxyPasswords(devices, warn)
	}
	if old := saved.Rescue; old != nil && (final.Rescue == nil || old.Cert != final.Rescue.Cert || old.Key != final.Rescue.Key) {
		if err := removeRescueFiles(dir, old); err != nil && warn != nil {
			warn(err.Error())
		}
	}
	if old := saved.HTTPSProxyListener; old != nil && (final.HTTPSProxyListener == nil || old.DNSSecret != final.HTTPSProxyListener.DNSSecret) {
		if err := removeProxyDNSSecret(dir, old); err != nil && warn != nil {
			warn(err.Error())
		}
	}
	return nil
}

func generateSetupKeys(s *Settings) error {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.RealityPrivateKey = link.EncodeKey([32]byte(key.Bytes()))
	s.RealityPublicKey = link.EncodeKey([32]byte(key.PublicKey().Bytes()))
	var pathSecret [16]byte
	rand.Read(pathSecret[:])
	s.WSPath = "/ws/" + hex.EncodeToString(pathSecret[:])
	if s.Mode == Shared {
		return s.refreshFastCertificate(time.Now())
	}
	return nil
}
