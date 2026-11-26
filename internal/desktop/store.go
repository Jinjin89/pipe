// SPDX-License-Identifier: GPL-3.0-or-later

// Package desktop is the local web server and OS integration of the Pipe app.
package desktop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"pipe/internal/clientctl"
	"pipe/internal/config"
	"pipe/internal/link"
	"pipe/internal/localfile"
	"pipe/internal/sysproxy"
)

const maxRules = 500

// Settings are the user-visible preferences (GET/PUT /api/settings).
type Settings struct {
	SystemProxy     bool   `json:"systemProxy"`
	TUN             bool   `json:"tun"` // connect through Pipe Helper's TUN (§8.5)
	ConnectOnLaunch bool   `json:"connectOnLaunch"`
	StartAtLogin    bool   `json:"startAtLogin"`
	ListenPort      int    `json:"listenPort"`
	IPv6            bool   `json:"ipv6"`
	LogDetail       string `json:"logDetail"`
	Theme           string `json:"theme"`
	UpdateAuto      *bool  `json:"updateAuto,omitempty"`
}

// RuleObject is the API form of a routing rule (design section 2.5).
type RuleObject struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Action string `json:"action"`
}

// ProfileRelay is the optional relay saved alongside a profile name.
type ProfileRelay struct {
	Code string `json:"host"`
	On   bool   `json:"on"`
}

func (r ProfileRelay) enabledCode() string {
	if r.On {
		return r.Code
	}
	return ""
}

type appData struct {
	Settings         Settings                    `json:"settings"`
	Mode             string                      `json:"mode"`
	Tier             string                      `json:"tier"`
	Rules            []RuleObject                `json:"rules"`
	Active           string                      `json:"active"`
	Relays           map[string]ProfileRelay     `json:"relays,omitempty"`
	Measurements     map[string]savedMeasurement `json:"measurements,omitempty"`
	LastProfileBatch time.Time                   `json:"lastProfileBatch,omitzero"`
}

type savedMeasurement struct {
	profileTestResponse
	Relay         string `json:"relay,omitempty"`
	IPv6          bool   `json:"ipv6"` // user setting matched against the current profile
	EffectiveIPv6 *bool  `json:"effectiveIPv6,omitempty"`
}

func (d *appData) setMeasurement(name string, measurement savedMeasurement) {
	if d.Measurements == nil {
		d.Measurements = make(map[string]savedMeasurement)
	}
	d.Measurements[name] = measurement
}

func (d appData) measurementFor(p ProfileInfo) *profileTestResponse {
	result, ok := d.Measurements[p.Name]
	if !ok || result.Rev != p.Rev || result.MetricVersion != clientctl.RTTMetricVersion ||
		result.IPv6 != d.Settings.IPv6 || result.Relay != d.relayFor(p.Name, p.Server).enabledCode() {
		return nil
	}
	return &result.profileTestResponse
}

func (d *appData) setRelay(name string, relay ProfileRelay) {
	if relay.Code == "" {
		delete(d.Relays, name)
		return
	}
	if d.Relays == nil {
		d.Relays = make(map[string]ProfileRelay)
	}
	d.Relays[name] = relay
}

func (d appData) relayFor(name, server string) ProfileRelay {
	relay := d.Relays[name]
	parsed, err := config.ParseRelay(relay.Code, server)
	if err != nil || parsed.Host == "" {
		return ProfileRelay{}
	}
	relay.Code = parsed.String()
	return relay
}

func defaultData() appData {
	return appData{
		Settings: Settings{SystemProxy: true, ListenPort: 7890, IPv6: true, LogDetail: "normal", Theme: "system"},
		Mode:     "smart", Tier: "auto", Rules: []RuleObject{},
	}
}

// Store persists app.json with atomic writes.
type Store struct {
	mu      sync.Mutex
	path    string
	data    appData
	loadErr error
}

// OpenStore loads path and uses defaults for display if it cannot read it.
// A read error on an existing file blocks saves.
func OpenStore(path string) *Store {
	return openStore(path, nil)
}

// Err returns the load error that prevents updating this store.
func (s *Store) Err() error { return s.loadErr }

func openStore(path string, profiles *Profiles) *Store {
	s := &Store{path: path, data: defaultData()}
	raw, err := sysproxy.ReadPrivateLimit(path, localfile.MaxConfigBytes)
	if err == nil {
		loaded := defaultData()
		if err := json.Unmarshal(raw, &loaded); err != nil {
			s.loadErr = fmt.Errorf("couldn't parse app.json: %w", err)
		} else {
			s.data = loaded
			s.sanitize(profiles)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		s.loadErr = fmt.Errorf("couldn't load app.json: %w", err)
	}
	return s
}

func (s *Store) sanitize(profiles *Profiles) {
	d := defaultData()
	if !validMode(s.data.Mode) {
		s.data.Mode = d.Mode
	}
	if !validTier(s.data.Tier) {
		s.data.Tier = d.Tier
	}
	if s.data.Rules == nil {
		s.data.Rules = []RuleObject{}
	}
	if s.data.Settings.ListenPort < 1 || s.data.Settings.ListenPort > 65535 {
		s.data.Settings.ListenPort = d.Settings.ListenPort
	}
	if !validLogDetail(s.data.Settings.LogDetail) {
		s.data.Settings.LogDetail = d.Settings.LogDetail
	}
	if !validTheme(s.data.Settings.Theme) {
		s.data.Settings.Theme = d.Settings.Theme
	}
	for name := range s.data.Relays {
		if !config.ValidAlias(name) {
			delete(s.data.Relays, name)
			continue
		}
		server := ""
		if profiles != nil {
			profile, err := profiles.Load(name)
			if err != nil {
				delete(s.data.Relays, name)
				continue
			}
			server = profile.Host
		}
		s.data.setRelay(name, s.data.relayFor(name, server))
	}
}

func validMode(m string) bool { return m == "smart" || m == "global" || m == "direct" }
func validTier(t string) bool {
	return t == "auto" || t == "fast" || t == "stealth" || t == "rescue"
}
func validLogDetail(v string) bool { return v == "normal" || v == "connections" }
func validTheme(v string) bool     { return v == "system" || v == "light" || v == "dark" }

// StatusFields returns the small subset of settings needed by /api/status
// without cloning all saved rules, relays and profile measurements.
func (s *Store) StatusFields(profiles *Profiles) (mode, tier string, listenPort int, measurement *profileTestResponse) {
	s.mu.Lock()
	mode, tier, listenPort = s.data.Mode, s.data.Tier, s.data.Settings.ListenPort
	active := s.data.Active
	m, hasM := s.data.Measurements[active]
	var relay ProfileRelay
	if hasM {
		relay = s.data.Relays[active]
	}
	ipv6 := s.data.Settings.IPv6
	s.mu.Unlock()
	if !hasM || active == "" || profiles == nil {
		return mode, tier, listenPort, nil
	}
	info, err := profiles.Info(active)
	if err != nil {
		return mode, tier, listenPort, nil
	}
	// Evaluate measurement match using the lightweight copy of active's data.
	partial := appData{
		Settings:     Settings{IPv6: ipv6},
		Relays:       map[string]ProfileRelay{active: relay},
		Measurements: map[string]savedMeasurement{active: m},
	}
	return mode, tier, listenPort, partial.measurementFor(info)
}

// Snapshot returns a copy of the current data.
func (s *Store) Snapshot() appData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.clone()
}

func (d appData) clone() appData {
	d.Rules = append([]RuleObject{}, d.Rules...)
	d.Relays = maps.Clone(d.Relays)
	d.Measurements = maps.Clone(d.Measurements)
	for name, measurement := range d.Measurements {
		measurement.Routes = maps.Clone(measurement.Routes)
		if measurement.EffectiveIPv6 != nil {
			measurement.EffectiveIPv6 = new(*measurement.EffectiveIPv6)
		}
		d.Measurements[name] = measurement
	}
	if d.Settings.UpdateAuto != nil {
		d.Settings.UpdateAuto = new(*d.Settings.UpdateAuto)
	}
	return d
}

// Update changes the data under the lock and saves it.
func (s *Store) Update(change func(*appData)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return s.loadErr
	}
	next := s.data.clone()
	change(&next)
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := localfile.WritePrivateAtomic(s.path, raw); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	s.data = next
	return nil
}

// WriteFileAtomic writes via a temporary file in the same directory.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(name, perm)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// RuleText maps a rule object to config.ParseRule text (design section 2.5).
func RuleText(r RuleObject) (string, error) {
	value := strings.TrimSpace(r.Value)
	if value == "" || strings.Contains(value, "->") {
		return "", errors.New("Enter a value for this rule.")
	}
	switch r.Action {
	case "proxy", "direct", "block":
	default:
		return "", errors.New("Choose Proxy, Direct or Block.")
	}
	var match string
	switch r.Type {
	case "domain", "ip":
		match = value
	case "suffix":
		match = "suffix:" + value
	case "keyword":
		match = "keyword:" + value
	case "app":
		match = "process:" + value
	default:
		return "", errors.New("Unknown rule type.")
	}
	return match + " -> " + r.Action, nil
}

// ProfileInfo is the public face of a saved profile. It never holds the link.
type ProfileInfo struct {
	Name        string               `json:"name"`
	Server      string               `json:"server"`
	Routes      []string             `json:"routes"`
	Fingerprint string               `json:"fingerprint"`
	Relay       ProfileRelay         `json:"relay"`
	Rev         string               `json:"rev,omitempty"`
	Measurement *profileTestResponse `json:"measurement,omitempty"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// NormalizeName lowercases and validates a NEW profile name.
func NormalizeName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	return name, nameRE.MatchString(name) && config.ValidAlias(name)
}

// Resolve maps a requested name to the stored one. It matches exactly first,
// then ignoring case, so case-insensitive file systems can't alias a profile.
func (p *Profiles) Resolve(name string) (string, bool) {
	if !config.ValidAlias(name) {
		return "", false
	}
	entries, _ := os.ReadDir(p.dir)
	folded := ""
	for _, e := range entries {
		stored, ok := strings.CutSuffix(e.Name(), ".link")
		if !ok || e.IsDir() {
			continue
		}
		if stored == name {
			return stored, true
		}
		if strings.EqualFold(stored, name) && config.ValidAlias(stored) {
			folded = stored
		}
	}
	return folded, folded != ""
}

func infoFor(name string, p link.Profile, revision string) ProfileInfo {
	routes := []string{"fast", "stealth"}
	if p.CDN != "" {
		routes = append(routes, "rescue")
	}
	sum := sha256.Sum256(p.PublicKey[:])
	var fp []string
	for _, b := range sum[:6] {
		fp = append(fp, fmt.Sprintf("%02X", b))
	}
	return ProfileInfo{Name: name, Server: p.Host, Routes: routes, Fingerprint: strings.Join(fp, ":"), Rev: revision}
}

type cachedProfileInfo struct {
	size    int64
	modTime int64
	info    ProfileInfo
}

// Profiles manages NAME.link files, shared with the CLI.
type Profiles struct {
	dir   string
	mu    sync.Mutex
	cache map[string]cachedProfileInfo
}

func NewProfiles(dir string) *Profiles {
	return &Profiles{dir: dir, cache: map[string]cachedProfileInfo{}}
}

func (p *Profiles) path(name string) string { return filepath.Join(p.dir, name+".link") }

// Load reads one profile.
func (p *Profiles) Load(name string) (link.Profile, error) {
	profile, _, err := p.load(name)
	return profile, err
}

// load reads the profile and its revision from the same saved link.
func (p *Profiles) load(name string) (link.Profile, string, error) {
	if !config.ValidAlias(name) {
		return link.Profile{}, "", os.ErrNotExist
	}
	raw, err := sysproxy.ReadPrivate(p.path(name))
	if err != nil {
		return link.Profile{}, "", err
	}
	profile, err := link.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		return profile, "", err
	}
	return profile, savedLinkRevision(raw), nil
}

func savedLinkRevision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

// List returns every readable profile, sorted by name. Unreadable files are skipped.
func (p *Profiles) List() []ProfileInfo {
	entries, _ := os.ReadDir(p.dir)
	list := []ProfileInfo{}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".link")
		if !ok || e.IsDir() {
			continue
		}
		if !config.ValidAlias(name) {
			continue
		}
		if profile, revision, err := p.load(name); err == nil {
			list = append(list, infoFor(name, profile, revision))
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

func (p *Profiles) Exists(name string) bool {
	_, ok := p.Resolve(name)
	return ok
}

// Save writes a profile (0600). It replaces an existing file of the same name.
func (p *Profiles) Save(name string, profile link.Profile) (ProfileInfo, error) {
	encoded, err := profile.Encode()
	if err != nil {
		return ProfileInfo{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if stored, ok := p.Resolve(name); ok {
		name = stored // replace the existing file, whatever its case
	}
	raw := []byte(encoded + "\n")
	if err := localfile.WritePrivateAtomic(p.path(name), raw); err != nil {
		return ProfileInfo{}, err
	}
	return infoFor(name, profile, savedLinkRevision(raw)), nil
}

// Rename moves a profile. It refuses to overwrite another one.
func (p *Profiles) Rename(from, to string) (ProfileInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	profile, revision, err := p.load(from)
	if err != nil {
		return ProfileInfo{}, err
	}
	if from != to {
		if stored, taken := p.Resolve(to); taken && !strings.EqualFold(stored, from) {
			return ProfileInfo{}, os.ErrExist
		}
		if err := os.Rename(p.path(from), p.path(to)); err != nil {
			return ProfileInfo{}, err
		}
	}
	return infoFor(to, profile, revision), nil
}

func (p *Profiles) Delete(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return os.Remove(p.path(name))
}

// Info returns the public info of one profile, caching by file size and mtime
// so 1-second status polls avoid reparsing and hashing unchanged link files.
func (p *Profiles) Info(name string) (ProfileInfo, error) {
	if !config.ValidAlias(name) {
		return ProfileInfo{}, os.ErrNotExist
	}
	st, err := os.Stat(p.path(name))
	if err != nil {
		p.mu.Lock()
		delete(p.cache, name)
		p.mu.Unlock()
		return ProfileInfo{}, err
	}
	modNano := st.ModTime().UnixNano()
	p.mu.Lock()
	if cached, ok := p.cache[name]; ok && cached.size == st.Size() && cached.modTime == modNano {
		p.mu.Unlock()
		return cached.info, nil
	}
	p.mu.Unlock()
	profile, revision, err := p.load(name)
	if err != nil {
		return ProfileInfo{}, err
	}
	info := infoFor(name, profile, revision)
	p.mu.Lock()
	p.cache[name] = cachedProfileInfo{size: st.Size(), modTime: modNano, info: info}
	p.mu.Unlock()
	return info, nil
}

// Preview parses a pasted link without saving it.
func Preview(raw string) (link.Profile, ProfileInfo, error) {
	profile, err := link.Parse(strings.TrimSpace(raw))
	if err != nil {
		return link.Profile{}, ProfileInfo{}, errors.New("That doesn't look like a Pipe link. Copy the whole link that starts with pipe://")
	}
	return profile, infoFor(DefaultName(profile), profile, ""), nil
}

// DefaultName suggests a profile name: the link's name lowercased, invalid
// characters turned into '-', trimmed, at most 32 characters.
func DefaultName(p link.Profile) string {
	var b strings.Builder
	for _, r := range strings.ToLower(p.Name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		} else if r == '-' || b.Len() > 0 {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 32 {
		out = out[:32]
	}
	out = strings.Trim(out, "-_")
	if out == "" {
		return "server"
	}
	return out
}
