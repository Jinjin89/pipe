// SPDX-License-Identifier: GPL-3.0-or-later

// Package desktop is the local web server and OS integration of the Pipe app.
package desktop

import (
	"crypto/sha256"
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
	Settings Settings                `json:"settings"`
	Mode     string                  `json:"mode"`
	Tier     string                  `json:"tier"`
	Rules    []RuleObject            `json:"rules"`
	Active   string                  `json:"active"`
	Relays   map[string]ProfileRelay `json:"relays,omitempty"`
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
	mu   sync.Mutex
	path string
	data appData
}

// OpenStore loads path, falling back to defaults when it is missing or damaged.
func OpenStore(path string) *Store {
	return openStore(path, nil)
}

func openStore(path string, profiles *Profiles) *Store {
	s := &Store{path: path, data: defaultData()}
	raw, err := sysproxy.ReadPrivateLimit(path, localfile.MaxConfigBytes)
	if err == nil {
		loaded := defaultData()
		if json.Unmarshal(raw, &loaded) == nil {
			s.data = loaded
			s.sanitize(profiles)
		}
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

// Snapshot returns a copy of the current data.
func (s *Store) Snapshot() appData {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.data
	d.Rules = append([]RuleObject{}, d.Rules...)
	d.Relays = maps.Clone(d.Relays)
	return d
}

// Update changes the data under the lock and saves it.
func (s *Store) Update(change func(*appData)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data
	next.Rules = append([]RuleObject{}, next.Rules...)
	next.Relays = maps.Clone(next.Relays)
	change(&next)
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(s.path, raw, 0600); err != nil {
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
	Name        string       `json:"name"`
	Server      string       `json:"server"`
	Routes      []string     `json:"routes"`
	Fingerprint string       `json:"fingerprint"`
	Relay       ProfileRelay `json:"relay"`
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

func infoFor(name string, p link.Profile) ProfileInfo {
	routes := []string{"fast", "stealth"}
	if p.CDN != "" {
		routes = append(routes, "rescue")
	}
	sum := sha256.Sum256(p.PublicKey[:])
	var fp []string
	for _, b := range sum[:6] {
		fp = append(fp, fmt.Sprintf("%02X", b))
	}
	return ProfileInfo{Name: name, Server: p.Host, Routes: routes, Fingerprint: strings.Join(fp, ":")}
}

// Profiles manages NAME.link files, shared with the CLI.
type Profiles struct {
	dir string
	mu  sync.Mutex
}

func NewProfiles(dir string) *Profiles { return &Profiles{dir: dir} }

func (p *Profiles) path(name string) string { return filepath.Join(p.dir, name+".link") }

// Load reads one profile.
func (p *Profiles) Load(name string) (link.Profile, error) {
	if !config.ValidAlias(name) {
		return link.Profile{}, os.ErrNotExist
	}
	raw, err := sysproxy.ReadPrivate(p.path(name))
	if err != nil {
		return link.Profile{}, err
	}
	return link.Parse(strings.TrimSpace(string(raw)))
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
		if profile, err := p.Load(name); err == nil {
			list = append(list, infoFor(name, profile))
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
	if err := WriteFileAtomic(p.path(name), []byte(encoded+"\n"), 0600); err != nil {
		return ProfileInfo{}, err
	}
	return infoFor(name, profile), nil
}

// Rename moves a profile. It refuses to overwrite another one.
func (p *Profiles) Rename(from, to string) (ProfileInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	profile, err := p.Load(from)
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
	return infoFor(to, profile), nil
}

func (p *Profiles) Delete(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return os.Remove(p.path(name))
}

// Info returns the public info of one profile.
func (p *Profiles) Info(name string) (ProfileInfo, error) {
	profile, err := p.Load(name)
	if err != nil {
		return ProfileInfo{}, err
	}
	return infoFor(name, profile), nil
}

// Preview parses a pasted link without saving it.
func Preview(raw string) (link.Profile, ProfileInfo, error) {
	profile, err := link.Parse(strings.TrimSpace(raw))
	if err != nil {
		return link.Profile{}, ProfileInfo{}, errors.New("That doesn't look like a Pipe link. Copy the whole link that starts with pipe://")
	}
	return profile, infoFor(DefaultName(profile), profile), nil
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
