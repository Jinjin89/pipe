// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"cmp"
	"regexp"
	"strings"
)

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([a-z0-9-]+(?:\.[a-z0-9-]+)*))?$`)

type releaseVersion struct {
	numbers []string
	pre     []string
	channel string
}

// ChannelOf returns the release channel ("stable", "alpha", ...) of ver.
func ChannelOf(ver string) (string, bool) {
	v, ok := parseVersion(ver)
	if !ok {
		return "", false
	}
	return v.channel, true
}

// CompareVersions compares two Pipe semantic versions on any channel.
func CompareVersions(a, b string) (int, bool) {
	va, oka := parseVersion(a)
	vb, okb := parseVersion(b)
	if !oka || !okb {
		return 0, false
	}
	return va.compare(vb), true
}

func parseVersion(text string) (releaseVersion, bool) {
	if len(text) > 80 {
		return releaseVersion{}, false
	}
	m := versionPattern.FindStringSubmatch(text)
	if m == nil {
		return releaseVersion{}, false
	}
	v := releaseVersion{numbers: m[1:4], channel: "stable"}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
		v.channel = v.pre[0]
		if v.channel[0] < 'a' || v.channel[0] > 'z' || v.channel == "stable" {
			return releaseVersion{}, false
		}
		for _, part := range v.pre {
			if numeric(part) && len(part) > 1 && part[0] == '0' {
				return releaseVersion{}, false
			}
		}
	}
	return v, true
}

func numeric(part string) bool {
	return strings.IndexFunc(part, func(c rune) bool { return c < '0' || c > '9' }) < 0
}

func compareNumber(a, b string) int {
	if n := cmp.Compare(len(a), len(b)); n != 0 {
		return n
	}
	return strings.Compare(a, b)
}

func (v releaseVersion) compare(w releaseVersion) int {
	for i, n := range v.numbers {
		if order := compareNumber(n, w.numbers[i]); order != 0 {
			return order
		}
	}
	if len(v.pre) == 0 || len(w.pre) == 0 {
		return cmp.Compare(len(w.pre), len(v.pre))
	}
	for i := 0; i < min(len(v.pre), len(w.pre)); i++ {
		a, b := v.pre[i], w.pre[i]
		an, bn := numeric(a), numeric(b)
		order := strings.Compare(a, b)
		switch {
		case an && bn:
			order = compareNumber(a, b)
		case an:
			order = -1
		case bn:
			order = 1
		}
		if order != 0 {
			return order
		}
	}
	return cmp.Compare(len(v.pre), len(w.pre))
}
