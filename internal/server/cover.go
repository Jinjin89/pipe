// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"net/http"
	"path"
	"strings"
	"time"

	"pipe/internal/link"
)

type coverPage []byte

func (page coverPage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/index.html"):
		// Remove the explicit index path in the same way as a file server.
		if strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") {
			http.NotFound(w, r)
			return
		}
		location := "./"
		if r.URL.RawQuery != "" {
			location += "?" + r.URL.RawQuery
		}
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusMovedPermanently)
	case path.Clean("/"+r.URL.Path) == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(page))
	default:
		http.NotFound(w, r)
	}
}

type coverEntry struct {
	Heading    string
	Paragraphs []string
}

type coverTheme struct {
	titles, introductions []string
	entries               []coverNote
	listTitles            []string
	listItems             []string
}

type coverNote struct {
	headings   [7]string
	paragraphs []string
}

type coverDocument struct {
	Title, Introduction, ListTitle string
	Description, Footer            string
	Entries                        []coverEntry
	Items                          []string
	Style                          coverStyle
}

var coverTitleFormats = [...]string{
	"%[1]s’s %[2]s · %[3]s",
	"%[3]s %[2]s by %[1]s",
	"%[2]s from %[3]s with %[1]s",
	"%[2]s at %[3]s — %[1]s",
	"%[1]s’s %[2]s in %[3]s",
	"%[3]s | %[2]s with %[1]s",
}

var coverFooterFormats = [...]string{
	"Written by %[1]s in %[2]s.",
	"Thanks for reading. — %[1]s, %[2]s",
	"Kept by %[1]s in a small corner of %[2]s.",
}

const mainCoverLabel = "pipe/v1 cover-site"
const rescueCoverLabel = "pipe/v1 rescue-cover-site"

func generateCoverSite(realityPrivateKey, label string) (coverPage, error) {
	// Both deployment modes already have this key, including older states.
	secret, err := link.DecodeKey(realityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derive default website seed: %w", err)
	}
	seed, err := hkdf.Key(sha256.New, secret[:], nil, label, 32)
	clear(secret[:])
	if err != nil {
		return nil, fmt.Errorf("derive default website seed: %w", err)
	}
	random := rand.New(rand.NewChaCha8([32]byte(seed)))
	clear(seed)

	theme := coverThemes[random.IntN(len(coverThemes))]
	layout := coverLayout(random.IntN(len(coverLayouts)))
	author := coverAuthors[random.IntN(len(coverAuthors))]
	place := coverPlaceNames[random.IntN(len(coverPlaceNames))] + " " + coverPlaceTypes[random.IntN(len(coverPlaceTypes))]
	topic := theme.titles[random.IntN(len(theme.titles))]
	titleFormat := coverTitleFormats[random.IntN(len(coverTitleFormats))]
	document := coverDocument{Title: fmt.Sprintf(titleFormat, author, topic, place)}
	if random.IntN(4) != 0 {
		document.Introduction = fmt.Sprintf(theme.introductions[random.IntN(len(theme.introductions))], place)
	}
	if random.IntN(2) == 0 {
		document.Description = fmt.Sprintf("%s by %s in %s.", topic, author, place)
	}
	if random.IntN(2) == 0 {
		document.Footer = fmt.Sprintf(coverFooterFormats[random.IntN(len(coverFooterFormats))], author, place)
	}
	sections := 1 + random.IntN(len(theme.entries))
	for _, i := range random.Perm(len(theme.entries))[:sections] {
		note := theme.entries[i]
		document.Entries = append(document.Entries, coverEntry{
			Heading:    note.headings[random.IntN(len(note.headings))],
			Paragraphs: note.paragraphs[:1+random.IntN(len(note.paragraphs))],
		})
	}
	if random.IntN(5) < 3 {
		document.ListTitle = theme.listTitles[random.IntN(len(theme.listTitles))]
		items := 1 + random.IntN(len(theme.listItems))
		for _, i := range random.Perm(len(theme.listItems))[:items] {
			document.Items = append(document.Items, theme.listItems[i])
		}
	}
	document.Style = coverStyles(random, layout, len(document.Items) != 0, document.Footer != "")
	return renderCoverDocument(layout, &document)
}
