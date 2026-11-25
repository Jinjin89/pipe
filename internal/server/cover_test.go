// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"pipe/internal/link"
)

func testCoverKey(index uint64) string {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:8], index)
	return link.EncodeKey(key)
}

func TestCoverSiteDeterministic(t *testing.T) {
	key := testCoverKey(1)
	page, err := generateCoverSite(key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := generateCoverSite(key)
	if err != nil || !bytes.Equal(page, again) {
		t.Fatalf("the same key should give the same page: %v", err)
	}
	different, err := generateCoverSite(testCoverKey(2))
	if err != nil || bytes.Equal(page, different) {
		t.Fatalf("different keys should give different pages: %v", err)
	}
}

func TestCoverSiteDiversity(t *testing.T) {
	const samples = 2500
	const maxRepeatedPages = samples * 2 / 100
	const maxRepeatedSkeletons = samples * 5 / 100
	titleWords := 0
	for _, theme := range coverThemes {
		titleWords += len(theme.titles)
	}
	if combinations := titleWords * len(coverAuthors) * len(coverPlaceNames) * len(coverPlaceTypes) * len(coverTitleFormats); combinations < 100_000 {
		t.Fatalf("only %d title combinations", combinations)
	}

	titles, styles := make(map[string]bool), make(map[string]bool)
	layouts := make(map[atom.Atom]bool)
	sectionCounts, paragraphCounts, listLengths := make(map[int]bool), make(map[int]bool), make(map[int]bool)
	headingFrequency, introFrequency, ruleFrequency := make(map[string]int), make(map[string]int), make(map[string]int)
	ruleSkeletonFrequency, styleSkeletonFrequency, tagSkeletonFrequency := make(map[string]int), make(map[string]int), make(map[string]int)
	intros, descriptions, footers := 0, 0, 0
	smallest, largest := 6<<10, 0
	for i := range samples {
		key := testCoverKey(uint64(i))
		page, err := generateCoverSite(key)
		if err != nil {
			t.Fatal(err)
		}
		smallest, largest = min(smallest, len(page)), max(largest, len(page))
		lower := strings.ToLower(string(page))
		for _, banned := range []string{
			"pipe", "proxy", "vpn", "sing-box", "<script", "<iframe", "<link",
			" src=", " href=", "url(", "@import", "zgotmplz", "&#", "&amp;", "&lt;", "&gt;", "&quot;", "&apos;",
		} {
			if strings.Contains(lower, banned) {
				t.Fatalf("page %d contains %q", i, banned)
			}
		}
		if bytes.Contains(page, []byte(key)) {
			t.Fatalf("page %d contains its key", i)
		}
		for line := range strings.SplitSeq(string(page), "\n") {
			if line != strings.TrimRight(line, " \t") {
				t.Fatalf("page %d has trailing whitespace on %q", i, line)
			}
		}
		doc, err := html.Parse(bytes.NewReader(page))
		if err != nil || doc.FirstChild == nil || doc.FirstChild.Type != html.DoctypeNode || doc.FirstChild.Data != "html" {
			t.Fatalf("page %d has no valid HTML doctype: %v", i, err)
		}
		var title, heading, style string
		tags := make(map[atom.Atom]int)
		selectors := make(map[string]bool)
		pageHeadings := make(map[string]bool)
		for node := range doc.Descendants() {
			if node.Type != html.ElementNode {
				continue
			}
			tags[node.DataAtom]++
			selectors[node.Data] = true
			for _, attr := range node.Attr {
				if attr.Key == "class" {
					for _, class := range strings.Fields(attr.Val) {
						selectors["."+class] = true
					}
				}
			}
			switch node.DataAtom {
			case atom.Title:
				title = node.FirstChild.Data
			case atom.H1:
				heading = node.FirstChild.Data
				next := node.NextSibling
				for next != nil && next.Type != html.ElementNode {
					next = next.NextSibling
				}
				if next != nil && next.DataAtom == atom.P {
					introFrequency[next.FirstChild.Data]++
					intros++
				}
			case atom.H2, atom.Dt, atom.Summary:
				pageHeadings[node.FirstChild.Data] = true
			case atom.Style:
				style = node.FirstChild.Data
			case atom.Meta:
				for _, attr := range node.Attr {
					if attr.Key == "name" && attr.Val == "description" {
						descriptions++
					}
				}
			case atom.Footer:
				footers++
			}
		}
		if title == "" || title != heading || tags[atom.Title] != 1 || tags[atom.H1] != 1 || tags[atom.Main] != 1 {
			t.Fatalf("page %d has inconsistent document headings", i)
		}
		titles[title] = true
		for heading := range pageHeadings {
			headingFrequency[heading]++
		}
		if style == "" || tags[atom.Style] != 1 {
			t.Fatalf("page %d has no stylesheet", i)
		}
		if strings.Contains(style, "hsl(") || coverCSSOverprecision.MatchString(style) {
			t.Fatalf("page %d has unrounded CSS values\n%s", i, style)
		}
		tagSkeletonFrequency[coverHTMLSkeleton(doc)]++
		styles[strings.Join(strings.Fields(style), " ")] = true
		pageRules := make(map[string]bool)
		pageSkeletons := make(map[string]bool)
		var stylesheet []string
		for line := range strings.SplitSeq(strings.TrimSpace(style), "\n") {
			selector, declarations, ok := strings.Cut(strings.TrimSpace(line), "{")
			declarations, closed := strings.CutSuffix(declarations, "}")
			if !ok || !closed || strings.TrimSpace(declarations) == "" {
				t.Fatalf("page %d has an invalid CSS rule %q", i, line)
			}
			for _, part := range strings.Fields(selector) {
				if part != ">" && !selectors[part] {
					t.Fatalf("page %d styles an absent tag or class in %q", i, selector)
				}
			}
			// Ignore selector names so changing only the class cannot make a rule pass.
			pageRules[strings.Join(strings.Fields(declarations), " ")] = true
			skeleton := coverCSSSkeleton(selector, declarations)
			pageSkeletons[skeleton] = true
			stylesheet = append(stylesheet, skeleton)
		}
		for declarations := range pageRules {
			ruleFrequency[declarations]++
		}
		for skeleton := range pageSkeletons {
			ruleSkeletonFrequency[skeleton]++
		}
		slices.Sort(stylesheet)
		styleSkeletonFrequency[strings.Join(stylesheet, "\n")]++
		for _, marker := range []atom.Atom{atom.Article, atom.Dt, atom.Details, atom.Section} {
			if tags[marker] != 0 {
				layouts[marker] = true
				sectionCounts[tags[marker]] = true
				break
			}
		}
		paragraphCounts[tags[atom.P]] = true
		listLengths[tags[atom.Li]] = true
	}
	if len(titles) < samples-10 || len(styles) != samples || len(layouts) != 4 {
		t.Fatalf("got %d titles, %d stylesheets, and %d layouts in %d pages", len(titles), len(styles), len(layouts), samples)
	}
	if len(sectionCounts) < 5 || len(paragraphCounts) < 5 || len(listLengths) < 6 || !listLengths[0] {
		t.Fatalf("page lengths barely varied: sections %v paragraphs %v list items %v", sectionCounts, paragraphCounts, listLengths)
	}
	for _, count := range []int{intros, descriptions, footers} {
		if count == 0 || count == samples {
			t.Fatalf("optional block appears in %d of %d pages", count, samples)
		}
	}
	if smallest < 850 || largest > 6<<10 || largest-smallest < 1800 {
		t.Fatalf("page sizes ranged from %d to %d bytes", smallest, largest)
	}
	for _, group := range []struct {
		name   string
		counts map[string]int
		limit  int
	}{
		{"CSS declaration block", ruleFrequency, maxRepeatedPages},
		{"heading", headingFrequency, maxRepeatedPages},
		{"introduction", introFrequency, maxRepeatedPages},
		{"normalized CSS rule", ruleSkeletonFrequency, maxRepeatedSkeletons},
		{"normalized stylesheet", styleSkeletonFrequency, maxRepeatedSkeletons},
		{"HTML tag skeleton", tagSkeletonFrequency, maxRepeatedSkeletons},
	} {
		most := 0
		for text, count := range group.counts {
			if count > group.limit {
				t.Fatalf("%s %q appears on %d of %d pages", group.name, text, count, samples)
			}
			most = max(most, count)
		}
		t.Logf("most frequent %s appears on %d of %d pages", group.name, most, samples)
	}
	t.Logf("%d distinct titles, %d stylesheets, %d layouts, %d–%d bytes", len(titles), len(styles), len(layouts), smallest, largest)
}

var coverCSSValue = regexp.MustCompile(`#[0-9a-f]{6}|-?(?:[0-9]*\.)?[0-9]+`)
var coverCSSOverprecision = regexp.MustCompile(`\.[0-9]{3,}`)

func coverCSSSkeleton(selector, declarations string) string {
	// Ignore both numeric jitter and declaration order. Keep the selector and
	// property names intact, including the digit in heading selectors.
	var normalized []string
	for declaration := range strings.SplitSeq(declarations, ";") {
		if property, value, ok := strings.Cut(declaration, ":"); ok {
			value = coverCSSValue.ReplaceAllString(strings.TrimSpace(value), "?")
			normalized = append(normalized, strings.TrimSpace(property)+": "+value)
		}
	}
	slices.Sort(normalized)
	return strings.Join(strings.Fields(selector), " ") + " { " + strings.Join(normalized, "; ") + " }"
}

func coverHTMLSkeleton(doc *html.Node) string {
	var out strings.Builder
	var appendTags func(*html.Node)
	appendTags = func(node *html.Node) {
		if node.Type == html.ElementNode {
			out.WriteString("<" + node.Data + ">")
		}
		for child := range node.ChildNodes() {
			appendTags(child)
		}
		if node.Type == html.ElementNode {
			out.WriteString("</" + node.Data + ">")
		}
	}
	appendTags(doc)
	return out.String()
}

func TestCoverColorsHaveReadableContrast(t *testing.T) {
	channelRange := func(color string) (dark, light float64) {
		t.Helper()
		hex, ok := strings.CutPrefix(color, "#")
		rgb, err := strconv.ParseUint(hex, 16, 24)
		if !ok || len(hex) != 6 || err != nil {
			t.Fatalf("invalid RGB color %q", color)
		}
		red, green, blue := rgb>>16, rgb>>8&255, rgb&255
		return float64(min(red, green, blue)) / 255, float64(max(red, green, blue)) / 255
	}
	linear := func(channel float64) float64 {
		if channel <= .04045 {
			return channel / 12.92
		}
		return math.Pow((channel+.055)/1.055, 2.4)
	}
	random := rand.New(rand.NewChaCha8([32]byte{1}))
	for range 2000 {
		palette := coverColors(random)
		// RGB channels bound luminance regardless of the chosen hue.
		paper, _ := channelRange(palette.paper)
		surface, _ := channelRange(palette.surface)
		_, ink := channelRange(palette.ink)
		_, accent := channelRange(palette.accent)
		if ratio := (linear(min(paper, surface)) + .05) / (linear(max(ink, accent)) + .05); ratio < 4.5 {
			t.Fatalf("contrast bound = %.2f, want at least 4.5:1", ratio)
		}
	}
}

func TestCoverRenderEscapesTextAndChecksCSS(t *testing.T) {
	const text = `<b>’ "double" & 'single'</b>`
	const escaped = `&lt;b&gt;’ &#34;double&#34; &amp; &#39;single&#39;&lt;/b&gt;`
	doc := coverDocument{
		Title: text, Description: text, Introduction: text, Footer: text,
		ListTitle: text, Items: []string{text},
		Entries: []coverEntry{{Heading: text, Paragraphs: []string{text}}},
		Style:   coverStyle{Frame: text, Entries: text, List: text, rules: "body { color: #271f17; }"},
	}
	for i := range coverLayouts {
		layout := coverLayout(i)
		page, err := renderCoverDocument(layout, &doc)
		if err != nil {
			t.Fatal(err)
		}
		want := 11
		if layout == coverCardsLayout {
			want++
		}
		if bytes.Count(page, []byte(escaped)) != want || bytes.Contains(page, []byte(text)) {
			t.Fatalf("layout %d should escape all its text and attribute values", i)
		}
	}

	doc.Style.rules = "body { color: black; }</style><p>unexpected markup</p>"
	if _, err := renderCoverDocument(coverNotebookLayout, &doc); err == nil {
		t.Fatal("rendered a stylesheet containing markup")
	}
}

func TestCoverPageServesStaticContent(t *testing.T) {
	page, err := generateCoverSite(testCoverKey(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := httptest.NewRecorder()
		page.ServeHTTP(w, httptest.NewRequest(method, "/", nil))
		want := []byte(page)
		if method == http.MethodHead {
			want = nil
		}
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), want) ||
			w.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
			w.Header().Get("Content-Length") != strconv.Itoa(len(page)) {
			t.Fatalf("%s cover response: status %d, headers %v, %d bytes", method, w.Code, w.Header(), w.Body.Len())
		}
	}
	redirect := httptest.NewRecorder()
	page.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/index.html?view=all", nil))
	if redirect.Code != http.StatusMovedPermanently || redirect.Header().Get("Location") != "./?view=all" {
		t.Fatalf("index redirect: status %d, headers %v", redirect.Code, redirect.Header())
	}
	missing := httptest.NewRecorder()
	page.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if missing.Code != http.StatusNotFound || missing.Body.String() != "404 page not found\n" {
		t.Fatalf("missing page: status %d, body %q", missing.Code, missing.Body.String())
	}
}
