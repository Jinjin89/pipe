// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
)

type coverStyle struct {
	Frame, Entries, List string
	rules                string
}

type coverPalette struct{ paper, ink, accent, surface string }

func coverColor(hue, saturation, lightness float64) string {
	level := lightness / 100
	chroma := (1 - math.Abs(2*level-1)) * saturation / 100
	sector := hue / 60
	second := chroma * (1 - math.Abs(math.Mod(sector, 2)-1))
	offset := level - chroma/2
	channels := [...][3]float64{
		{chroma, second, 0}, {second, chroma, 0}, {0, chroma, second},
		{0, second, chroma}, {second, 0, chroma}, {chroma, 0, second},
	}
	rgb := channels[int(sector)%len(channels)]
	channel := func(value float64) int { return int(math.Round((value + offset) * 255)) }
	return fmt.Sprintf("#%02x%02x%02x", channel(rgb[0]), channel(rgb[1]), channel(rgb[2]))
}

func coverColors(random *rand.Rand) coverPalette {
	r := random.Float64
	hue := 360 * r()
	related := math.Mod(hue+12+46*r(), 360)
	accent := math.Mod(hue+70+120*r(), 360)
	// These ranges bound all background channels above all text channels
	// with at least 4.5:1 contrast, including rounding to 8-bit sRGB.
	return coverPalette{
		paper:   coverColor(hue, 12+27*r(), 95+4*r()),
		surface: coverColor(related, 11+24*r(), 88+6*r()),
		ink:     coverColor(related, 11+24*r(), 12+8*r()),
		accent:  coverColor(accent, 41+29*r(), 13+8*r()),
	}
}

type coverSheet struct {
	random *rand.Rand
	pixels bool
	rules  []string
}

func (s *coverSheet) pick(values ...string) string {
	return values[s.random.IntN(len(values))]
}

// Lengths are selected in hundredths of a rem and optionally converted to whole pixels.
func (s *coverSheet) size(start, step, count int) string {
	value := start + step*s.random.IntN(count)
	if s.pixels {
		return strconv.Itoa((value*16+50)/100) + "px"
	}
	return decimalCoverLength(value, "rem")
}

func decimalCoverLength(value int, unit string) string {
	n := strconv.FormatFloat(float64(value)/100, 'f', 2, 64)
	return strings.TrimRight(strings.TrimRight(n, "0"), ".") + unit
}

func (s *coverSheet) add(selector string, declarations ...string) {
	s.random.Shuffle(len(declarations), func(i, j int) {
		declarations[i], declarations[j] = declarations[j], declarations[i]
	})
	s.rules = append(s.rules, selector+" { "+strings.Join(declarations, "; ")+"; }")
}

func (s *coverSheet) background(color string) string {
	return s.pick("background", "background-color") + ": " + color
}

func (s *coverSheet) padding(vertical, horizontal string) []string {
	if s.random.IntN(2) == 0 {
		return []string{"padding: " + vertical + " " + horizontal}
	}
	return []string{"padding-block: " + vertical, "padding-inline: " + horizontal}
}

var coverFonts = [...]string{
	"Georgia, serif", "Palatino, Georgia, serif", "Cambria, serif",
	"Verdana, sans-serif", "Tahoma, sans-serif", "Arial, sans-serif",
	"system-ui, sans-serif", "ui-serif, Georgia, serif",
}

func (s *coverSheet) typography(size, leading, weight string) []string {
	family := s.pick(coverFonts[:]...)
	if s.random.IntN(2) == 0 {
		return []string{"font: " + weight + " " + size + "/" + leading + " " + family}
	}
	return []string{"font-family: " + family, "font-size: " + size, "line-height: " + leading, "font-weight: " + weight}
}

func (s *coverSheet) heading(selector, ink string, title bool) {
	size := s.size(110, 5, 11)
	leading := s.pick("1.2", "1.3", "1.4")
	if title {
		size = s.size(200, 10, 10)
		leading = s.pick("1.1", "1.2", "1.3")
		if s.random.IntN(2) == 0 {
			size = fmt.Sprintf("clamp(%s, %s, %s)", s.size(160, 10, 6), s.pick("4vw", "5vw", "6vw"), s.size(260, 15, 7))
		}
	}
	gap := s.size(35, 5, 15)
	declarations := []string{
		"color: " + ink,
		s.pick("margin: 0 0 "+gap, "margin-bottom: "+gap, "margin-block-end: "+gap),
	}
	if title || s.random.IntN(2) == 0 {
		declarations = append(declarations, s.typography(size, leading, s.pick("bold", "600", "700"))...)
	} else {
		declarations = append(declarations, "font-size: "+size, "line-height: "+leading)
	}
	if title && s.random.IntN(3) == 0 {
		declarations = append(declarations, "letter-spacing: "+decimalCoverLength(s.random.IntN(7)-4, "em"))
	}
	s.add(selector, declarations...)
}

func coverStyles(random *rand.Rand, layout coverLayout, hasList, hasFooter bool) coverStyle {
	s := coverSheet{random: random, pixels: random.IntN(2) == 0}
	// These names come from separate banks so they cannot collide on a page.
	className := func(names ...string) string {
		return s.pick("local", "quiet", "small", "open", "plain", "daily", "loose", "soft", "light", "short") + "-" + s.pick(names...)
	}
	style := coverStyle{Frame: className("page", "wrap", "sheet", "folio", "frame", "container")}
	frameSelector := "." + style.Frame
	palette := coverColors(random)
	background := palette.paper
	if layout == coverJournalLayout {
		background = palette.surface
	}

	body := s.typography(s.size(100, 5, 5), s.pick("1.4", "1.5", "1.6", "1.7"), "normal")
	body = append(body, s.background(background), "color: "+palette.ink)
	root := s.pick("body", "html")
	if root == "body" {
		body = append(body, s.pick("margin: 0", "margin-block: 0", "margin-inline: 0"))
	}
	s.add(root, body...)

	width := s.size([...]int{3200, 4800, 4500, 3400}[layout], 100, 15)
	padding := s.padding(s.size(120, 20, 12), s.size(90, 10, 14))
	margin := s.size(50, 25, 10)
	frame := append(padding, "box-sizing: border-box", s.pick("max-width: "+width, "width: min(100%, "+width+")"))
	if random.IntN(2) == 0 {
		frame = append(frame, "margin: "+margin+" auto")
	} else {
		frame = append(frame, "margin-inline: auto", "margin-block: "+margin)
	}

	titleParent := [...]string{"header", "body > header", frameSelector + " > aside", "main"}[layout]
	s.heading(s.pick("h1", titleParent+" h1"), palette.accent, true)
	noteTag := [...]string{"article", "section", "dd", "details"}[layout]
	subheading := [...]string{"h2", "h2", "dt", "summary"}[layout]
	subheadingSelector := [...]string{"article h2", "section h2", "dl dt", "details summary"}[layout]
	s.heading(s.pick(subheading, subheadingSelector), palette.accent, false)

	spacing := s.size(70, 10, 14)
	note := []string{s.pick("padding: "+spacing+" 0", "padding-block: "+spacing, "margin-block: "+spacing)}
	if layout == coverCardsLayout {
		note = s.padding(spacing, s.size(70, 10, 12))
		note = append(note, "border-radius: "+s.size(20, 10, 11))
	}
	switch random.IntN(3) {
	case 0:
		note = append(note, "border-bottom: 1px solid "+palette.surface)
	case 1:
		note = append(note, "border-top: 1px solid "+palette.surface)
	case 2:
		note = append(note, "line-height: "+s.pick("1.5", "1.6", "1.7"))
	}
	s.add(s.pick(noteTag, frameSelector+" "+noteTag), note...)

	switch layout {
	case coverNotebookLayout, coverCardsLayout:
		header := s.padding(s.size(80, 20, 13), s.size(50, 10, 13))
		if layout == coverCardsLayout {
			header = append(header, s.pick("text-align: center", "text-align: start"))
		}
		header = append(header, s.pick("border-bottom: 1px solid "+palette.accent, s.background(palette.surface)))
		s.add(s.pick("header", titleParent), header...)
		if layout == coverCardsLayout {
			style.Entries = className("entries", "posts", "clippings", "notes", "sketches", "log")
			gap := "gap: " + s.size(60, 10, 12)
			if random.IntN(2) == 0 {
				s.add("."+style.Entries, "display: grid", "grid-template-columns: repeat(auto-fit, minmax(min(100%, "+s.size(1400, 100, 9)+"), 1fr))", gap)
			} else {
				s.add("."+style.Entries, "display: flex", "flex-wrap: wrap", gap)
				s.add("."+style.Entries+" > section", "box-sizing: border-box", "flex: 1 1 "+s.size(1400, 100, 9))
			}
		}
	case coverSidebarLayout:
		frame = append(frame, "display: flex", "flex-wrap: wrap", "align-items: flex-start", "gap: "+s.size(100, 25, 10))
		s.add(titleParent, "flex: 1 1 "+s.size(1200, 100, 7), s.background(palette.surface), "padding: "+s.size(80, 10, 12),
			s.pick("border-top", "border-left")+": 2px solid "+palette.accent)
		s.add(frameSelector+" > main", "flex: 3 1 "+s.size(1900, 100, 9), "min-width: 0", s.pick("padding-top", "padding-block-start")+": "+s.size(20, 10, 8))
	case coverJournalLayout:
		frame = append(frame, s.background(palette.paper), "border-radius: "+s.size(20, 10, 9))
		if random.IntN(2) == 0 {
			gap := s.size(90, 15, 9)
			s.add(s.pick("hr", frameSelector+" hr"), "border: 0", "height: 1px", s.background(palette.accent),
				s.pick("margin: "+gap+" 0", "margin-block: "+gap))
		}
	}
	s.add(frameSelector, frame...)

	if hasList {
		style.List = className("aside", "extras", "list", "memo", "sidebar", "reminders")
		listSelector := "." + style.List
		s.add(listSelector, s.background(palette.surface), "border-radius: "+s.size(10, 10, 9),
			s.pick("margin-top", "margin-block-start")+": "+s.size(85, 15, 10),
			"padding: "+s.size(75, 10, 8))
		s.heading(listSelector+" h2", palette.accent, false)

		listTag := coverListTag(layout)
		s.add(s.pick(listTag, listSelector+" "+listTag),
			s.pick("padding-left", "padding-inline-start")+": "+s.size(115, 10, 9),
			s.pick("margin-bottom", "margin-block-end")+": "+s.size(10, 10, 7),
			"line-height: "+s.pick("1.4", "1.5", "1.6"))
	}
	if hasFooter {
		footer := s.typography(s.size(80, 5, 6), s.pick("1.4", "1.5", "1.6"), "normal")
		footer = append(footer, "color: "+palette.accent, "text-align: "+s.pick("center", "start"))
		if random.IntN(2) == 0 {
			footer = append(footer, "margin: "+s.size(75, 10, 13)+" auto")
		} else {
			footer = append(footer, "padding-block: "+s.size(75, 10, 13), "padding-inline: "+s.size(75, 10, 13))
		}
		s.add("footer", footer...)
	}
	if random.IntN(3) == 0 {
		selector := s.pick("p", noteTag+" p")
		if random.IntN(2) == 0 {
			width := s.pick("52ch", "56ch", "60ch", "64ch", "68ch", "72ch")
			s.add(selector, s.pick("max-width: "+width, "max-inline-size: "+width, "width: min(100%, "+width+")"))
		} else {
			s.add(selector, s.pick("margin-block", "margin-bottom")+": "+s.size(40, 5, 19))
		}
	}

	random.Shuffle(len(s.rules), func(i, j int) { s.rules[i], s.rules[j] = s.rules[j], s.rules[i] })
	style.rules = strings.Join(s.rules, "\n")
	return style
}

func validCoverCSS(css string) bool {
	// The rule generator needs only ASCII words, numeric values and this
	// punctuation. In particular, raw HTML and escapes cannot enter <style>.
	for _, c := range css {
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.ContainsRune(" \n{}(),-./:;%>#", c) {
			continue
		}
		return false
	}
	return css != ""
}
