// SPDX-License-Identifier: GPL-3.0-or-later

package server

import (
	"bytes"
	"errors"
	"html"
)

type coverLayout int

const (
	coverNotebookLayout coverLayout = iota
	coverCardsLayout
	coverSidebarLayout
	coverJournalLayout
)

var coverLayouts = [...]func(*coverHTML, *coverDocument){
	coverNotebookLayout: writeCoverNotebook,
	coverCardsLayout:    writeCoverCards,
	coverSidebarLayout:  writeCoverSidebar,
	coverJournalLayout:  writeCoverJournal,
}

func renderCoverDocument(layout coverLayout, doc *coverDocument) (coverPage, error) {
	if !validCoverCSS(doc.Style.rules) {
		return nil, errors.New("render default website: invalid generated CSS")
	}
	var out coverHTML
	coverLayouts[layout](&out, doc)
	return out.Bytes(), nil
}

type coverHTML struct{ bytes.Buffer }

func (w *coverHTML) text(before, value, after string) {
	w.WriteString(before)
	w.WriteString(html.EscapeString(value))
	w.WriteString(after)
}

func (w *coverHTML) optionalText(before, value, after string) {
	if value != "" {
		w.text(before, value, after)
	}
}

func (w *coverHTML) description(indent, value string) {
	w.optionalText(indent+`<meta name="description" content="`, value, "\">\n")
}

func (w *coverHTML) stylesheet(indent, rules string) {
	w.WriteString(indent + "<style>\n")
	w.WriteString(rules)
	w.WriteString("\n" + indent + "</style>\n")
}

func (w *coverHTML) paragraphs(indent string, values []string) {
	for _, paragraph := range values {
		w.text(indent+"<p>", paragraph, "</p>\n")
	}
}

func coverListTag(layout coverLayout) string {
	if layout == coverCardsLayout {
		return "ol"
	}
	return "ul"
}

func (w *coverHTML) list(doc *coverDocument, indent, container string, layout coverLayout) {
	if len(doc.Items) == 0 {
		return
	}
	listTag := coverListTag(layout)
	w.text(indent+"<"+container+` class="`, doc.Style.List, "\">\n")
	w.text(indent+"  <h2>", doc.ListTitle, "</h2>\n")
	w.WriteString(indent + "  <" + listTag + ">\n")
	for _, item := range doc.Items {
		w.text(indent+"    <li>", item, "</li>\n")
	}
	w.WriteString(indent + "  </" + listTag + ">\n")
	w.WriteString(indent + "</" + container + ">\n")
}

func writeCoverNotebook(w *coverHTML, doc *coverDocument) {
	w.WriteString(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
`)
	w.text("  <title>", doc.Title, "</title>\n")
	w.description("  ", doc.Description)
	w.stylesheet("  ", doc.Style.rules)
	w.WriteString("</head>\n<body>\n")
	w.text(`  <main class="`, doc.Style.Frame, "\">\n")
	w.WriteString("    <header>\n")
	w.text("      <h1>", doc.Title, "</h1>\n")
	w.optionalText("      <p>", doc.Introduction, "</p>\n")
	w.WriteString("    </header>\n")
	for _, entry := range doc.Entries {
		w.WriteString("    <article>\n")
		w.text("      <h2>", entry.Heading, "</h2>\n")
		w.paragraphs("      ", entry.Paragraphs)
		w.WriteString("    </article>\n")
	}
	w.list(doc, "    ", "aside", coverNotebookLayout)
	w.optionalText("    <footer>", doc.Footer, "</footer>\n")
	w.WriteString("  </main>\n</body>\n</html>\n")
}

func writeCoverCards(w *coverHTML, doc *coverDocument) {
	w.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
`)
	w.description("", doc.Description)
	w.text("<title>", doc.Title, "</title>\n")
	w.stylesheet("", doc.Style.rules)
	w.WriteString("</head>\n<body>\n<header>\n")
	w.text("  <h1>", doc.Title, "</h1>\n")
	w.optionalText("  <p>", doc.Introduction, "</p>\n")
	w.WriteString("</header>\n")
	w.text(`<main class="`, doc.Style.Frame, "\">\n")
	w.text(`  <div class="`, doc.Style.Entries, "\">\n")
	for _, entry := range doc.Entries {
		w.WriteString("    <section>\n")
		w.text("      <h2>", entry.Heading, "</h2>\n")
		w.paragraphs("      ", entry.Paragraphs)
		w.WriteString("    </section>\n")
	}
	w.WriteString("  </div>\n")
	w.list(doc, "  ", "aside", coverCardsLayout)
	w.WriteString("</main>\n")
	w.optionalText("<footer>", doc.Footer, "</footer>\n")
	w.WriteString("</body>\n</html>\n")
}

func writeCoverSidebar(w *coverHTML, doc *coverDocument) {
	w.WriteString(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
`)
	w.text("  <title>", doc.Title, "</title>\n")
	w.WriteString("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	w.stylesheet("  ", doc.Style.rules)
	w.description("  ", doc.Description)
	w.WriteString("</head>\n<body>\n")
	w.text(`  <div class="`, doc.Style.Frame, "\">\n")
	w.WriteString("    <aside>\n")
	w.text("      <h1>", doc.Title, "</h1>\n")
	w.optionalText("      <p>", doc.Introduction, "</p>\n")
	w.list(doc, "      ", "section", coverSidebarLayout)
	w.WriteString("    </aside>\n    <main>\n      <dl>\n")
	for _, entry := range doc.Entries {
		w.text("        <dt>", entry.Heading, "</dt>\n")
		w.WriteString("        <dd>\n")
		w.paragraphs("          ", entry.Paragraphs)
		w.WriteString("        </dd>\n")
	}
	w.WriteString("      </dl>\n    </main>\n  </div>\n")
	w.optionalText("  <footer>", doc.Footer, "</footer>\n")
	w.WriteString("</body>\n</html>\n")
}

func writeCoverJournal(w *coverHTML, doc *coverDocument) {
	w.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
`)
	w.text("<title>", doc.Title, "</title>\n")
	w.description("", doc.Description)
	w.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	w.stylesheet("", doc.Style.rules)
	w.WriteString("</head>\n<body>\n")
	w.text(`<main class="`, doc.Style.Frame, "\">\n")
	w.text("  <h1>", doc.Title, "</h1>\n")
	w.optionalText("  <p>", doc.Introduction, "</p>\n")
	w.WriteString("  <hr>\n")
	for _, entry := range doc.Entries {
		w.WriteString("  <details open>\n")
		w.text("    <summary>", entry.Heading, "</summary>\n")
		w.paragraphs("    ", entry.Paragraphs)
		w.WriteString("  </details>\n")
	}
	w.list(doc, "  ", "section", coverJournalLayout)
	w.optionalText("  <footer>", doc.Footer, "</footer>\n")
	w.WriteString("</main>\n</body>\n</html>\n")
}
