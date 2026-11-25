// SPDX-License-Identifier: GPL-3.0-or-later

package link

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

const qrQuietZone = 4

// QRLevel is the error correction of every Pipe QR code. Codes are shown on
// screens, which don't smudge, so the lowest level wins: a 377-character link
// becomes 69×69 instead of 77×77 modules, and a phone reads the bigger modules
// from farther away and with more blur (measured with simulated camera frames).
const QRLevel = qr.L

// QRSVG encodes text as a crisp inline SVG QR code (error correction QRLevel).
// It returns "" when text is empty or cannot be encoded.
func QRSVG(text string) string {
	if text == "" {
		return ""
	}
	code, err := qr.Encode(text, QRLevel)
	if err != nil {
		return ""
	}
	dim := code.Size + 2*qrQuietZone
	var b strings.Builder
	b.Grow(code.Size * code.Size)
	fmt.Fprintf(&b,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="none" stroke="#000" stroke-width="1" transform="translate(%d %d.5)" d="`,
		dim, dim, dim, dim, qrQuietZone, qrQuietZone,
	)
	for y := range code.Size {
		prev := -1
		for x := 0; x < code.Size; {
			if !code.Black(x, y) {
				x++
				continue
			}
			start := x
			for x < code.Size && code.Black(x, y) {
				x++
			}
			if prev < 0 {
				fmt.Fprintf(&b, "M%d %dh%d", start, y, x-start)
			} else {
				fmt.Fprintf(&b, "m%d 0h%d", start-prev, x-start)
			}
			prev = x
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// QRPNG encodes text as a PNG QR code (error correction QRLevel).
// It returns nil when text is empty or cannot be encoded.
func QRPNG(text string) []byte {
	if text == "" {
		return nil
	}
	code, err := qr.Encode(text, QRLevel)
	if err != nil {
		return nil
	}
	return code.PNG()
}
