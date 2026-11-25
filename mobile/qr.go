// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"

	"pipe/internal/link"

	"github.com/liyue201/goqr"
)

const maxQRPixels = 2 * 1024 * 1024

// DecodeQR scans a grayscale image (a screenshot or photo) for a valid
// pipe:// link. It tries every threshold, light-on-dark codes included.
// It returns "" when no valid pipe link is found or the input is invalid.
func DecodeQR(gray []byte, width, height, stride int) string {
	if !validGray(gray, width, height, stride) {
		return ""
	}
	r := region{gray: gray, stride: stride, width: width, height: height}
	return r.decode(asIs, inverted, r.binarized(false), r.binarized(true))
}

// frames counts camera frames so DecodeQRFrame cycles thresholds.
var frames atomic.Uint32

// DecodeQRFrame scans one camera frame for a valid pipe:// link. It reads only
// the centered square of the frame (the viewfinder sits in its middle) with
// one of DecodeQR's four thresholds per frame, in turn: the min/max midpoint,
// which reads blur, and goqr's own running mean, which reads under glare, each
// for dark-on-light and light-on-dark codes. In simulated phone frames one
// pass over the square read as many codes as four over the whole frame, at a
// fifth of the time, which lets the camera send bigger, sharper frames.
func DecodeQRFrame(gray []byte, width, height, stride int) string {
	if !validGray(gray, width, height, stride) {
		return ""
	}
	side := min(width, height)
	r := region{gray: gray, stride: stride, left: (width - side) / 2, top: (height - side) / 2, width: side, height: side}
	switch (frames.Add(1) - 1) % 4 {
	case 0:
		return r.decode(r.binarized(false))
	case 1:
		return r.decode(r.binarized(true))
	case 2:
		return r.decode(asIs)
	default:
		return r.decode(inverted)
	}
}

func validGray(gray []byte, width, height, stride int) bool {
	switch {
	case width <= 0 || height <= 0 || stride < width || len(gray) < width:
		return false
	case width > maxQRPixels/height:
		return false
	case height > 1 && stride > (len(gray)-width)/(height-1):
		return false
	}
	return stride*(height-1)+width <= len(gray)
}

// region is a rectangle of a grayscale buffer.
type region struct {
	gray                             []byte
	stride, left, top, width, height int
}

func (r region) row(y int) []byte {
	start := (r.top+y)*r.stride + r.left
	return r.gray[start : start+r.width]
}

func asIs(v byte) byte     { return v }
func inverted(v byte) byte { return 255 - v }

// binarized thresholds at the midpoint of the region's darkest and brightest
// pixels. It reads blurred codes that goqr's running-mean threshold misses.
func (r region) binarized(invert bool) func(byte) byte {
	lo, hi := byte(255), byte(0)
	for y := range r.height {
		for _, v := range r.row(y) {
			lo, hi = min(lo, v), max(hi, v)
		}
	}
	if hi-lo < 16 {
		return nil
	}
	mid := byte((int(lo) + int(hi)) / 2)
	if invert {
		return func(v byte) byte {
			if v > mid {
				return 0
			}
			return 255
		}
	}
	return func(v byte) byte {
		if v < mid {
			return 0
		}
		return 255
	}
}

// decode tries each pixel mapping in turn and returns the first valid link.
func (r region) decode(passes ...func(byte) byte) string {
	for _, pixel := range passes {
		if pixel == nil {
			continue
		}
		if s := r.pass(pixel); s != "" {
			return s
		}
	}
	return ""
}

func (r region) pass(pixel func(byte) byte) (out string) {
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	q := goqr.NewRecognizer(r.width, r.height)
	if q == nil {
		return ""
	}
	q.Begin()
	for y := range r.height {
		for x, v := range r.row(y) {
			q.SetPixel(x, y, pixel(v))
		}
	}
	q.End()
	for i := range q.Count() {
		data, err := q.Decode(i)
		if err != nil || len(data.Payload) == 0 {
			continue
		}
		candidate := strings.TrimSpace(string(data.Payload))
		if _, err := link.Parse(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

type linkDetails struct {
	Proxy  string `json:"proxy"`
	Export string `json:"export"`
	QR     string `json:"qr"`
}

// LinkDetails parses raw and returns JSON {"proxy":"...","export":"...","qr":"<base64 PNG>"}.
func LinkDetails(raw string) (string, error) {
	profile, err := link.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	encoded, err := profile.Encode()
	if err != nil {
		return "", err
	}
	pngBytes := link.QRPNG(encoded)
	if len(pngBytes) == 0 {
		return "", errors.New("could not encode device QR")
	}
	proxy, _ := link.ProxyURL(profile)
	body, err := json.Marshal(linkDetails{
		Proxy:  proxy,
		Export: link.ProxyExport(proxy),
		QR:     base64.StdEncoding.EncodeToString(pngBytes),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}
