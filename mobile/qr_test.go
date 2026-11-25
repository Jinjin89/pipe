// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"math"
	"strings"
	"testing"

	"pipe/internal/link"
)

func sampleSharedLink(t *testing.T, withProxy bool) (string, link.Profile) {
	t.Helper()
	p := link.Profile{
		Host: "203.0.113.10", FastPort: 443, StealthPort: 8443,
		FastSNI: "vpn.example.org", RealitySNI: "vpn.example.org",
		FastPin: link.EncodeKey([32]byte{9, 8, 7, 6}), FastHop: "20000-40000",
		CDN: "static.example.com", WSPath: "/ws/0123456789abcdef0123456789abcdef",
		Name: "my-phone",
	}
	if withProxy {
		p.HTTPSProxy = "vpn.example.org:9443"
	}
	for i := range p.Seed {
		p.Seed[i] = byte(i*7 + 3)
		p.PublicKey[i] = byte(i*13 + 5)
	}
	raw, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw, p
}

func pngToGray(t *testing.T, data []byte) ([]byte, int, int) {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return imageToGray(img)
}

func imageToGray(img image.Image) ([]byte, int, int) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	gray := make([]byte, w*h)
	for y := range h {
		for x := range w {
			r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			gray[y*w+x] = byte((77*(r>>8) + 150*(g>>8) + 29*(bl>>8)) >> 8)
		}
	}
	return gray, w, h
}

func TestDecodeQRRoundTripAndDistortions(t *testing.T) {
	logs.Clear()
	raw, _ := sampleSharedLink(t, true)
	pngBytes := link.QRPNG(raw)
	if len(pngBytes) == 0 {
		t.Fatal("empty QRPNG")
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	modW, modH := b.Dx()/8, b.Dy()/8
	mods := make([]byte, modW*modH)
	for y := range modH {
		for x := range modW {
			r, _, _, _ := img.At(b.Min.X+x*8+4, b.Min.Y+y*8+4).RGBA()
			if r > 0x8000 {
				mods[y*modW+x] = 255
			}
		}
	}
	makeScaled := func(scale int) ([]byte, int, int) {
		w, h := modW*scale, modH*scale
		buf := make([]byte, w*h)
		for y := range h {
			for x := range w {
				buf[y*w+x] = mods[(y/scale)*modW+(x/scale)]
			}
		}
		return buf, w, h
	}
	invert := func(in []byte) []byte {
		out := make([]byte, len(in))
		for i, v := range in {
			out[i] = 255 - v
		}
		return out
	}
	boxBlur := func(in []byte, w, h int) []byte {
		out := make([]byte, len(in))
		for y := range h {
			for x := range w {
				sum, cnt := 0, 0
				for dy := -1; dy <= 1; dy++ {
					ny := y + dy
					if ny < 0 || ny >= h {
						continue
					}
					for dx := -1; dx <= 1; dx++ {
						nx := x + dx
						if nx < 0 || nx >= w {
							continue
						}
						sum += int(in[ny*w+nx])
						cnt++
					}
				}
				out[y*w+x] = byte(sum / cnt)
			}
		}
		return out
	}
	addNoise := func(in []byte, amp int) []byte {
		out := make([]byte, len(in))
		var seed uint32 = 0x12345678
		for i, v := range in {
			seed = seed*1664525 + 1013904223
			delta := int(seed>>24)%(2*amp+1) - amp
			nv := min(max(int(v)+delta, 0), 255)
			out[i] = byte(nv)
		}
		return out
	}
	embed := func(in []byte, sw, sh, fw, fh, stride, ox, oy int, bg byte) []byte {
		out := make([]byte, stride*fh)
		for i := range out {
			out[i] = bg
		}
		for y := range sh {
			copy(out[(oy+y)*stride+ox:], in[y*sw:(y+1)*sw])
		}
		return out
	}
	rotate := func(in []byte, w, h int, deg float64, bg byte) []byte {
		out := make([]byte, w*h)
		rad := deg * math.Pi / 180
		cos, sin := math.Cos(rad), math.Sin(rad)
		cx, cy := float64(w)/2, float64(h)/2
		for y := range h {
			for x := range w {
				dx, dy := float64(x)-cx, float64(y)-cy
				sx := int(math.Round(dx*cos + dy*sin + cx))
				sy := int(math.Round(-dx*sin + dy*cos + cy))
				if sx >= 0 && sx < w && sy >= 0 && sy < h {
					out[y*w+x] = in[sy*w+sx]
				} else {
					out[y*w+x] = bg
				}
			}
		}
		return out
	}

	g4, w4, h4 := makeScaled(4)
	// A 3x3 blur at exactly 4 px per module reads or not depending on the
	// code's bit pattern, at every error correction level; 5 px is stable.
	g5, w5, h5 := makeScaled(5)
	cases := []struct {
		name         string
		gray         []byte
		w, h, stride int
	}{
		{"scale-3", func() []byte { g, _, _ := makeScaled(3); return g }(), modW * 3, modH * 3, modW * 3},
		{"scale-4", g4, w4, h4, w4},
		{"scale-6", func() []byte { g, _, _ := makeScaled(6); return g }(), modW * 6, modH * 6, modW * 6},
		{"scale-8", func() []byte { g, _, _ := makeScaled(8); return g }(), modW * 8, modH * 8, modW * 8},
		{"inverted", invert(g4), w4, h4, w4},
		{"blur", boxBlur(g5, w5, h5), w5, h5, w5},
		{"noise", addNoise(g4, 25), w4, h4, w4},
		{"offset-stride", embed(g4, w4, h4, 640, 480, 704, 180, 90, 120), 640, 480, 704},
		{"dark-terminal", embed(addNoise(boxBlur(invert(g5), w5, h5), 15), w5, h5, 640, 480, 640, 140, 60, 20), 640, 480, 640},
		{"rotated-10deg", rotate(embed(g4, w4, h4, 640, 480, 640, 160, 80, 200), 640, 480, 10, 200), 640, 480, 640},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecodeQR(tc.gray, tc.w, tc.h, tc.stride); got != raw {
				t.Fatalf("DecodeQR(%s) failed to decode expected link", tc.name)
			}
		})
	}
	// Exact-size buffer without trailing stride padding on the last row must work.
	const fw, fh, stride = 640, 480, 704
	tight := embed(g4, w4, h4, fw, fh, stride, 180, 90, 120)[:stride*(fh-1)+fw]
	if got := DecodeQR(tight, fw, fh, stride); got != raw {
		t.Fatal("DecodeQR failed on exact stride*(height-1)+width buffer")
	}

	// Camera frames cycle four thresholds: frames 0 and 2 read dark-on-light
	// codes, 1 and 3 light-on-dark ones, all only inside the centered square.
	const cw, ch = 1600, 720
	g6, w6, h6 := makeScaled(6)
	centered := addNoise(boxBlur(embed(g6, w6, h6, cw, ch, cw, (cw-w6)/2, (ch-h6)/2, 200), cw, ch), 10)
	centeredDark := invert(centered)
	aside := embed(g4, w4, h4, cw, ch, cw, 0, (ch-h4)/2, 200)
	if (cw-ch)/2 < w4 {
		t.Fatal("test code overlaps the centered square")
	}
	for phase := range uint32(4) {
		for _, fc := range []struct {
			name  string
			gray  []byte
			reads bool
		}{
			{"centered", centered, phase%2 == 0},
			{"centered light-on-dark", centeredDark, phase%2 == 1},
			{"outside the square", aside, false},
		} {
			frames.Store(phase)
			want := ""
			if fc.reads {
				want = raw
			}
			if got := DecodeQRFrame(fc.gray, cw, ch, cw); got != want {
				t.Fatalf("DecodeQRFrame phase %d on %s: read=%v, want %v", phase, fc.name, got != "", fc.reads)
			}
		}
	}

	// Non-pipe QR codes must be ignored.
	nonPipe, w, h := pngToGray(t, link.QRPNG("https://example.com/not-a-pipe-link"))
	if got := DecodeQR(nonPipe, w, h, w); got != "" {
		t.Fatalf("expected non-pipe QR to be ignored, got non-empty result")
	}

	if entries, _ := logs.Since(0, 10); len(entries) != 0 {
		t.Fatal("DecodeQR wrote to logs")
	}
}

func TestDecodeQRRejectsBadInputsAndGarbage(t *testing.T) {
	small := make([]byte, 64*64)
	for _, tc := range []struct {
		name         string
		gray         []byte
		w, h, stride int
	}{
		{"nil", nil, 64, 64, 64},
		{"zero width", small, 0, 64, 64},
		{"zero height", small, 64, 0, 64},
		{"neg width", small, -10, 64, 64},
		{"stride < width", small, 64, 64, 63},
		{"short buffer", small[:64*63+63], 64, 64, 64},
		{"short stride buffer", make([]byte, 70*63+63), 64, 64, 70},
		{"over 2MB", make([]byte, 2048*1025), 2048, 1025, 2048},
		{"overflow dims", small, 1 << 30, 4, 1 << 30},
		{"overflow stride", small, 4, 1 << 20, 1 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecodeQR(tc.gray, tc.w, tc.h, tc.stride); got != "" {
				t.Fatalf("expected empty for %s", tc.name)
			}
			if got := DecodeQRFrame(tc.gray, tc.w, tc.h, tc.stride); got != "" {
				t.Fatalf("expected empty frame for %s", tc.name)
			}
		})
	}

	// Garbage frames (tiny, flat, checkerboard, random) must never panic.
	noise := make([]byte, 320*240)
	var seed uint32 = 0xdeadbeef
	for i := range noise {
		seed = seed*1664525 + 1013904223
		noise[i] = byte(seed >> 24)
	}
	checker := make([]byte, 128*128)
	for y := range 128 {
		for x := range 128 {
			if (x+y)&1 == 0 {
				checker[y*128+x] = 255
			}
		}
	}
	for _, g := range []struct {
		buf  []byte
		w, h int
	}{
		{[]byte{0}, 1, 1},
		{make([]byte, 100), 10, 10},
		{bytes.Repeat([]byte{255}, 256*256), 256, 256},
		{checker, 128, 128},
		{noise, 320, 240},
	} {
		if got := DecodeQR(g.buf, g.w, g.h, g.w); got != "" {
			t.Fatalf("garbage %dx%d returned non-empty", g.w, g.h)
		}
		for range 4 {
			if got := DecodeQRFrame(g.buf, g.w, g.h, g.w); got != "" {
				t.Fatalf("garbage frame %dx%d returned non-empty", g.w, g.h)
			}
		}
	}
}

func TestLinkDetails(t *testing.T) {
	logs.Clear()
	raw, profile := sampleSharedLink(t, true)
	wantProxy, ok := link.ProxyURL(profile)
	if !ok {
		t.Fatal("expected ProxyURL")
	}
	body, err := LinkDetails("  " + raw + "\n")
	if err != nil {
		t.Fatal(err)
	}
	var got linkDetails
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Proxy != wantProxy {
		t.Fatalf("proxy mismatch")
	}
	pngBytes, err := base64.StdEncoding.DecodeString(got.QR)
	if err != nil {
		t.Fatal(err)
	}
	gray, w, h := pngToGray(t, pngBytes)
	if decoded := DecodeQR(gray, w, h, w); decoded != raw {
		t.Fatal("LinkDetails QR did not decode back to the link")
	}

	noProxyRaw, _ := sampleSharedLink(t, false)
	body, err = LinkDetails(noProxyRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"proxy":""`) {
		t.Fatalf("expected empty proxy field in JSON: %s", body[:min(80, len(body))])
	}

	bad := "pipe://" + link.EncodeKey(profile.Seed) + "@bad"
	if out, err := LinkDetails(bad); err == nil || out != "" || strings.Contains(err.Error(), link.EncodeKey(profile.Seed)) {
		t.Fatal("invalid link must fail without exposing secrets")
	}
	if entries, _ := logs.Since(0, 10); len(entries) != 0 {
		t.Fatal("LinkDetails wrote to logs")
	}
}
