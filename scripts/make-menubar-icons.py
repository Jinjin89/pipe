#!/usr/bin/env python3
"""Draws the macOS menu bar template icons (black on transparent, 36x36 px,
shown at 18 pt). icon_off.png is a hollow outline of the pipe glyph and
icon_on.png is the bold, filled variant. Run from the repo root."""
import math, os
from PIL import Image, ImageDraw

N, SS = 36, 8            # output size, supersampling
S = 31.0 / 37.0          # px per logo unit: the glyph (y 15..52) fills ~31 px


def T(x, y):
    """Logo units (viewBox 64x64, glyph centred near 33.5, 33.5) to supersampled px."""
    return ((x - 33.5) * S + N / 2.0) * SS, ((y - 33.5) * S + N / 2.0) * SS


def pts():
    """Centreline of the logo glyph in 64-unit coordinates: stem, then bowl."""
    stem = [(23 + 0.0, 50 - i * 33 / 40.0) for i in range(41)]  # 50 -> 17
    bowl = [(23 + i * 10 / 20.0, 21) for i in range(21)]          # top edge
    for i in range(1, 40):                                          # arc, r=11
        a = -math.pi / 2 + math.pi * i / 40
        bowl.append((33 + 11 * math.cos(a), 32 + 11 * math.sin(a)))
    bowl += [(33 - i * 10 / 20.0, 43) for i in range(21)]         # bottom edge
    return stem, bowl


def stamp(d, line, width_px, fill):
    r = width_px * SS / 2.0
    for x, y in line:
        cx, cy = T(x, y)
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)


def make(kind):
    m = Image.new("L", (N * SS, N * SS), 0)
    d = ImageDraw.Draw(m)
    stem, bowl = pts()
    if kind == "on":
        stamp(d, stem, 5.6, 255)
        stamp(d, bowl, 5.6, 255)
        d.polygon([T(x, y) for x, y in bowl], fill=255)  # solid bowl
    else:
        stamp(d, stem, 4.6, 255)
        stamp(d, bowl, 4.6, 255)
        stamp(d, stem, 1.8, 0)   # hollow core
        stamp(d, bowl, 1.8, 0)
    a = m.resize((N, N), Image.LANCZOS)
    out = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    out.putalpha(a)
    return out


here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "internal", "menubar")
for k in ("off", "on"):
    make(k).save(os.path.join(here, "icon_%s.png" % k))
