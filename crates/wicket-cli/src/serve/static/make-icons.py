#!/usr/bin/env python3
"""Draws the console's app icons (icon.svg and the PNGs next to it): three stumps and two bails, a
wicket, in white on the console's accent blue. Full-bleed squares, so they also work as maskable
icons (the motif stays inside the central safe zone). Standard library only; re-run after a change:

    python3 make-icons.py
"""

import struct
import zlib

BG = (0x2F, 0x6F, 0xDE)
FG = (0xFF, 0xFF, 0xFF)

# The motif on a 100x100 canvas: (x, y, width, height) rectangles.
RECTS = [
    (29, 34, 9, 40),  # stumps
    (45.5, 34, 9, 40),
    (62, 34, 9, 40),
    (28, 27, 21, 5),  # bails
    (51, 27, 21, 5),
]


def svg():
    rects = "".join(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="1.5"/>' for x, y, w, h in RECTS)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
        f'<rect width="100" height="100" fill="#{BG[0]:02x}{BG[1]:02x}{BG[2]:02x}"/>'
        f'<g fill="#fff">{rects}</g></svg>\n'
    )


def png(size):
    scale = size / 100
    rows = []
    for py in range(size):
        row = bytearray([0])  # filter: none
        cy = (py + 0.5) / scale
        for px in range(size):
            cx = (px + 0.5) / scale
            inside = any(x <= cx < x + w and y <= cy < y + h for x, y, w, h in RECTS)
            row += bytes(FG if inside else BG)
        rows.append(bytes(row))
    raw = zlib.compress(b"".join(rows), 9)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


if __name__ == "__main__":
    with open("icon.svg", "w") as f:
        f.write(svg())
    for size, name in [(192, "icon-192.png"), (512, "icon-512.png"), (180, "apple-touch-icon.png")]:
        with open(name, "wb") as f:
            f.write(png(size))
