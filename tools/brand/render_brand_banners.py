#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render MapleSU brand banners for documentation.

The ULTRA, NORMAL and MAPLE banners are a line-by-line port of the Manager's renderer
(manager/src/main/java/com/maplesu/core/ui/component/maple/BrandBannerArt.kt,
BrandBanner.kt, UltraBrandTokens.kt, UltraPixelField.kt) to Pillow: the same tokens,
palettes, glyph coverage, motion field and seeded noise. Each one is the settled frame
the Manager shows when system animations are disabled (t = STILL_TIME_SECONDS,
reveal = 1), on a transparent background, in the dark and the light palette with the
Miuix glow. The MapleSU wordmark's travelling sheen is left out, because a frozen
sheen reads as a faded patch rather than a highlight.

The community card (the About dialog's channel line) and the repository social
preview are documentation-only compositions built from the same parts.

The renderer needs the Android platform faces that Typeface.DEFAULT, MONOSPACE and
the CJK fallback resolve to on a stock device: Roboto (Apache-2.0), Droid Sans Mono
(Apache-2.0) and Noto Sans CJK (OFL-1.1). The fonts are not stored in this repository.
They ship, for example, inside Robolectric's nativeruntime-dist-compat artifact:

    unzip -j nativeruntime-dist-compat-*.jar 'fonts/Roboto-*.ttf' \
        fonts/DroidSansMono.ttf 'fonts/NotoSansCJK-*.ttc' -d /tmp/android-fonts
    python3 tools/brand/render_brand_banners.py --fonts /tmp/android-fonts

Only Pillow is required.
"""

from __future__ import annotations

import argparse
import math
import struct
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

REPOSITORY = Path(__file__).resolve().parents[2]

# ── Tokens: BrandBanner.kt / UltraBrandTokens.kt / BrandBannerArt.kt ─────────────

STILL_TIME_SECONDS = 3.4

SQUARE_PITCH = 3.2
SQUARE_CELL = 2.25
SQUARE_GAIN = 1.5
SQUARE_BLOOM_ALPHA = {True: 0.55, False: 0.22}

DOT_PITCH = 4.0
DOT_MIN_RADIUS = 0.55
DOT_RADIUS_RANGE = 1.15
DOT_SWELL_WAVELENGTH = 210.0
DOT_SWELL_SPEED = 20.0
DOT_LEVELS = 5
DOT_BLOOM_ALPHA = {True: 0.22, False: 0.1}

MICRO_ROW = 3.7
MICRO_TEXT = 3.35
MICRO_ROW_SHIFT = 37.3

LEAF_SIZE_RATIO = 0.4
LEAF_GAP_RATIO = 0.05
LEAF_SWAY_SECONDS = 5.2
LEAF_TILT_DEGREES = 19.5
LEAF_SWAY_DEGREES = 4.0
LEAF_BOB = 1.2
LEAF_UNITS = 96.0

BLOOM_RADIUS = 12.0

SWELL_WAVELENGTH, SWELL_SPEED = 170.0, 48.0
SPOT_WAVELENGTH, SPOT_SPEED = 62.0, 72.0
TWINKLE_WAVELENGTH, TWINKLE_SPEED = 23.0, 96.0

TRACKING_EM = 0.02
NOISE_SEED = 0x4D61706C
CREDIT_RIBBON = "MapleAutumn · 小酒 · 晚风 · FinaSU · KernelSU · 7kimisu · KernelPatch · "

# Masks are drawn at this multiple of the output size and box-filtered down.
SUPERSAMPLE = 4

# ── Palettes ────────────────────────────────────────────────────────────────────


def rgb(value: int) -> tuple[int, int, int]:
    return (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF


@dataclass(frozen=True)
class MaplePalette:
    stops: tuple[int, ...]
    body_alpha: float
    bloom_alpha: float


MAPLE = {
    True: MaplePalette((0xEAC26C, 0xFFB05C, 0xF58B55, 0xD95343), 0.28, 0.34),
    False: MaplePalette((0xA8650F, 0xBC5A1E, 0xB23F27, 0x962A28), 0.58, 0.12),
}


@dataclass(frozen=True)
class UltraPalette:
    bloom: int
    cells: tuple[int, ...]


ULTRA = {
    True: UltraPalette(
        0x8B5CF6,
        (0x3B1F7A, 0x5B2EC0, 0x8B5CF6, 0xA780FA, 0xC4A1FF, 0xDDC8FF, 0xF3E8FF),
    ),
    False: UltraPalette(
        0x7C3AED,
        (0xC9B6F2, 0xA88AEE, 0x8B5CF6, 0x7C3AED, 0x6D28D9, 0x5B21B6, 0x4C1D95),
    ),
}

# Normal follows the user's theme colour in the Manager. Documentation uses the
# Material 3 primary (tone 80 dark / tone 40 light) of the built-in Blue preset 0xFF2196F3.
NORMAL_ACCENT = {True: 0x9ECAFF, False: 0x0061A4}

# ── Small numeric helpers matching Kotlin semantics ─────────────────────────────


def round_to_int(value: float) -> int:
    """Kotlin Float.roundToInt(): ties round up."""
    return math.floor(value + 0.5)


def lerp(start: float, stop: float, fraction: float) -> float:
    return start + (stop - start) * fraction


def clamp(value: float, low: float, high: float) -> float:
    return low if value < low else high if value > high else value


_WAVE_LUT = [0.5 + 0.5 * math.sin(2.0 * math.pi * i / 1024) for i in range(1024)]


def wave(cycles: float) -> float:
    """UltraPixelField.wave(): table lookup, truncation toward zero, two's-complement wrap."""
    return _WAVE_LUT[int(cycles * 1024) & 1023]


def row_envelope(rows: int, edge: float) -> list[float]:
    span = max(rows - 1, 1)
    result = []
    for row in range(rows):
        v = abs(2.0 * row / span - 1.0)
        result.append(1.0 - v * v * edge)
    return result


def alpha_of(opacity: float) -> int:
    """withAlpha(): floor(alpha * 255 + 0.5)."""
    return math.floor(clamp(opacity, 0.0, 1.0) * 255.0 + 0.5)


class XorWow:
    """kotlin.random.Random(seed: Int) — XorWowRandom(seed, seed shr 31)."""

    MASK = 0xFFFFFFFF

    def __init__(self, seed: int):
        seed1 = seed & self.MASK
        seed2 = (-1 if seed < 0 else 0) & self.MASK
        self.x, self.y, self.z, self.w = seed1, seed2, 0, 0
        self.v = ~seed1 & self.MASK
        self.addend = ((seed1 << 10) ^ (seed2 >> 4)) & self.MASK
        for _ in range(64):
            self.next_int()

    def next_int(self) -> int:
        t = self.x
        t ^= t >> 2
        self.x, self.y, self.z = self.y, self.z, self.w
        v0 = self.v
        self.w = v0
        t = (t ^ (t << 1) ^ v0 ^ (v0 << 4)) & self.MASK
        self.v = t
        self.addend = (self.addend + 362437) & self.MASK
        return (t + self.addend) & self.MASK

    def next_float(self) -> float:
        return (self.next_int() >> 8) / float(1 << 24)


# ── Minimal OpenType reader: cmap, hmtx and GPOS pair kerning ───────────────────


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def _s16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">h", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


class OpenTypeFace:
    """Enough of an sfnt parser to lay out a word the way HarfBuzz would on Android."""

    def __init__(self, path: Path, index: int = 0):
        self.path = path
        self.index = index
        data = path.read_bytes()
        base = 0
        if data[:4] == b"ttcf":
            base = _u32(data, 12 + 4 * index)
        self.data = data
        self.tables: dict[str, int] = {}
        for i in range(_u16(data, base + 4)):
            record = base + 12 + 16 * i
            self.tables[data[record:record + 4].decode("latin-1")] = _u32(data, record + 8)
        self.units_per_em = _u16(data, self.tables["head"] + 18)
        hhea = self.tables["hhea"]
        self.ascender = _s16(data, hhea + 4)
        self.metric_count = _u16(data, hhea + 34)
        self.cmap = self._read_cmap()
        self.kern_lookups = self._read_kern_lookups()
        self._pil: dict[float, ImageFont.FreeTypeFont] = {}

    def pil(self, size: float) -> ImageFont.FreeTypeFont:
        font = self._pil.get(size)
        if font is None:
            font = ImageFont.truetype(str(self.path), size, index=self.index)
            self._pil[size] = font
        return font

    def has(self, char: str) -> bool:
        return self.cmap.get(ord(char), 0) != 0

    def glyph(self, char: str) -> int:
        return self.cmap.get(ord(char), 0)

    def advance(self, glyph: int) -> int:
        hmtx = self.tables["hmtx"]
        return _u16(self.data, hmtx + 4 * min(glyph, self.metric_count - 1))

    def _read_cmap(self) -> dict[int, int]:
        data, base = self.data, self.tables["cmap"]
        chosen = None
        for i in range(_u16(data, base + 2)):
            platform, encoding, offset = struct.unpack_from(">HHI", data, base + 4 + 8 * i)
            fmt = _u16(data, base + offset)
            if fmt == 12 and (platform, encoding) in ((3, 10), (0, 4), (0, 6)):
                chosen = (base + offset, 12)
                break
            if fmt == 4 and platform in (0, 3) and chosen is None:
                chosen = (base + offset, 4)
        if chosen is None:
            raise ValueError(f"{self.path.name}: no Unicode cmap")
        sub, fmt = chosen
        mapping: dict[int, int] = {}
        if fmt == 4:
            seg2 = _u16(data, sub + 6)
            ends = sub + 14
            starts = ends + seg2 + 2
            deltas = starts + seg2
            ranges = deltas + seg2
            for s in range(seg2 // 2):
                end, start = _u16(data, ends + 2 * s), _u16(data, starts + 2 * s)
                delta, range_offset = _s16(data, deltas + 2 * s), _u16(data, ranges + 2 * s)
                for code in range(start, end + 1):
                    if code == 0xFFFF:
                        continue
                    if range_offset == 0:
                        glyph = (code + delta) & 0xFFFF
                    else:
                        glyph = _u16(data, ranges + 2 * s + range_offset + 2 * (code - start))
                        if glyph:
                            glyph = (glyph + delta) & 0xFFFF
                    mapping[code] = glyph
        else:
            for g in range(_u32(data, sub + 12)):
                first, last, glyph = struct.unpack_from(">III", data, sub + 16 + 12 * g)
                if last - first > 0x4000:  # CJK blocks: not needed for kerning
                    continue
                for code in range(first, last + 1):
                    mapping[code] = glyph + code - first
        return mapping

    def _read_kern_lookups(self) -> list[list[int]]:
        if "GPOS" not in self.tables:
            return []
        data, gpos = self.data, self.tables["GPOS"]
        features = gpos + _u16(data, gpos + 6)
        lookups = gpos + _u16(data, gpos + 8)
        indices: set[int] = set()
        for i in range(_u16(data, features)):
            record = features + 2 + 6 * i
            if data[record:record + 4] == b"kern":
                feature = features + _u16(data, record + 4)
                for k in range(_u16(data, feature + 2)):
                    indices.add(_u16(data, feature + 4 + 2 * k))
        result = []
        for index in sorted(indices):
            lookup = lookups + _u16(data, lookups + 2 + 2 * index)
            kind = _u16(data, lookup)
            subtables = []
            for s in range(_u16(data, lookup + 4)):
                sub = lookup + _u16(data, lookup + 6 + 2 * s)
                sub_kind = kind
                if kind == 9:
                    sub_kind = _u16(data, sub + 2)
                    sub = sub + _u32(data, sub + 4)
                if sub_kind == 2:
                    subtables.append(sub)
            if subtables:
                result.append(subtables)
        return result

    def _coverage(self, table: int, glyph: int) -> int | None:
        data = self.data
        if _u16(data, table) == 1:
            low, high = 0, _u16(data, table + 2) - 1
            while low <= high:
                mid = (low + high) // 2
                value = _u16(data, table + 4 + 2 * mid)
                if value == glyph:
                    return mid
                if value < glyph:
                    low = mid + 1
                else:
                    high = mid - 1
            return None
        for k in range(_u16(data, table + 2)):
            record = table + 4 + 6 * k
            if _u16(data, record) <= glyph <= _u16(data, record + 2):
                return _u16(data, record + 4) + glyph - _u16(data, record)
        return None

    def _class(self, table: int, glyph: int) -> int:
        data = self.data
        if _u16(data, table) == 1:
            start, count = _u16(data, table + 2), _u16(data, table + 4)
            return _u16(data, table + 6 + 2 * (glyph - start)) if start <= glyph < start + count else 0
        for k in range(_u16(data, table + 2)):
            record = table + 4 + 6 * k
            if _u16(data, record) <= glyph <= _u16(data, record + 2):
                return _u16(data, record + 4)
        return 0

    def kerning(self, first: int, second: int) -> int:
        data, total = self.data, 0
        for subtables in self.kern_lookups:
            for sub in subtables:
                covered = self._coverage(sub + _u16(data, sub + 2), first)
                if covered is None:
                    continue
                format1, format2 = _u16(data, sub + 4), _u16(data, sub + 6)
                size1, size2 = 2 * bin(format1).count("1"), 2 * bin(format2).count("1")
                x_advance = 2 * bin(format1 & 0x3).count("1") if format1 & 0x4 else None
                if _u16(data, sub) == 1:
                    pair_set = sub + _u16(data, sub + 10 + 2 * covered)
                    stride = 2 + size1 + size2
                    hit = None
                    for k in range(_u16(data, pair_set)):
                        record = pair_set + 2 + k * stride
                        if _u16(data, record) == second:
                            hit = record + 2
                            break
                    if hit is None:
                        continue
                    if x_advance is not None:
                        total += _s16(data, hit + x_advance)
                    break
                class1 = self._class(sub + _u16(data, sub + 8), first)
                class2 = self._class(sub + _u16(data, sub + 10), second)
                record = sub + 16 + (class1 * _u16(data, sub + 14) + class2) * (size1 + size2)
                if x_advance is not None:
                    total += _s16(data, record + x_advance)
                break
        return total


# ── Text layout (Paint.letterSpacing + kerning) ─────────────────────────────────


@dataclass
class Glyph:
    char: str
    face: OpenTypeFace
    x: float  # pen position relative to the run origin, in px


class TextRun:
    """A laid-out string: per-glyph pen positions plus tight ink bounds at [size]."""

    REFERENCE = 1000.0

    def __init__(self, text: str, faces: list[OpenTypeFace], size: float, tracking_em: float = 0.0):
        self.text = text
        self.size = size
        spacing = tracking_em * size
        pen = spacing / 2.0
        self.glyphs: list[Glyph] = []
        previous: tuple[OpenTypeFace, int] | None = None
        for char in text:
            face = next((f for f in faces if f.has(char)), faces[-1])
            glyph = face.glyph(char)
            scale = size / face.units_per_em
            if previous is not None and previous[0] is face:
                pen += face.kerning(previous[1], glyph) * scale
            self.glyphs.append(Glyph(char, face, pen))
            pen += face.advance(glyph) * scale + spacing
            previous = (face, glyph)
        self.advance = pen - spacing / 2.0

    def bounds(self) -> tuple[float, float, float, float]:
        left = top = math.inf
        right = bottom = -math.inf
        for g in self.glyphs:
            if g.char.isspace():
                continue
            box = g.face.pil(self.REFERENCE).getbbox(g.char, anchor="ls")
            k = self.size / self.REFERENCE
            left = min(left, g.x + box[0] * k)
            top = min(top, box[1] * k)
            right = max(right, g.x + box[2] * k)
            bottom = max(bottom, box[3] * k)
        return left, top, right, bottom

    def draw(self, draw: ImageDraw.ImageDraw, x: float, y: float, scale: float, fill=255, embolden: float = 0.0):
        size = self.size * scale
        for g in self.glyphs:
            if g.char.isspace():
                continue
            kwargs = {}
            if embolden > 0:
                kwargs = {"stroke_width": embolden * scale, "stroke_fill": fill}
            draw.text(((x + g.x) * scale, y * scale), g.char, font=g.face.pil(size), fill=fill, anchor="ls", **kwargs)


@dataclass
class PlacedWord:
    run: TextRun
    x: float
    y: float
    bounds: tuple[float, float, float, float]

    @property
    def right(self) -> float:
        return self.x + self.bounds[2]

    @property
    def top(self) -> float:
        return self.y + self.bounds[1]


def place_word(text, face, fit_width, fit_height, box_width, box_height) -> PlacedWord:
    run = TextRun(text, [face], fit_height, TRACKING_EM)
    left, top, right, bottom = run.bounds()
    size = fit_height * min(fit_width / (right - left), fit_height / (bottom - top))
    run = TextRun(text, [face], size, TRACKING_EM)
    left, top, right, bottom = run.bounds()
    return PlacedWord(
        run=run,
        x=(box_width - (right - left)) / 2.0 - left,
        y=(box_height - (bottom - top)) / 2.0 - top,
        bounds=(left, top, right, bottom),
    )


def word_mask(word: PlacedWord, width: int, height: int) -> Image.Image:
    """Antialiased coverage of the word at SUPERSAMPLE x the output size."""
    mask = Image.new("L", (width * SUPERSAMPLE, height * SUPERSAMPLE), 0)
    word.run.draw(ImageDraw.Draw(mask), word.x, word.y, SUPERSAMPLE)
    return mask


def downsample(image: Image.Image, width: int, height: int) -> Image.Image:
    return image.resize((width, height), Image.Resampling.BOX)


def pixel_values(image: Image.Image) -> list[int]:
    """Single-band pixel values in row order, across Pillow versions."""
    flattened = getattr(image, "get_flattened_data", None)
    return list(flattened() if flattened else image.getdata())


# ── Grid ────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Grid:
    pitch: int
    cols: int
    rows: int
    left: float
    top: float


def banner_grid(width: int, height: int, pitch: int) -> Grid:
    pitch = max(pitch, 2)
    cols, rows = width // pitch, height // pitch
    return Grid(pitch, cols, rows, (width - cols * pitch) / 2.0, (height - rows * pitch) / 2.0)


def grid_coverage(mask_ss: Image.Image, grid: Grid, soft: bool) -> list[float]:
    """wordCoverage(): share of each pitch x pitch cell covered by the glyphs."""
    s = SUPERSAMPLE
    box = (
        round(grid.left * s), round(grid.top * s),
        round((grid.left + grid.cols * grid.pitch) * s), round((grid.top + grid.rows * grid.pitch) * s),
    )
    cells = mask_ss.crop(box).resize((grid.cols, grid.rows), Image.Resampling.BOX)
    values = [v / 255.0 for v in pixel_values(cells)]
    return values if soft else [1.0 if v >= 0.5 else 0.0 for v in values]


def noise_field(count: int) -> list[float]:
    random = XorWow(NOISE_SEED)
    return [random.next_float() for _ in range(count)]


# ── Glow (BlurMaskFilter NORMAL) ────────────────────────────────────────────────


def blur_sigma(radius_px: float) -> float:
    """Skia's BlurMaskFilter radius -> sigma conversion."""
    return 0.57735 * radius_px + 0.5 if radius_px > 0 else 0.0


def glow_layer(mask: Image.Image, color_layer: Image.Image, radius_px: float, opacity: float) -> Image.Image:
    blurred = mask.filter(ImageFilter.GaussianBlur(blur_sigma(radius_px)))
    alpha = blurred.point(lambda v: round(v * opacity))
    layer = color_layer.copy()
    layer.putalpha(alpha)
    return layer


def solid(width: int, height: int, color: int) -> Image.Image:
    return Image.new("RGB", (width, height), rgb(color))


def horizontal_gradient(width: int, height: int, stops: tuple[int, ...]) -> Image.Image:
    """LinearGradient(0, 0, width, 0, stops, positions = null): evenly spaced stops."""
    row = Image.new("RGB", (width, 1))
    pixels = row.load()
    segments = len(stops) - 1
    colors = [rgb(c) for c in stops]
    for x in range(width):
        t = clamp((x + 0.5) / width, 0.0, 1.0) * segments
        i = min(int(t), segments - 1)
        f = t - i
        a, b = colors[i], colors[i + 1]
        pixels[x, 0] = tuple(round(a[k] + (b[k] - a[k]) * f) for k in range(3))
    return row.resize((width, height), Image.Resampling.NEAREST)


# ── Dot banners: ULTRA (squares) and NORMAL (round dots) ────────────────────────


class UltraMotion:
    def __init__(self, grid: Grid, px_per_dp: float, soft: bool):
        last = max(grid.cols - 1, 1)
        pitch_dp = grid.pitch / px_per_dp
        self.rise, self.rise_soft, self.tail = [], [], []
        self.swell_phase, self.spot_phase, self.twinkle_phase = [], [], []
        for col in range(grid.cols):
            u = col / last
            rise = u ** 1.5
            self.rise.append(rise)
            self.rise_soft.append(rise ** 0.7)
            self.tail.append(clamp((1.0 - u) / 0.12, 0.0, 1.0))
            x_dp = col * pitch_dp
            self.swell_phase.append(x_dp / SWELL_WAVELENGTH)
            self.spot_phase.append(x_dp / SPOT_WAVELENGTH)
            self.twinkle_phase.append(x_dp / TWINKLE_WAVELENGTH)
        self.envelope = row_envelope(grid.rows, 0.92 if soft else 0.5)

    def prepare(self, time: float):
        self.swell_shift = time * SWELL_SPEED / SWELL_WAVELENGTH
        self.spot_shift = time * SPOT_SPEED / SPOT_WAVELENGTH
        self.twinkle_shift = time * TWINKLE_SPEED / TWINKLE_WAVELENGTH

    def value(self, col: int, row: int, noise: float, coverage: float) -> float:
        swell = wave(self.swell_phase[col] - self.swell_shift)
        spot = wave(self.spot_phase[col] - self.spot_shift + row / 9.0 + noise * 0.1)
        tw = wave(self.twinkle_phase[col] - self.twinkle_shift + noise)
        tw2 = tw * tw
        twinkle = tw2 * tw2 * tw
        r = self.rise[col]
        field = ((r * (0.3 + 0.26 * swell + 0.28 * spot) + self.rise_soft[col] * twinkle * 0.4)
                 * self.envelope[row] * (0.72 + 0.28 * noise) * 0.62 * self.tail[col])
        if coverage <= 0.0:
            return field
        letter = ((lerp(0.42, 0.86, r) + 0.16 * spot + 0.1 * swell - 0.08 + twinkle * 0.22)
                  * (0.86 + 0.14 * noise))
        return lerp(field, letter, coverage)


class NormalMotion:
    def __init__(self, grid: Grid, px_per_dp: float, soft: bool):
        last = max(grid.cols - 1, 1)
        pitch_dp = grid.pitch / px_per_dp
        self.phase = [col * pitch_dp / DOT_SWELL_WAVELENGTH for col in range(grid.cols)]
        self.edge = [max(math.sin(math.pi * col / last), 0.0) ** 0.9 for col in range(grid.cols)]
        self.envelope = row_envelope(grid.rows, 0.9 if soft else 0.55)

    def prepare(self, time: float):
        self.shift = time * DOT_SWELL_SPEED / DOT_SWELL_WAVELENGTH

    def value(self, col: int, row: int, noise: float, coverage: float) -> float:
        swell = wave(self.phase[col] - self.shift + row * 0.012)
        env = self.envelope[row]
        field = (0.1 + 0.1 * swell) * env * env * (0.7 + 0.3 * noise) * self.edge[col]
        if coverage <= 0.0:
            return field
        return lerp(field, 0.58 + 0.34 * swell + 0.06 * noise, coverage)


@dataclass
class Fonts:
    heavy: OpenTypeFace
    bold: OpenTypeFace
    medium: OpenTypeFace
    mono: OpenTypeFace
    cjk: OpenTypeFace


def dot_banner(kind: str, width: int, height: int, px_per_dp: float, dark: bool, soft: bool,
               fonts: Fonts, accent: int | None = None, time: float = STILL_TIME_SECONDS) -> Image.Image:
    if kind == "ultra":
        palette = ULTRA[dark]
        pitch = max(round_to_int(SQUARE_PITCH * px_per_dp), 3)
        cell = max(round_to_int(SQUARE_CELL * px_per_dp), 2)
        grid = banner_grid(width, height, pitch)
        word = place_word("ULTRA", fonts.heavy, grid.cols * pitch * 0.94, grid.rows * pitch * 0.8, width, height)
        levels = len(palette.cells)
        colors = [
            rgb(palette.cells[level]) + (alpha_of(min(((level + 0.5) / levels) * SQUARE_GAIN + 0.15, 1.0)),)
            for level in range(levels)
        ]
        strokes = [float(cell)] * levels
        half = cell / 2.0
        motion = UltraMotion(grid, px_per_dp, soft)
        round_cap = False
        glow_color, glow_alpha = palette.bloom, SQUARE_BLOOM_ALPHA[dark]
    else:
        accent = NORMAL_ACCENT[dark] if accent is None else accent
        pitch = max(round_to_int(DOT_PITCH * px_per_dp), 3)
        grid = banner_grid(width, height, pitch)
        word = place_word("NORMAL", fonts.bold, grid.cols * pitch * 0.9, grid.rows * pitch * 0.74, width, height)
        levels = DOT_LEVELS
        colors = [rgb(accent) + (alpha_of(min(0.2 + (level + 0.5) / levels * 0.95, 1.0)),) for level in range(levels)]
        strokes = [
            2.0 * (DOT_MIN_RADIUS + DOT_RADIUS_RANGE * (level + 0.5) / levels) * px_per_dp for level in range(levels)
        ]
        half = pitch / 2.0
        motion = NormalMotion(grid, px_per_dp, soft)
        round_cap = True
        glow_color, glow_alpha = accent, DOT_BLOOM_ALPHA[dark]

    mask_ss = word_mask(word, width, height)
    coverage = grid_coverage(mask_ss, grid, soft)
    noise = noise_field(grid.cols * grid.rows)
    motion.prepare(time)

    s = SUPERSAMPLE
    cells = Image.new("RGBA", (width * s, height * s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(cells)
    for row in range(grid.rows):
        y = grid.top + row * grid.pitch + half
        for col in range(grid.cols):
            index = row * grid.cols + col
            v = motion.value(col, row, noise[index], coverage[index])
            if v < 0.035:
                continue
            level = min(int(v * levels), levels - 1)
            x = grid.left + col * grid.pitch + half
            r = strokes[level] / 2.0
            box = ((x - r) * s, (y - r) * s, (x + r) * s - 1, (y + r) * s - 1)
            if round_cap:
                draw.ellipse(box, fill=colors[level])
            else:
                draw.rectangle(box, fill=colors[level])
    art = downsample(cells, width, height)

    out = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    if soft:
        mask = downsample(mask_ss, width, height)
        out = Image.alpha_composite(
            out, glow_layer(mask, solid(width, height, glow_color), BLOOM_RADIUS * px_per_dp, glow_alpha)
        )
    return Image.alpha_composite(out, art)


# ── MapleSU wordmark with microprinted credits ──────────────────────────────────


def leaf_points(cx: float, cy: float, size: float, degrees: float) -> list[tuple[float, float]]:
    outline = [
        (48, 7), (57, 28), (64, 22), (62, 43), (79, 31), (78, 43), (91, 44), (75, 60),
        (80, 66), (56, 70), (52, 78), (47, 78), (42, 70), (17, 66), (22, 60),
        (6, 44), (20, 43), (18, 31), (35, 43), (33, 22), (40, 28),
    ]
    return [leaf_transform(u, v, cx, cy, size, degrees) for u, v in outline]


def leaf_transform(u, v, cx, cy, size, degrees):
    k = size / LEAF_UNITS
    x, y = (u - LEAF_UNITS / 2) * k, (v - LEAF_UNITS / 2) * k
    a = math.radians(degrees)
    return cx + x * math.cos(a) - y * math.sin(a), cy + x * math.sin(a) + y * math.cos(a)


def draw_leaf(width: int, height: int, cx: float, cy: float, size: float, degrees: float,
              start: int, end: int) -> Image.Image:
    """bakeLeaf(): outline filled with a linear gradient, plus the stem, both antialiased."""
    s = SUPERSAMPLE
    mask = Image.new("L", (width * s, height * s), 0)
    draw = ImageDraw.Draw(mask)
    draw.polygon([(x * s, y * s) for x, y in leaf_points(cx, cy, size, degrees)], fill=255)
    stroke = 2.6 * size / LEAF_UNITS * s
    p0 = leaf_transform(48, 70, cx, cy, size, degrees)
    p1 = leaf_transform(49, 92, cx, cy, size, degrees)
    draw.line([(p0[0] * s, p0[1] * s), (p1[0] * s, p1[1] * s)], fill=255, width=max(1, round(stroke)))
    for px, py in (p0, p1):
        r = stroke / 2
        draw.ellipse((px * s - r, py * s - r, px * s + r, py * s + r), fill=255)
    alpha = downsample(mask, width, height)

    g0 = leaf_transform(20, 8, cx, cy, size, degrees)
    g1 = leaf_transform(72, 84, cx, cy, size, degrees)
    dx, dy = g1[0] - g0[0], g1[1] - g0[1]
    length2 = dx * dx + dy * dy
    a, b = rgb(start), rgb(end)
    color = Image.new("RGB", (width, height))
    bbox = alpha.getbbox() or (0, 0, 0, 0)
    pixels = color.load()
    for y in range(bbox[1], bbox[3]):
        for x in range(bbox[0], bbox[2]):
            t = clamp(((x + 0.5 - g0[0]) * dx + (y + 0.5 - g0[1]) * dy) / length2, 0.0, 1.0)
            pixels[x, y] = tuple(round(a[k] + (b[k] - a[k]) * t) for k in range(3))
    color.putalpha(alpha)
    return color


def microprint_mask(width: int, height: int, px_per_dp: float, fonts: Fonts) -> Image.Image:
    """microprintSheet(): staggered rows of the credit ribbon, Droid Sans Mono + CJK fallback."""
    size = MICRO_TEXT * px_per_dp
    run = TextRun(CREDIT_RIBBON, [fonts.mono, fonts.cjk], size)
    ribbon = run.advance
    row_height = MICRO_ROW * px_per_dp
    row_shift = MICRO_ROW_SHIFT * px_per_dp
    # Typeface.create(MONOSPACE, 600): Droid Sans Mono has only 400, so Skia applies
    # fake bold (outline outset of size * 1/24 .. 1/32, interpolated over 9..36 px).
    ratio = 1 / 24 + (1 / 32 - 1 / 24) * clamp((size - 9) / 27, 0.0, 1.0)
    embolden = size * ratio / 2
    s = SUPERSAMPLE
    sheet = Image.new("L", (width * s, height * s), 0)
    draw = ImageDraw.Draw(sheet)
    baseline = fonts.mono.ascender * size / fonts.mono.units_per_em
    row = 0
    while baseline - size < height:
        x = -((row * row_shift) % ribbon)
        while x < width:
            run.draw(draw, x, baseline, s, embolden=embolden)
            x += ribbon
        row += 1
        baseline += row_height
    return sheet


def maple_banner(width: int, height: int, px_per_dp: float, dark: bool, soft: bool, fonts: Fonts,
                 time: float = STILL_TIME_SECONDS) -> Image.Image:
    palette = MAPLE[dark]
    w, h = float(width), float(height)
    leaf_size = h * LEAF_SIZE_RATIO
    leaf_gap = h * LEAF_GAP_RATIO
    leaf_ink = leaf_size * 0.72
    word = place_word("MapleSU", fonts.heavy, w * 0.9 - leaf_ink - leaf_gap, h * 0.88, w - leaf_ink - leaf_gap, h)
    gradient = horizontal_gradient(width, height, palette.stops)

    glyphs = word_mask(word, width, height)
    micro = microprint_mask(width, height, px_per_dp, fonts)
    # Body pass (gradient at bodyAlpha) then microprint pass (BitmapShader), both SRC_OVER.
    over = ImageChops.multiply(micro, glyphs)
    body = glyphs.point(lambda v: round(v * palette.body_alpha))
    alpha_ss = ImageChops.add(over, ImageChops.multiply(body, ImageChops.invert(over)))
    word_layer = gradient.copy()
    word_layer.putalpha(downsample(alpha_ss, width, height))

    out = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    if soft:
        mask = downsample(glyphs, width, height)
        out = Image.alpha_composite(out, glow_layer(mask, gradient, BLOOM_RADIUS * px_per_dp, palette.bloom_alpha))
    out = Image.alpha_composite(out, word_layer)

    sway = math.sin(2 * math.pi * time / LEAF_SWAY_SECONDS)
    leaf_x = word.right + leaf_gap + leaf_size * 0.3
    leaf_y = word.top + leaf_size * 0.46 + LEAF_BOB * px_per_dp * sway
    leaf = draw_leaf(width, height, leaf_x, leaf_y, leaf_size, LEAF_TILT_DEGREES + LEAF_SWAY_DEGREES * sway,
                     palette.stops[1], palette.stops[3])
    return Image.alpha_composite(out, leaf)


# ── Documentation pieces built from the same parts ──────────────────────────────

# GitHub's own foreground colours, so text on transparent artwork matches the page.
PAGE_TEXT = {True: 0xF0F6FC, False: 0x1F2328}
PAGE_MUTED = {True: 0x9198A1, False: 0x59636E}

COMMUNITY_LABEL = {"zh": "官方频道 · 更新与公告", "en": "Official channel · Updates and announcements"}
COMMUNITY_LINK = "Telegram · @KernelMapleSU"


def text_layer(width: int, height: int, run: TextRun, x: float, baseline: float, color: Image.Image,
               opacity: float = 1.0) -> Image.Image:
    s = SUPERSAMPLE
    mask = Image.new("L", (width * s, height * s), 0)
    run.draw(ImageDraw.Draw(mask), x, baseline, s)
    alpha = downsample(mask, width, height)
    if opacity < 1.0:
        alpha = alpha.point(lambda v: round(v * opacity))
    layer = color.copy()
    layer.putalpha(alpha)
    return layer


def rounded_box(width: int, height: int, inset: float, radius: float, color: int, fill: float,
                border: float, border_width: float) -> Image.Image:
    s = SUPERSAMPLE
    box = (inset * s, inset * s, (width - inset) * s - 1, (height - inset) * s - 1)
    fill_mask = Image.new("L", (width * s, height * s), 0)
    ImageDraw.Draw(fill_mask).rounded_rectangle(box, radius * s, fill=round(255 * fill))
    ring = Image.new("L", (width * s, height * s), 0)
    draw = ImageDraw.Draw(ring)
    draw.rounded_rectangle(box, radius * s, fill=round(255 * border))
    inner = tuple(v + border_width * s * sign for v, sign in zip(box, (1, 1, -1, -1)))
    draw.rounded_rectangle(inner, (radius - border_width) * s, fill=0)
    alpha = ImageChops.lighter(fill_mask, ring)
    layer = solid(width, height, color)
    layer.putalpha(downsample(alpha, width, height))
    return layer


def paper_plane(width: int, height: int, cx: float, cy: float, size: float, pitch: int, cell: int,
                stops: tuple[int, ...]) -> Image.Image:
    """A folded paper plane sampled into the Ultra square grid, shaded per facet."""
    k = size / LEAF_UNITS

    def at(u: float, v: float) -> tuple[float, float]:
        return cx + (u - 48) * k, cy + (v - 48) * k

    nose, wing, fold, keel, tail = (91, 9), (4, 45), (41, 58), (67, 88), (47, 84)
    facets = [  # (outline in 96-unit space, brightness)
        ([wing, nose, fold], 1.0),
        ([fold, nose, keel], 0.66),
        ([fold, (55, 67), tail], 0.42),
    ]
    creases = [(fold, nose), (fold, tail)]
    s = SUPERSAMPLE
    shade = Image.new("L", (width * s, height * s), 0)
    draw = ImageDraw.Draw(shade)
    for outline, brightness in facets:
        draw.polygon([(x * s, y * s) for x, y in (at(u, v) for u, v in outline)], fill=round(255 * brightness))
    coverage_mask = Image.new("L", (width * s, height * s), 0)
    cover_draw = ImageDraw.Draw(coverage_mask)
    for outline, _ in facets:
        cover_draw.polygon([(x * s, y * s) for x, y in (at(u, v) for u, v in outline)], fill=255)

    left, top = cx - size / 2, cy - size / 2
    cols = rows = int(size // pitch)
    grid = Grid(pitch, cols, rows, left + (size - cols * pitch) / 2, top + (size - rows * pitch) / 2)
    region = (round(grid.left * s), round(grid.top * s),
              round((grid.left + cols * pitch) * s), round((grid.top + rows * pitch) * s))
    coverage = [v / 255 for v in pixel_values(coverage_mask.crop(region).resize((cols, rows), Image.Resampling.BOX))]
    shading = [v / 255 for v in pixel_values(shade.crop(region).resize((cols, rows), Image.Resampling.BOX))]
    noise = noise_field(cols * rows)
    colors = [rgb(c) for c in stops]

    cells = Image.new("RGBA", (width * s, height * s), (0, 0, 0, 0))
    cell_draw = ImageDraw.Draw(cells)
    for row in range(rows):
        for col in range(cols):
            i = row * cols + col
            if coverage[i] < 0.3:
                continue
            centre = ((grid.left + (col + 0.5) * pitch - cx) / k + 48, (grid.top + (row + 0.5) * pitch - cy) / k + 48)
            if any(segment_distance(centre, a, b) * k < pitch * 0.42 for a, b in creases):
                continue
            value = clamp(shading[i] / max(coverage[i], 1e-6), 0.0, 1.0) * (0.86 + 0.14 * noise[i])
            t = clamp((col + rows - row) / (cols + rows), 0.0, 1.0) * (len(colors) - 1)
            j = min(int(t), len(colors) - 2)
            f = t - j
            base = tuple(round(colors[j][c] + (colors[j + 1][c] - colors[j][c]) * f) for c in range(3))
            opacity = clamp((0.35 + 0.65 * value) * min(coverage[i] * 1.6, 1.0), 0.0, 1.0)
            x = grid.left + col * pitch
            y = grid.top + row * pitch
            cell_draw.rectangle((x * s, y * s, (x + cell) * s - 1, (y + cell) * s - 1), fill=base + (alpha_of(opacity),))
    return downsample(cells, width, height)


def segment_distance(p, a, b) -> float:
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    t = clamp(((p[0] - ax) * dx + (p[1] - ay) * dy) / (dx * dx + dy * dy), 0.0, 1.0)
    return math.hypot(p[0] - ax - t * dx, p[1] - ay - t * dy)


def arrow_layer(width: int, height: int, x: float, y: float, length: float, stroke: float, color: int,
                opacity: float) -> Image.Image:
    """A right-pointing arrow with round caps (Roboto on Android has no U+2192)."""
    s = SUPERSAMPLE
    mask = Image.new("L", (width * s, height * s), 0)
    draw = ImageDraw.Draw(mask)
    head = length * 0.42
    segments = [((x, y), (x + length, y)),
                ((x + length - head, y - head), (x + length, y)),
                ((x + length - head, y + head), (x + length, y))]
    for (x0, y0), (x1, y1) in segments:
        draw.line([(x0 * s, y0 * s), (x1 * s, y1 * s)], fill=255, width=round(stroke * s))
        for px, py in ((x0, y0), (x1, y1)):
            r = stroke * s / 2
            draw.ellipse((px * s - r, py * s - r, px * s + r, py * s + r), fill=255)
    layer = solid(width, height, color)
    layer.putalpha(downsample(mask, width, height).point(lambda v: round(v * opacity)))
    return layer


def community_card(lang: str, dark: bool, fonts: Fonts) -> Image.Image:
    """The About dialog's community line: label, then the channel link, in a tinted card."""
    width, height = 1200, 208
    palette = MAPLE[dark]
    accent = palette.stops[2] if dark else palette.stops[1]
    out = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    out = Image.alpha_composite(out, rounded_box(width, height, 2, 30, accent, 0.09 if dark else 0.06,
                                                 0.30 if dark else 0.24, 2.0))
    out = Image.alpha_composite(out, paper_plane(width, height, 110, height / 2 + 2, 132, 5, 4, palette.stops))

    label = TextRun(COMMUNITY_LABEL[lang], [fonts.medium, fonts.cjk], 34)
    link = TextRun(COMMUNITY_LINK, [fonts.bold, fonts.cjk], 46, 0.005)
    text_x = 214
    out = Image.alpha_composite(out, text_layer(width, height, label, text_x, 86, solid(width, height, PAGE_MUTED[dark])))
    link_color = horizontal_gradient(width, height, palette.stops)
    out = Image.alpha_composite(out, text_layer(width, height, link, text_x, 150, link_color))

    out = Image.alpha_composite(out, arrow_layer(width, height, width - 104, height / 2, 40, 5, accent, 0.85))
    return out


def social_preview(fonts: Fonts) -> Image.Image:
    """1280 x 640 repository card: opaque, dark, wordmark over both mode marks."""
    width, height = 1280, 640
    base = Image.new("RGBA", (width, height), (11, 13, 18, 255))
    # Warm light from the wordmark, cool light from the mode marks.
    glow = Image.new("L", (width, height), 0)
    ImageDraw.Draw(glow).ellipse((190, 40, 1090, 420), fill=46)
    glow = glow.filter(ImageFilter.GaussianBlur(120))
    warm = solid(width, height, 0xF58B55)
    warm.putalpha(glow)
    base = Image.alpha_composite(base, warm)

    hero = maple_banner(1100, 318, 3.06, True, True, fonts)
    base.alpha_composite(hero, ((width - hero.width) // 2, 56))
    ultra = dot_banner("ultra", 480, 134, 1.4, True, True, fonts)
    normal = dot_banner("normal", 480, 134, 1.4, True, True, fonts)
    gap = 36
    left = (width - 2 * 480 - gap) // 2
    base.alpha_composite(ultra, (left, 402))
    base.alpha_composite(normal, (left + 480 + gap, 402))

    caption = TextRun("Kernel-level root  ·  Normal & Ultra  ·  Android 12+ ARM64", [fonts.medium], 26, 0.02)
    cl, ct, cr, cb = caption.bounds()
    base = Image.alpha_composite(base, text_layer(width, height, caption, (width - (cr - cl)) / 2 - cl, 598,
                                                  solid(width, height, 0x9198A1)))
    return base.convert("RGB")


# ── Entry point ─────────────────────────────────────────────────────────────────


def load_fonts(directory: Path) -> Fonts:
    def face(name: str, index: int = 0) -> OpenTypeFace:
        path = directory / name
        if not path.exists():
            raise SystemExit(f"missing font: {path}")
        return OpenTypeFace(path, index)

    cjk = next((n for n in ("NotoSansCJK-Medium.ttc", "NotoSansCJK-Regular.ttc", "NotoSansCJK-Bold.ttc")
                if (directory / n).exists()), None)
    if cjk is None:
        raise SystemExit(f"missing font: {directory}/NotoSansCJK-*.ttc")
    return Fonts(
        heavy=face("Roboto-Black.ttf"),
        bold=face("Roboto-Bold.ttf"),
        medium=face("Roboto-Medium.ttf"),
        mono=face("DroidSansMono.ttf"),
        cjk=face(cjk, 2),  # index 2 = Simplified Chinese
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fonts", type=Path, required=True, help="directory with the Android platform fonts")
    parser.add_argument("--out", type=Path, default=REPOSITORY / "docs/assets/brand", help="output directory")
    parser.add_argument("--only", nargs="*", choices=("maplesu", "ultra", "normal", "community", "social"),
                        help="render only these pieces")
    args = parser.parse_args()

    fonts = load_fonts(args.fonts)
    args.out.mkdir(parents=True, exist_ok=True)
    wanted = set(args.only or [])

    def emit(name: str, image: Image.Image) -> None:
        path = args.out / f"{name}.png"
        image.save(path, optimize=True)
        print(f"{path}  {image.width}x{image.height}")

    for dark in (True, False):
        theme = "dark" if dark else "light"
        if not wanted or "maplesu" in wanted:
            emit(f"maplesu-{theme}", maple_banner(1800, 520, 5.0, dark, True, fonts))
        if not wanted or "ultra" in wanted:
            emit(f"ultra-{theme}", dot_banner("ultra", 1032, 288, 3.0, dark, True, fonts))
        if not wanted or "normal" in wanted:
            emit(f"normal-{theme}", dot_banner("normal", 1032, 288, 3.0, dark, True, fonts))
        if not wanted or "community" in wanted:
            for lang in ("zh", "en"):
                emit(f"community-{lang}-{theme}", community_card(lang, dark, fonts))
    if not wanted or "social" in wanted:
        emit("social-preview", social_preview(fonts))


if __name__ == "__main__":
    main()
