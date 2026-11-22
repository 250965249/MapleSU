"""Tests of tools/brand/render_advisor_wall.py: the packaged roster, the wall layout and the generated files."""
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brand"))
import render_advisor_wall as wall


def png(width, height):
    """The smallest PNG header image_size() can read."""
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", width, height) + b"\x08\x02\0\0\0"


class AdvisorWallTest(unittest.TestCase):
    def test_packaged_roster_is_valid(self):
        self.assertEqual([], wall.problems(wall.load_members()))

    def test_wall_and_readme_tables_are_current(self):
        self.assertEqual(0, wall.main(["--check"]))

    def test_author_is_centred_largest_and_no_avatars_overlap(self):
        placed = wall.layout(wall.load_members())
        author, x, y, radius, _ = placed[0]
        self.assertEqual("author", author["group"])
        self.assertEqual((0.0, 0.0), (x, y))
        self.assertTrue(all(radius > other for _, _, _, other, _ in placed[1:]))
        for index, (_, x1, y1, r1, _) in enumerate(placed):
            for _, x2, y2, r2, _ in placed[index + 1:]:
                self.assertGreaterEqual(math.hypot(x1 - x2, y1 - y2), r1 + r2)

    def test_special_thanks_are_spread_around_the_author(self):
        # The same roster as AdvisorRosterTest.seatsMatchTheReadmeRenderer, so the Manager's wall matches this one.
        members = [{"id": f"b{i}", "name": f"B{i}", "group": "beta"} for i in range(1, 12)]
        members += [{"id": f"t{i}", "name": f"T{i}", "group": "thanks"} for i in range(1, 4)]
        members.append({"id": "a", "name": "A", "group": "author"})
        seats = [(m["id"], round(x, 4), round(y, 4)) for m, x, y, _ in wall.assign(members)]
        self.assertEqual([("a", 0.0, 0.0), ("t1", 0.5, -0.866), ("b1", 1.0, 0.0), ("t2", 0.5, 0.866),
                          ("b2", -0.5, 0.866), ("t3", -1.0, 0.0), ("b3", -0.5, -0.866)], seats[:7])
        self.assertEqual([("b10", 1.0, -1.7321), ("b11", -1.0, 1.7321)], seats[-2:])

    def test_lens_radius_is_the_integral_of_the_scale(self):
        self.assertAlmostEqual(0.8, wall.lens_radius(1.0), places=5)
        self.assertAlmostEqual(0.9875, wall.lens_radius(wall.FADE_END), places=5)
        self.assertEqual(0.0, wall.lens_scale(wall.FADE_END))

    def test_roster_problems_are_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "avatars").mkdir()
            for name, size in (("a", (200, 200)), ("wide", (300, 200)), ("stray", (200, 200))):
                (directory / "avatars" / f"{name}.png").write_bytes(png(*size))
            members = [
                {"id": "a", "name": "A", "group": "author"},
                {"id": "wide", "name": "W", "group": "thanks", "tags": ["Rust"]},
                {"id": "nopic", "name": "N", "group": "beta", "beta": True},
                {"id": "a", "name": "Again", "group": "beta", "telegram": "@someone"},
            ]
            found = "\n".join(wall.problems(members, directory))
        for expected in ("tag 'Rust' has no badge", "wide.png is 300 × 200", "avatars/nopic.jpg is missing",
                         "beta: true only marks", "duplicate id", "telegram must be",
                         "avatars/stray.png: no member uses this file"):
            self.assertIn(expected, found)


if __name__ == "__main__":
    unittest.main()
