import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseAssetRecordsTest(unittest.TestCase):
    def test_each_record_names_its_spec_relative_to_the_repository(self):
        records = sorted((ROOT / "patch-engine/assets/releases").glob("*.ir.spec.json"))
        self.assertTrue(records)
        for path in records:
            record = json.loads(path.read_text(encoding="utf-8"))
            spec = record["spec"]
            self.assertFalse(Path(spec).is_absolute() or ":" in spec or "\\" in spec,
                             path.name + " stores a machine path: " + spec)
            digest = hashlib.sha256((ROOT / spec).read_bytes()).hexdigest()
            self.assertEqual(record["specSha256"], digest, path.name)


if __name__ == "__main__":
    unittest.main()
