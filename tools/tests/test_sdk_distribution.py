import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from sdk_distribution import checked, verify_distribution


class SdkDistributionTest(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((ROOT / 'runtime/maplesu-sdk/SDK-RELEASE.json').read_bytes())

    def test_published_sources_archive_and_embedded_helper_are_paired(self):
        result = verify_distribution(self.manifest, ROOT)
        self.assertEqual(260, result['archiveMembers'])
        self.assertEqual(self.manifest['sdkBuildId'], result['sdkBuildId'])

    def test_changed_archive_is_rejected(self):
        self.manifest['archive']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'input changed'):
            verify_distribution(self.manifest, ROOT)

    def test_wrong_helper_slot_is_rejected(self):
        self.manifest['helper']['keySlotOffset'] += 1
        with self.assertRaisesRegex(AssertionError, 'HELPER_SLOT'):
            verify_distribution(self.manifest, ROOT)

    def test_wrong_backend_identity_is_rejected(self):
        self.manifest['environmentPolicyBoot']['backend']['noteHex'] = '00'
        with self.assertRaises(AssertionError):
            verify_distribution(self.manifest, ROOT)

    def test_outside_source_path_is_rejected(self):
        item = copy.deepcopy(self.manifest['archive'])
        item['path'] = '../' + item['path']
        with self.assertRaisesRegex(ValueError, 'Invalid SDK distribution path'):
            checked(ROOT, item)


if __name__ == '__main__':
    unittest.main()
