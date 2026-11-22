"""Synthetic malformed-plan regressions; never used as kernel/device evidence."""
import copy
import unittest

from verify_plan_replay import verify_plan


class PlanReplayTests(unittest.TestCase):
    def setUp(self):
        self.source = bytes(128)
        self.lines = [
            f'PLAN_EDIT offset=64 expected={bytes(48).hex()} replacement={bytes(48).hex()}',
            'PLAN_EDIT offset=120 expected=00 replacement=01',
            'PLAN_SLOT offset=64 length=48',
            'PATCH_PLAN_OK edits=2 credentialInitialized=false flashableCandidate=false',
            'PLAN_REPLAY_OK changedBytes=1',
        ]

    def verify(self, lines=None):
        return verify_plan('\n'.join(self.lines if lines is None else lines), self.source)

    def test_valid_plan_does_not_modify_source(self):
        original = copy.copy(self.source)
        record = self.verify()
        self.assertEqual((record['edits'], record['changedBytes']), (2, 1))
        self.assertEqual(self.source, original)
        self.assertFalse(record['credentialInitialized'])
        self.assertFalse(record['flashableCandidate'])

    def test_marker_missing_or_duplicated(self):
        for i in (2, 3, 4):
            for lines in (self.lines[:i] + self.lines[i + 1:], self.lines + [self.lines[i]]):
                with self.subTest(i=i, lines=len(lines)), self.assertRaises(ValueError):
                    self.verify(lines)

    def test_edit_count_missing_or_malformed(self):
        for edit in ('', 'PLAN_EDIT offset=120 expected=0 replacement=01',
                     'PLAN_EDIT offset=120 expected=zz replacement=01'):
            lines = self.lines.copy()
            lines[1] = edit
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.verify(lines)

    def test_preimage_overlap_range_and_size(self):
        for edit in ('PLAN_EDIT offset=120 expected=02 replacement=01',
                     'PLAN_EDIT offset=100 expected=00 replacement=01',
                     'PLAN_EDIT offset=128 expected=00 replacement=01',
                     'PLAN_EDIT offset=120 expected=00 replacement=0102'):
            lines = self.lines.copy()
            lines[1] = edit
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.verify(lines)

    def test_slot_must_be_contained_and_empty(self):
        for slot in ('PLAN_SLOT offset=8 length=48', 'PLAN_SLOT offset=96 length=48',
                     'PLAN_SLOT offset=64 length=47', 'PLAN_SLOT offset=65 length=48'):
            lines = self.lines.copy()
            lines[2] = slot
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                self.verify(lines)
        lines = self.lines.copy()
        lines[0] = lines[0][:-2] + '01'
        lines[-1] = 'PLAN_REPLAY_OK changedBytes=2'
        with self.assertRaisesRegex(ValueError, 'initialized credentials'):
            self.verify(lines)

    def test_flags_counts_and_late_failure(self):
        for lines in (self.lines[:-1] + ['PLAN_REPLAY_OK changedBytes=0'],
                      self.lines[:-1] + ['PLAN_REPLAY_OK changedBytes=2'],
                      [s.replace('credentialInitialized=false', 'credentialInitialized=true') for s in self.lines],
                      [s.replace('flashableCandidate=false', 'flashableCandidate=true') for s in self.lines],
                      self.lines + ['PATCH_GENERATION_FAILED']):
            with self.subTest(lines=lines[-1]), self.assertRaises(ValueError):
                self.verify(lines)

    def test_digest_covers_replacement_bytes(self):
        original = self.verify()
        lines = self.lines.copy()
        lines[1] = lines[1].replace('replacement=01', 'replacement=02')
        self.assertNotEqual(original['planSha256'], self.verify(lines)['planSha256'])


if __name__ == '__main__':
    unittest.main()
