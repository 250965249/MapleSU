"""Candidate input provenance and credential framing; no kernel payload execution."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('candidate_builder', ROOT / 'tools/patch/build_candidate.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class CandidateContractTest(unittest.TestCase):
    def setUp(self):
        self.raw = bytearray(b'A' * 128)
        self.edits = [{'offset': 16, 'expected': b'A' * 48, 'replacement': bytes(48)}]
        self.slot = {'offset': 16, 'length': 48}
        self.key = 'K' * 47

    def rejected_unchanged(self, pattern):
        before = bytes(self.raw)
        with self.assertRaisesRegex(SystemExit, pattern):
            builder.apply_plan(self.raw, self.edits, self.slot, self.key)
        self.assertEqual(bytes(self.raw), before)

    def test_runtime_and_slot_credentials_have_distinct_lengths(self):
        credential = builder.runtime_credential(self.key, None)
        self.assertEqual(len(credential), 48)
        self.assertEqual(credential[:-1], self.key)
        self.assertEqual(builder.apply_plan(self.raw, self.edits, self.slot, credential[:-1]), 16)
        self.assertEqual(self.raw[16:64], credential[:-1].encode('ascii') + b'\0')
        self.assertEqual(self.raw[:16] + self.raw[64:], b'A' * 80)

    def test_runtime_credential_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'credential.txt'
            source.write_text('Z' * 48 + '\n', encoding='ascii')
            self.assertEqual(builder.runtime_credential(None, source), 'Z' * 48)
            source.write_text('Z' * 47, encoding='ascii')
            with self.assertRaisesRegex(SystemExit, '48 characters'):
                builder.runtime_credential(None, source)

    def test_generated_runtime_credential_matches_format(self):
        credential = builder.runtime_credential(None, None)
        self.assertEqual(len(credential), 48)
        self.assertTrue(all(ch in builder.ALPHABET for ch in credential))

    def test_invalid_legacy_credentials_are_rejected(self):
        for key in ('', 'K' * 46, 'K' * 48, '!' * 47, '中' * 47):
            with self.subTest(length=len(key)), self.assertRaises(SystemExit):
                builder.runtime_credential(key, None)

    def test_late_preimage_failure_leaves_memory_unchanged(self):
        self.edits.append({'offset': 80, 'expected': b'B' * 4, 'replacement': b'C' * 4})
        self.rejected_unchanged('preimage mismatch')

    def test_overlapping_edits_leave_memory_unchanged(self):
        self.edits.append({'offset': 60, 'expected': b'A' * 8, 'replacement': bytes(8)})
        self.rejected_unchanged('overlaps')

    def test_out_of_bounds_edit_leaves_memory_unchanged(self):
        self.edits.append({'offset': 128, 'expected': b'A', 'replacement': b'B'})
        self.rejected_unchanged('bounds')

    def test_nonzero_slot_replacement_leaves_memory_unchanged(self):
        self.edits[0]['replacement'] = b'X' + bytes(47)
        self.rejected_unchanged('not zero')

    def test_slot_outside_edit_leaves_memory_unchanged(self):
        self.slot['offset'] = 64
        self.rejected_unchanged('not inside')

    def test_invalid_slot_bounds_leave_memory_unchanged(self):
        for offset, length in ((-1, 48), (120, 48), (16, 47)):
            with self.subTest(offset=offset, length=length):
                self.slot = {'offset': offset, 'length': length}
                self.rejected_unchanged('bounds')

    def test_invalid_slot_credential_leaves_memory_unchanged(self):
        self.key = '!' * 47
        self.rejected_unchanged('47 characters')

    def test_valid_plan_parses_and_preserves_edit_count(self):
        edits, slot = builder.parse_plan('diagnostic\nPLAN_EDIT offset=16 expected=4141 replacement=0000\n'
                                         'PLAN_SLOT offset=16 length=48\n')
        self.assertEqual(edits, [{'offset': 16, 'expected': b'AA', 'replacement': bytes(2)}])
        self.assertEqual(slot, self.slot)

    def test_duplicate_missing_and_malformed_plans_are_rejected(self):
        edit = 'PLAN_EDIT offset=16 expected=4141 replacement=0000\n'
        slot = 'PLAN_SLOT offset=16 length=48\n'
        for text in ('', edit, slot, edit + slot + slot, edit + slot.replace('48', '47'),
                     edit + slot + 'PLAN_EDIT invalid', edit + 'PLAN_SLOT invalid'):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                builder.parse_plan(text)


class SourcePairIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='maplesu-pair-test-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.classes = Path(cls.temporary.name)
        cls.jar = ROOT / 'image-core/build/libs/image-core.jar'
        cls.java, javac = builder.tool_path('java'), builder.tool_path('javac')
        subprocess.run([str(javac), '-cp', str(cls.jar), '-d', str(cls.classes),
                        str(ROOT / 'tools/patch/KernelCodec.java')], check=True, capture_output=True)
        cls.classpath = str(cls.jar) + builder.os.pathsep + str(cls.classes)

    def setUp(self):
        self.temporary_case = tempfile.TemporaryDirectory(prefix='maplesu-source-pair-')
        self.addCleanup(self.temporary_case.cleanup)
        self.work = Path(self.temporary_case.name)
        self.raw = bytearray(256)
        self.raw[56:60] = b'ARMd'

    def test_actual_codec_matches_source_in_all_supported_formats(self):
        source = self.work / 'input.raw'
        source.write_bytes(self.raw)
        for compression in ('RAW_ARM64', 'GZIP', 'LZ4_LEGACY'):
            with self.subTest(compression=compression):
                encoded = self.work / 'encoded'
                subprocess.run([str(self.java), '-cp', self.classpath, 'dev.maplesu.image.KernelCodec',
                                'encode', str(source), str(encoded), compression], check=True, capture_output=True)
                component = encoded.read_bytes()
                record = builder.check_source_pair(bytes(4096) + component, bytes(self.raw),
                    {'kernelOffset': 4096, 'kernelSize': len(component), 'compression': compression},
                    self.java, self.classpath, self.work)
                self.assertTrue(record['bootKernelMatchesRaw'])
                self.assertEqual(record['decodedSha256'], builder.digest(self.raw))

    def test_wrong_source_pair_is_rejected_by_actual_codec(self):
        changed = bytearray(self.raw)
        changed[-1] = 1
        with self.assertRaisesRegex(SystemExit, 'differs from the decoded kernel'):
            builder.check_source_pair(bytes(4096) + self.raw, changed,
                {'kernelOffset': 4096, 'kernelSize': len(self.raw), 'compression': 'RAW_ARM64'},
                self.java, self.classpath, self.work)

    def test_truncated_source_component_is_rejected_before_decode(self):
        with self.assertRaisesRegex(SystemExit, 'bounds'):
            builder.check_source_pair(bytes(4096), self.raw,
                {'kernelOffset': 4096, 'kernelSize': 256, 'compression': 'RAW_ARM64'},
                self.java, self.classpath, self.work)

    def test_cli_failure_keeps_false_evidence_and_never_runs_analyzer(self):
        header = bytearray(4096)
        header[:8] = b'ANDROID!'
        struct.pack_into('<I', header, 8, len(self.raw))
        struct.pack_into('<I', header, 20, 1584)
        struct.pack_into('<I', header, 40, 4)
        boot, raw = self.work / 'boot.img', self.work / 'wrong.raw'
        boot.write_bytes(header + self.raw + bytes(4096 - len(self.raw)))
        changed = bytearray(self.raw)
        changed[-1] = 1
        raw.write_bytes(changed)
        out = self.work / 'result'
        command = [sys.executable, str(ROOT / 'tools/patch/build_candidate.py'),
                   '--boot', str(boot), '--kernel', str(raw), '--out', str(out),
                   '--analyzer', str(Path(__file__))]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        evidence = json.loads((out / 'evidence.json').read_text(encoding='utf-8'))
        self.assertFalse(evidence['passed'])
        self.assertIn('differs from the decoded kernel', evidence['error'])
        self.assertTrue(evidence['sourceInputsUnchanged'])
        self.assertEqual(evidence['steps'], [])
        self.assertFalse((out / 'kernel.patched.raw').exists())
        self.assertFalse((out / 'candidate-root-key.txt').exists())
        self.assertFalse((out / 'container').exists())

    def build_fixture(self, compression, name, mutate=False):
        source = self.work / 'input.raw'
        source.write_bytes(self.raw)
        component = self.work / 'fixture.component'
        subprocess.run([str(self.java), '-cp', self.classpath, 'dev.maplesu.image.KernelCodec',
                        'encode', str(source), str(component), compression], check=True, capture_output=True)
        encoded = component.read_bytes()
        header = bytearray(4096)
        header[:8] = b'ANDROID!'
        struct.pack_into('<I', header, 8, len(encoded))
        struct.pack_into('<I', header, 20, 1584)
        struct.pack_into('<I', header, 40, 4)
        boot = self.work / 'fixture.img'
        boot.write_bytes(header + encoded + bytes((-len(encoded)) % 4096))
        credential = self.work / 'fixture-credential.txt'
        credential.write_text('Q' * 48, encoding='ascii')
        out = self.work / name
        command = ['build_candidate.py', '--boot', str(boot), '--kernel', str(source),
                   '--out', str(out), '--analyzer', str(Path(__file__)),
                   '--credential-file', str(credential)]
        real_run = builder.run

        def fixture_analyzer(argv):
            if argv[0] == str(Path(__file__)):
                if mutate:
                    source.write_bytes(bytes(self.raw[:-1]) + b'X')
                return 'PLAN_EDIT offset=128 expected=' + '00' * 48 + ' replacement=' + '00' * 48 + \
                       '\nPLAN_SLOT offset=128 length=48\n'
            return real_run(argv)

        with patch.object(sys, 'argv', command), patch.object(builder, 'run', fixture_analyzer), \
                contextlib.redirect_stdout(io.StringIO()):
            code = builder.main()
        return code, json.loads((out / 'evidence.json').read_text(encoding='utf-8'))

    def test_full_fixture_pipeline_preserves_compression_and_credentials(self):
        for compression in ('RAW_ARM64', 'GZIP', 'LZ4_LEGACY'):
            with self.subTest(compression=compression):
                code, evidence = self.build_fixture(compression, compression)
                self.assertEqual(code, 0, evidence.get('error'))
                self.assertTrue(evidence['passed'])
                self.assertTrue(evidence['sourceInputsUnchanged'])
                self.assertEqual(evidence['patchedComponent']['format'], compression)
                self.assertEqual(Path(evidence['credential']['keyFile']).read_text().strip(), 'Q' * 48)
                patched = Path(evidence['patchedKernel']['path']).read_bytes()
                self.assertEqual(patched[128:176], b'Q' * 47 + b'\0')
                self.assertFalse(evidence['runtimeElevationVerified'])
                self.assertFalse(evidence['fullProParityVerified'])
                self.assertEqual(len(evidence['steps']), 7)
                plan = next(step for step in evidence['steps'] if step['name'] == 'analyze')
                plan_path = Path(evidence['patchedKernel']['path']).parent / 'work/plan.txt'
                self.assertEqual(plan['planSha256'], builder.sha256(plan_path))

    def test_same_runtime_credential_rebuilds_identical_fixture_candidate(self):
        first_code, first = self.build_fixture('LZ4_LEGACY', 'first')
        second_code, second = self.build_fixture('LZ4_LEGACY', 'second')
        self.assertEqual((first_code, second_code), (0, 0))
        self.assertEqual(first['candidate']['sha256'], second['candidate']['sha256'])

    def test_input_mutation_marks_completed_fixture_build_as_failed(self):
        code, evidence = self.build_fixture('RAW_ARM64', 'mutated', mutate=True)
        self.assertEqual(code, 1)
        self.assertFalse(evidence['passed'])
        self.assertFalse(evidence['sourceInputsUnchanged'])
        self.assertEqual(evidence['changedInputs'], ['kernel'])
        self.assertNotIn('candidate', evidence)


if __name__ == '__main__':
    unittest.main()
