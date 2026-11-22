"""Independent offline verifier regressions; real Java codecs, no device I/O."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('independent_candidate_verifier',
                                              ROOT / 'tools/patch/verify_candidate.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class IndependentCandidateVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix='maplesu-verifier-codec-test-')
        cls.addClassCleanup(cls.shared.cleanup)
        cls.classes = Path(cls.shared.name)
        cls.java, cls.javac = verifier.java_tools()
        cls.jar = ROOT / 'image-core/build/libs/image-core.jar'
        subprocess.run([str(cls.javac), '-cp', str(cls.jar), '-d', str(cls.classes),
                        str(ROOT / 'tools/patch/KernelCodec.java')], capture_output=True, check=True)
        cls.classpath = str(cls.jar) + os.pathsep + str(cls.classes)
        cls.aosp = {name: {'commit': commit, 'files': {
            filename: verifier.digest((ROOT / '.research' / directory / filename).read_bytes())
            for filename in files}}
            for name, (directory, commit, files) in verifier.AOSP_SOURCES.items()}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='maplesu-verifier-case-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.out = self.work / 'candidate'
        (self.out / 'work').mkdir(parents=True)
        (self.out / 'container').mkdir()
        self.evidence_path = self.out / 'evidence.json'
        self.key = b'Q' * 47 + b'Z'
        self.raw = bytearray(512)
        self.raw[56:60] = b'ARMd'
        self.raw[128:176] = b'A' * 48
        self.patched = bytearray(self.raw)
        self.patched[128:176] = self.key[:-1] + b'\0'
        self.plan = ('PLAN_EDIT offset=128 expected=' + '41' * 48 + ' replacement=' + '00' * 48
                     + '\nPLAN_SLOT offset=128 length=48\n'
                     + 'PATCH_PLAN_OK edits=1 credentialInitialized=false flashableCandidate=false\n'
                     + 'PLAN_REPLAY_OK changedBytes=48\n')
        self.ramdisk = b'original ramdisk\x00\xff'

    @staticmethod
    def item(path):
        data = path.read_bytes()
        return {'path': str(path), 'size': len(data), 'sha256': verifier.digest(data)}

    def encode(self, data, format_name, name):
        source, destination = self.work / (name + '.raw'), self.work / (name + '.encoded')
        source.write_bytes(data)
        subprocess.run([str(self.java), '-cp', self.classpath, 'dev.maplesu.image.KernelCodec',
                        'encode', str(source), str(destination), format_name], capture_output=True, check=True)
        return destination.read_bytes()

    def boot(self, component):
        header = bytearray(4096)
        header[:8] = b'ANDROID!'
        struct.pack_into('<4I', header, 8, len(component), len(self.ramdisk), 0, 1584)
        struct.pack_into('<I', header, 40, 4)
        return (header + component + bytes(-len(component) % 4096)
                + self.ramdisk + bytes(-len(self.ramdisk) % 4096))

    def save(self):
        self.evidence_path.write_text(json.dumps(self.evidence), encoding='utf-8')

    def fixture(self, format_name='RAW_ARM64'):
        original_component = self.encode(self.raw, format_name, 'original')
        patched_component = self.encode(self.patched, format_name, 'patched')
        boot, raw = self.work / 'boot.img', self.work / 'input.raw'
        patched, component = self.out / 'kernel.patched.raw', self.out / 'kernel.component'
        candidate, rebuild = self.out / 'container/boot.img', self.out / 'container/rebuild.json'
        key_file, plan_file = self.out / 'candidate-root-key.txt', self.out / 'work/plan.txt'
        for path, data in ((boot, self.boot(original_component)), (raw, self.raw),
                           (patched, self.patched), (component, patched_component),
                           (candidate, self.boot(patched_component)), (key_file, self.key + b'\r\n')):
            path.write_bytes(data)
        plan_file.write_text(self.plan, encoding='utf-8')
        tool = self.work / 'recorded-not-executed-tool'
        tool.write_bytes(b'tool identity fixture')
        source_paths = {name: tool for name in verifier.SOURCE_NAMES}
        source_paths.update({'boot': boot, 'kernel': raw, 'imageCoreJar': self.jar,
                             'codecDriver': ROOT / 'tools/patch/KernelCodec.java',
                             'java': self.java, 'javac': self.javac, 'python': Path(sys.executable)})
        sources = {name: {'path': str(path), 'sha256': verifier.digest(path.read_bytes())}
                   for name, path in source_paths.items()}
        original_layout, layout = verifier.boot_v4(boot.read_bytes()), verifier.boot_v4(candidate.read_bytes())
        rebuild_record = {'schemaVersion': 1, 'passed': True, 'sourcesUnchanged': True,
                          'toolSha256': sources['repack']['sha256'],
                          'inputs': {'boot': self.item(boot), 'kernel': self.item(component)},
                          'candidate': {**self.item(candidate), 'layout': layout},
                          'originalLayout': original_layout, 'aospSources': self.aosp,
                          **{name: False for name in ('flashableCandidate', 'partitionWrites',
                              'verificationDisabled', 'kernelPayloadExecuted', 'deviceBootTestPerformed',
                              'candidateGkiSignaturePresent', 'candidateAvbFooterPresent')}}
        rebuild.write_text(json.dumps(rebuild_record), encoding='utf-8')
        self.evidence = {'schemaVersion': 2, 'operation': 'BUILD_OFFLINE_CANDIDATE', 'passed': True,
            'credentialInitialized': True, **{name: False for name in verifier.FALSE_FLAGS},
            'sourceInputsUnchanged': True, 'changedInputs': [], 'sourceInputs': sources,
            'sources': {name: sources[name]['sha256'] for name in
                        ('analyzer', 'repack', 'imageCoreJar', 'builder', 'codecDriver')},
            'inputs': {'boot': self.item(boot), 'kernel': self.item(raw), 'layout': {
                name: original_layout[name] for name in
                ('headerVersion', 'headerSize', 'kernelOffset', 'kernelSize', 'ramdiskSize')}},
            'patchedKernel': self.item(patched),
            'patchedComponent': {**self.item(component), 'format': format_name},
            'candidate': self.item(candidate),
            'credential': {'keyFile': str(key_file), 'keySha256': verifier.digest(self.key),
                           'runtimeInputLength': 48, 'kernelComparedLength': 47, 'slotLength': 48,
                           'runtimeTransform': 'drop-last-character', 'contractVerifiedStatically': True,
                           'runtimeElevationVerified': False},
            'rebuildEvidence': {**self.item(rebuild), 'aospSources': self.aosp},
            'changedBytes': 48, 'planEdits': 1,
            'steps': [
                {'name': 'verify-source-pair', 'compression': format_name,
                 'componentSha256': verifier.digest(original_component),
                 'decodedSha256': verifier.digest(self.raw), 'bootKernelMatchesRaw': True},
                {'name': 'analyze', 'exitCode': 0, 'edits': 1, 'deterministic': True,
                 'planSha256': verifier.digest(plan_file.read_bytes()), 'slot': {'offset': 128, 'length': 48}},
                {'name': 'apply-plan', 'changedBytes': 48, 'credentialSlot': 128},
                {'name': 'structural-checks', 'changedOffsets': 48,
                 'diffsInsidePlannedRanges': True, 'allPlannedRegionsMatch': True},
                {'name': 'encode', 'format': format_name, 'rawBytes': len(self.raw),
                 'compressedBytes': len(patched_component), 'compressedSha256': verifier.digest(patched_component),
                 'roundTripVerified': True},
                {'name': 'rebuild-container', **self.item(candidate), 'containerVerified': True,
                 'replacementKernelVerified': True, 'ramdiskPreserved': True},
                {'name': 'verify-candidate', 'payloadMatch': True, 'credentialPresent': True,
                 'inspect': {**layout, 'sha256': verifier.digest(candidate.read_bytes()),
                             'fileSize': candidate.stat().st_size, 'compression': format_name}},
            ]}
        self.save()
        return self.evidence

    def test_real_codec_and_full_candidate_in_all_formats(self):
        for format_name in ('RAW_ARM64', 'GZIP', 'LZ4_LEGACY'):
            with self.subTest(format=format_name):
                self.fixture(format_name)
                report = verifier.verify(self.evidence_path)
                self.assertTrue(report['passed'])
                self.assertTrue(all(report['checks'].values()))
                self.assertEqual(report['changedBytes'], 48)
                self.assertTrue(all(report[name] is False for name in verifier.FALSE_FLAGS))
                self.assertNotIn(self.key.decode(), json.dumps(report))

    def test_wrong_artifact_digest_rejected(self):
        self.fixture()
        self.evidence['candidate']['sha256'] = '0' * 64
        self.save()
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            verifier.verify(self.evidence_path)

    def test_plan_digest_is_exact_file_bytes(self):
        self.fixture()
        path = self.out / 'work/plan.txt'
        path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            verifier.verify(self.evidence_path)

    def test_tool_replacement_rejected(self):
        self.fixture()
        Path(self.evidence['sourceInputs']['analyzer']['path']).write_bytes(b'replaced tool')
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            verifier.verify(self.evidence_path)

    def test_plan_overlap_bounds_preimage_and_slot_failures(self):
        cases = (
            self.plan.replace('offset=128 expected=', 'offset=500 expected='),
            self.plan.replace('expected=' + '41' * 48, 'expected=' + '42' * 48),
            self.plan.replace('replacement=' + '00' * 48, 'replacement=' + '00' * 47),
            self.plan.replace('PLAN_SLOT offset=128', 'PLAN_SLOT offset=129'),
            self.plan.replace('replacement=' + '00' * 48, 'replacement=' + '01' * 48),
            self.plan.replace('edits=1', 'edits=2'),
            self.plan + 'PLAN_SLOT offset=128 length=48\n',
            self.plan + 'PLAN_SLOT invalid\n',
            self.plan.replace('length=48', 'length=47'),
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                verifier.replay_plan(case, self.raw, self.key)

    def test_overlap_rejected(self):
        plan = self.plan.replace('edits=1', 'edits=2') + 'PLAN_EDIT offset=160 expected=41 replacement=00\n'
        with self.assertRaisesRegex(ValueError, 'overlap'):
            verifier.replay_plan(plan, self.raw, self.key)

    def test_credential_contract_drops_only_last_character(self):
        output, metadata = verifier.replay_plan(self.plan, self.raw, self.key)
        self.assertEqual(output[128:176], b'Q' * 47 + b'\0')
        self.assertEqual(output[:128] + output[176:], self.raw[:128] + self.raw[176:])
        self.assertEqual(metadata['changedBytes'], 48)
        for credential in (self.key[:-1], self.key + b'X', b'!' * 48):
            with self.subTest(length=len(credential)), self.assertRaises(ValueError):
                verifier.replay_plan(self.plan, self.raw, credential)

    def test_changes_outside_plan_rejected_with_refreshed_digest(self):
        self.fixture()
        path = Path(self.evidence['patchedKernel']['path'])
        data = bytearray(path.read_bytes())
        data[250] = 1
        path.write_bytes(data)
        self.evidence['patchedKernel'] = self.item(path)
        self.save()
        with self.assertRaisesRegex(ValueError, 'complete independent plan replay'):
            verifier.verify(self.evidence_path)

    def test_candidate_component_substitution_rejected(self):
        self.fixture()
        path = Path(self.evidence['candidate']['path'])
        data = bytearray(path.read_bytes())
        data[4096 + 250] = 1
        path.write_bytes(data)
        self.evidence['candidate'] = self.item(path)
        self.save()
        with self.assertRaisesRegex(ValueError, 'substituted kernel component'):
            verifier.verify(self.evidence_path)

    def test_ramdisk_change_rejected(self):
        self.fixture()
        path = Path(self.evidence['candidate']['path'])
        data = bytearray(path.read_bytes())
        data[8192] ^= 1
        path.write_bytes(data)
        self.evidence['candidate'] = self.item(path)
        self.save()
        with self.assertRaisesRegex(ValueError, 'ramdisk differs'):
            verifier.verify(self.evidence_path)

    def test_unrelated_header_change_rejected(self):
        self.fixture()
        path = Path(self.evidence['candidate']['path'])
        data = bytearray(path.read_bytes())
        data[16] = 1
        path.write_bytes(data)
        self.evidence['candidate'] = self.item(path)
        self.save()
        with self.assertRaisesRegex(ValueError, 'unrelated boot header'):
            verifier.verify(self.evidence_path)

    def test_source_pair_mismatch_rejected_with_consistent_records(self):
        self.fixture()
        path = Path(self.evidence['inputs']['boot']['path'])
        data = bytearray(path.read_bytes())
        data[4096 + 250] = 1
        path.write_bytes(data)
        self.evidence['inputs']['boot'] = self.item(path)
        self.evidence['sourceInputs']['boot']['sha256'] = self.item(path)['sha256']
        self.evidence['steps'][0]['componentSha256'] = verifier.digest(data[4096:4608])
        rebuild_path = Path(self.evidence['rebuildEvidence']['path'])
        record = json.loads(rebuild_path.read_text())
        record['inputs']['boot'] = self.item(path)
        rebuild_path.write_text(json.dumps(record))
        self.evidence['rebuildEvidence'].update(self.item(rebuild_path))
        self.save()
        with self.assertRaisesRegex(ValueError, 'Original boot kernel differs'):
            verifier.verify(self.evidence_path)

    def test_evidence_and_tool_mutation_during_decode_rejected(self):
        for name in ('evidence', 'tool'):
            with self.subTest(name=name):
                self.fixture()
                path = (self.evidence_path if name == 'evidence'
                        else Path(self.evidence['sourceInputs']['analyzer']['path']))

                def mutate(*args):
                    path.write_bytes(path.read_bytes() + b' ')
                    return [bytes(self.raw), bytes(self.patched), bytes(self.patched)]

                with patch.object(verifier, 'decode_components', mutate), \
                        self.assertRaisesRegex(ValueError, 'changed during verification'):
                    verifier.verify(self.evidence_path)

    def test_false_runtime_or_pro_claim_rejected(self):
        self.fixture()
        for flag in ('fullProParityVerified', 'deviceBootTestPerformed', 'flashableCandidate'):
            with self.subTest(flag=flag):
                self.evidence[flag] = True
                self.save()
                with self.assertRaisesRegex(ValueError, 'offline candidate status'):
                    verifier.verify(self.evidence_path)
                self.evidence[flag] = False

    def test_self_consistent_decoder_tool_substitution_rejected_before_execution(self):
        self.fixture()
        tool = self.work / 'untrusted-java'
        tool.write_bytes(b'replacement executable is never run')
        self.evidence['sourceInputs']['java'] = self.item(tool)
        self.save()
        with self.assertRaisesRegex(ValueError, 'Decoder tool identity'):
            verifier.verify(self.evidence_path)

    def test_missing_aosp_source_provenance_rejected(self):
        self.fixture()
        rebuild_path = Path(self.evidence['rebuildEvidence']['path'])
        rebuild = json.loads(rebuild_path.read_text())
        rebuild['aospSources']['avb']['files'] = {}
        rebuild_path.write_text(json.dumps(rebuild))
        self.evidence['rebuildEvidence'].update(self.item(rebuild_path))
        self.evidence['rebuildEvidence']['aospSources'] = rebuild['aospSources']
        self.save()
        with self.assertRaisesRegex(ValueError, 'revision or source set'):
            verifier.verify(self.evidence_path)

    def test_duplicate_json_field_rejected(self):
        self.fixture()
        text = self.evidence_path.read_text()
        self.evidence_path.write_text(text.replace('{', '{"schemaVersion": 2, ', 1))
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON field'):
            verifier.verify(self.evidence_path)

    def test_cli_writes_redacted_failure_report_without_changing_input(self):
        self.fixture()
        self.evidence['candidate']['sha256'] = '0' * 64
        self.save()
        report_path = self.work / 'failure.json'
        before = self.evidence_path.read_bytes()
        output = io.StringIO()
        with patch.object(sys, 'argv', ['verify_candidate.py', '--evidence', str(self.evidence_path),
                                        '--out', str(report_path)]), contextlib.redirect_stdout(output):
            code = verifier.main()
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(report_path.read_text())['passed'])
        self.assertEqual(before, self.evidence_path.read_bytes())
        self.assertNotIn(self.key.decode(), output.getvalue())

    def test_cli_prevents_input_directory_and_existing_output_writes(self):
        self.fixture()
        for target in (self.evidence_path, self.out / 'report.json'):
            with self.subTest(target=target), patch.object(sys, 'argv', ['verify_candidate.py', '--evidence',
                    str(self.evidence_path), '--out', str(target)]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verifier.main(), 1)
        existing = self.work / 'existing.json'
        existing.write_text('preserve')
        with patch.object(sys, 'argv', ['verify_candidate.py', '--evidence', str(self.evidence_path),
                                       '--out', str(existing)]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(verifier.main(), 1)
        self.assertEqual(existing.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
