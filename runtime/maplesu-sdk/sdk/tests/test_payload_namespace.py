"""Compile tiny generated arrays; exercise real extraction without building SDK code."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path.cwd().resolve()
TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E = load('candidate_payload_extractor', TOOLS / 'extract_payloads.py')
G = load('current_payload_headers', ROOT / 'runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py')
COMMANDS = []


class PayloadNamespaceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='maplesu-payload-namespace-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.compiler = Path('D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe')
        cls.member_sets = {}
        cls.payloads = {}
        for mode in ('current', 'legacy'):
            members = {}
            for asset, symbol, header_name, frozen_symbol, current_member in G.TABLE:
                payload = b'ordinary fixture\x00' + asset.encode() + b'\xff'
                cls.payloads[asset] = payload
                text = G.render_header(symbol, asset, payload, current_member, '', '')
                namespace = 'maplesu::sdk'
                member = current_member
                if mode == 'legacy':
                    text = text.replace('namespace maplesu::sdk', 'namespace skroot_env')
                    namespace = 'skroot_env'
                    member = next(old for old, current in E.INSTALLER_NAMES.items() if current == current_member)
                source = cls.directory / (mode + '-' + symbol + '.cpp')
                source.write_text(text + '\nextern "C" const unsigned char *fixture() { return ' + namespace + '::' + symbol + '; }\n', encoding='utf-8')
                target = source.with_suffix('.o')
                command = [str(cls.compiler), '--target=aarch64-linux-android21', '-std=c++17', '-O0', '-fPIC',
                           '-c', str(source), '-o', str(target)]
                done = subprocess.run(command, capture_output=True, text=True)
                COMMANDS.append({'argv':command, 'exitCode':done.returncode,
                                 'stderr':done.stderr, 'objectSha256':hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None})
                if done.returncode:
                    raise AssertionError(done.stderr)
                blob = target.read_bytes()
                members[member] = E.ArMember(member, 0, 0, len(blob), blob)
            cls.member_sets[mode] = members

    def test_current_generated_arrays_extract_through_existing_callers(self):
        for old, symbol, short, label in E.TARGETS:
            with self.subTest(asset=short):
                record = E.extract_one(old, symbol, short, label, b'', self.member_sets['current'])
                asset = 'resetprop_file.bin' if short == 'resetprop' else short + '.bin'
                self.assertNotIn('error', record)
                self.assertEqual(record['member'], E.INSTALLER_NAMES[old])
                self.assertEqual(record['symbol'], E.PAYLOAD_SYMBOLS[symbol])
                self.assertEqual(record['payload_sha256'], E.sha256(self.payloads[asset]))
                self.assertEqual(record['payload_size'], len(self.payloads[asset]))

    def test_legacy_symbols_and_report_fields_preserved(self):
        for old, symbol, short, label in E.TARGETS:
            record = E.extract_one(old, symbol, short, label, b'', self.member_sets['legacy'])
            self.assertNotIn('error', record)
            self.assertNotIn('requested_member', record)
            self.assertNotIn('requested_symbol', record)
            self.assertEqual((record['member'], record['symbol']), (old, symbol))

    def test_ambiguous_old_and_current_members_rejected(self):
        members = {**self.member_sets['legacy'], **self.member_sets['current']}
        for target in E.TARGETS:
            self.assertIn('ambiguous installer', E.extract_one(*target, b'', members)['error'])

    def test_duplicate_installers_rejected_but_same_named_other_members_preserved(self):
        member = next(iter(self.member_sets['current'].values()))
        with self.assertRaisesRegex(ValueError, 'duplicate installer'):
            E.installer_member_lookup([member, member])
        first = E.ArMember('patch_base.o', 0, 0, 1, b'a')
        second = E.ArMember('patch_base.o', 0, 0, 1, b'b')
        self.assertIs(E.installer_member_lookup([first, second])['patch_base.o'], second)

    def test_missing_symbol_and_asset_mismatch_remain_errors(self):
        old, symbol, short, label = E.TARGETS[0]
        missing = E.extract_one(old, 'missing_fixture_symbol', short, label, b'', self.member_sets['current'])
        self.assertIn('not found', missing['error'])
        asset = self.directory / 'su.bin'
        asset.write_bytes(b'wrong fixture')
        result = E.extract_one(old, symbol, short, label, b'', self.member_sets['current'], expected_assets=str(self.directory))
        self.assertIn('differs from selected asset', result['error'])

    def test_actual_frozen_archive_retains_four_payload_contracts(self):
        raw = Path(ROOT / 'runtime/maplesu-sdk/maintenance/freeze/freeze-maplesu-pro-5.2.0-su-uid-isolation-20261114-20261114/archive/libkernel_module_kit_static.a').read_bytes()
        members = E.parse_ar(raw)
        for target in E.TARGETS:
            result = E.extract_one(*target, raw, members, expected_assets=str(ROOT / 'runtime/maplesu-sdk/sdk/assets'))
            self.assertNotIn('error', result)
            self.assertTrue(result['expected_asset']['matches'])

    def test_cli_reads_migrated_archive_and_compares_actual_asset_bytes(self):
        blob = bytearray(b'!<arch>\n')
        for name, member in self.member_sets['current'].items():
            encoded = name.encode()
            body = encoded + member.raw
            header = (('#1/' + str(len(encoded))).ljust(16) + '0'.ljust(12) + '0'.ljust(6)
                      + '0'.ljust(6) + '100644'.ljust(8) + str(len(body)).ljust(10) + '`\n')
            blob += header.encode() + body + (b'\n' if len(body) % 2 else b'')
        archive = self.directory / 'current-fixture.a'
        archive.write_bytes(blob)
        assets = self.directory / 'assets'
        assets.mkdir()
        for name, payload in self.payloads.items():
            (assets / name).write_bytes(payload)
        output = self.directory / 'extracted'
        self.assertEqual(E.main(['--archive', str(archive), '--out', str(output),
            '--emit', '--quiet', '--expected-assets', str(assets)]), 0)
        report = json.loads((output / 'payloads.json').read_text(encoding='utf-8'))
        self.assertEqual({row['member'] for row in report['targets']}, set(E.INSTALLER_NAMES.values()))
        self.assertTrue(all(row['expected_asset']['matches'] for row in report['targets']))


if __name__ == '__main__':
    unittest.main()
