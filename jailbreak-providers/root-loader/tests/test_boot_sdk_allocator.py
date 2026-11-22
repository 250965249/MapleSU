"""Differential checks for live vmalloc decoding, with corrupt operands/callees."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'jailbreak-providers/dirtyfrag/tests'))
from test_l3_arm import host_compiler
from test_boot_sdk_build import SDK, Symbols

class BootSdkAllocatorTest(unittest.TestCase):
    def test_live_operands_and_callee_match_the_image_decoder(self):
        # Real reference wrappers, with BL relocated into this host fixture.
        wrappers = [
            (False, 21, "3f2303d5ff8300d1fd7b01a9fd430091ff2003d528fd00b069e080d208c15939090de0f2e2675ab22a0175b2e38f64b2210080521f0100710200b0f2a3ffdff225018a9a04988152e6031faa07008012fe0300f9c4fdff97fd7b41a9ff830091bf2303d5c0035fd6"),
            (False, 25, "3f2303d5ff8300d1fd7b01a9fd430091e8f600d0ff2003d56be080d2c96359b2cabf4992df0349f2082159390b0de0f24901899a6a0175b2e2675ab2e38f64b21f0100712100805265018a9a0200a1f2a3ffdff204988152e6031faa07008012e90300f9c0b6f997fd7b41a9ff830091bf2303d5c0035fd6"),
            (True, 26, "3f2303d5ff0301d1fd7b03a9fdc30091084138d5088943f9a8831ff8ff2003d5bf031ff81f2003d5082101b069e080d2e2675ab208317e39090de0f2e37b5fb22a0175b2210080520200b0f21f01007103f0b7f2049881524511899ae6031faa07008012fe0300f935020094084138d5088943f9a9835ff81f0109ebe1010054fd7b43a9ff030191bf2303d5c0035fd6"),
        ]
        with tempfile.TemporaryDirectory(prefix='sdk-live-allocator-') as directory:
            path = Path(directory); exe = path / 'decoder'
            subprocess.run([host_compiler(), '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                '-I'+str(HERE.parent/'module'), HERE/'boot_sdk_allocator_test.c', '-o', exe], check=True)
            for profiled, call, hexcode in wrappers:
                image = bytearray(8192); struct.pack_into('<Q', image, 16, 0x10000000)
                image[56:60] = b'ARM\x64'
                code = bytearray.fromhex(hexcode)
                struct.pack_into('<I', code, call*4, 0x94000000 | ((6144-4096-call*4)//4))
                image[4096:4096+len(code)] = code
                names = ('vmalloc_noprof', '__vmalloc_node_range_noprof') if profiled else ('vmalloc', '__vmalloc_node_range')
                missing = ('vmalloc', '__vmalloc_node_range') if profiled else ()
                facts = SDK.vmalloc_facts(image, Symbols(missing=missing, overrides={names[0]:4096,names[1]:6144}))
                self.assertIsNotNone(facts)
                file = path/'code.bin'; file.write_bytes(image[4096:4216])
                command = [exe, file, '4096', '6144', str(0x10000000), str(int(profiled))]
                expected = [facts['MSU_BS_'+name] for name in ('VM_START_MAG','VM_END_MAG','VM_ALIGN','VM_GFP','VM_PROT','VM_PROT_SET','VM_PROT_FLAG')]
                with self.subTest(profiled=profiled, call=call):
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(expected, list(map(int, result.stdout.split())))
                for at in (0, call*4):
                    broken = bytearray(image[4096:4216]); broken[at] ^= 4; file.write_bytes(broken)
                    self.assertEqual(2, subprocess.run(command, capture_output=True).returncode)
                file.write_bytes(image[4096:4216])
                wrong = command.copy(); wrong[3] = '6148'
                self.assertEqual(2, subprocess.run(wrong, capture_output=True).returncode)

if __name__ == '__main__': unittest.main()
