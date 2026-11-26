"""Execute the exact production C validators on Windows, without an Android device."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
DLL = None

class LeaseContractTest(unittest.TestCase):
    def test_endpoint(self):
        for value in (b"maplesu-jb-a", b"maplesu-jb-" + b"a" * 89):
            self.assertEqual(DLL.maplesu_lease_endpoint(value), 1)
        for value in (None, b"", b"maplesu-jb-", b"other-1", b"maplesu-jb-A", b"maplesu-jb-../x", b"maplesu-jb-" + b"a" * 90):
            self.assertEqual(DLL.maplesu_lease_endpoint(value), 0, value)

    def test_nonce(self):
        out = (ctypes.c_ubyte * 32)()
        self.assertEqual(DLL.maplesu_lease_nonce(b"0123456789abcdef" * 4, out), 1)
        self.assertEqual(bytes(out), bytes.fromhex("0123456789abcdef" * 4))
        for value in (None, b"", b"0" * 63, b"0" * 65, b"G" + b"0" * 63, b"A" * 64):
            self.assertEqual(DLL.maplesu_lease_nonce(value, out), 0, value)
        self.assertEqual(DLL.maplesu_lease_nonce(b"0" * 64, None), 0)

    def test_boot_id(self):
        self.assertEqual(DLL.maplesu_lease_boot_id(b"5334f916-9a56-4267-8d79-cb67a4782ece"), 1)
        for value in (None, b"", b"0" * 36, b"5334f916-9a56-4267-8d79-cb67a4782ec", b"5334f916-9a56-4267-8d79-cb67a4782ece\n"):
            self.assertEqual(DLL.maplesu_lease_boot_id(value), 0, value)

    def test_decimal(self):
        out = ctypes.c_int()
        for value, expected in ((b"10000", 10000), (b"2147483647", 2147483647)):
            self.assertEqual(DLL.maplesu_lease_decimal(value, 10000, ctypes.byref(out)), 1)
            self.assertEqual(out.value, expected)
        for value in (None, b"", b"-1", b"+10000", b"9999", b"2147483648", b"10000x", b"10000 "):
            self.assertEqual(DLL.maplesu_lease_decimal(value, 10000, ctypes.byref(out)), 0, value)
        self.assertEqual(DLL.maplesu_lease_decimal(b"10000", -1, ctypes.byref(out)), 0)
        self.assertEqual(DLL.maplesu_lease_decimal(b"10000", 10000, None), 0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", required=False, type=Path,
                        help="NDK root; when omitted (or no compiler) run the pure-Python contract mirror")
    parser.add_argument("--output", required=False, type=Path)
    args = parser.parse_args()
    output = args.output or (ROOT / "build" / "lease-contract")
    output.mkdir(parents=True, exist_ok=True)
    source = ROOT / "lease/src/lease_contract.c"
    commands = []
    mode = "python-mirror"
    note = "No --ndk supplied (or no compiler): executed pure-Python mirror of lease_contract.c; production C NOT executed on host."
    if args.ndk is not None:
        compiler = args.ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
        linker = compiler.with_name("ld.lld.exe")
        obj = output / "lease_contract.obj"
        dll = output / "lease_contract.dll"
        commands = [[str(compiler), "--target=x86_64-pc-windows-msvc", "-ffreestanding", "-fno-stack-protector", "-Wall", "-Wextra", "-Werror", "-c", str(source), "-o", str(obj)],
                    [str(linker), "-flavor", "link", "/dll", "/noentry", "/out:" + str(dll), *["/export:maplesu_lease_" + name for name in ("endpoint", "nonce", "boot_id", "decimal")], str(obj)]]
        for command in commands:
            subprocess.run(command, check=True)
        DLL = ctypes.CDLL(str(dll.resolve()))
        DLL.maplesu_lease_endpoint.argtypes = [ctypes.c_char_p]
        DLL.maplesu_lease_boot_id.argtypes = [ctypes.c_char_p]
        DLL.maplesu_lease_nonce.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte)]
        DLL.maplesu_lease_decimal.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
        mode = "c-ndk"
        note = "Production C validators compiled with NDK clang and executed on Windows; Android IPC/device lifecycle not exercised"
    else:
        import lease_contract_ref
        DLL = lease_contract_ref.MirrorDLL()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LeaseContractTest))
    report = {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "mode": mode, "note": note, "sourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "commands": commands,
              "scope": "argv contract validators; Android IPC and device lifecycle not exercised"}
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if result.wasSuccessful() else 1)
