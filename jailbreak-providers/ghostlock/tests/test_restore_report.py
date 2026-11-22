"""Run the production C++ restore verdict on the host; only selinuxfs reads are mocked."""
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_restore
import test_handoff_record

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT.parent / "tools"))
import native_toolchain  # noqa: E402


def definition(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


class RestoreReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        text = (ROOT / "lease/src/root_consumer.cpp").read_text()
        source = "\n".join([
            definition(text, "enum RestoreOrigin" ) + ";",
            definition(text, "struct RestoreReport") + ";",
            definition(text, "struct Session") + ";\nSession g_session;",
            "static unsigned char live_enforcing, live_checkreqprot;",
            "unsigned char read_enforcing_byte(char&) { return live_enforcing; }",
            "unsigned char read_selinux_flag(const char*, char&, bool = false) { return live_checkreqprot; }",
            "void log_line(const char*, ...) {}",
            definition(text, "RestoreReport ghostlock_report()"),
            r'''extern "C"
#ifdef _WIN32
__declspec(dllexport)
#endif
unsigned long long evaluate(int rc, int reported_e, int reported_c, int origin, int live_e, int live_c) {
    g_session.ghostlock_rc = rc;
    g_session.ghostlock_enforcing = reported_e;
    g_session.ghostlock_checkreqprot = reported_c;
    g_session.ghostlock_source = origin;
    live_enforcing = static_cast<unsigned char>(live_e);
    live_checkreqprot = static_cast<unsigned char>(live_c);
    const auto r = ghostlock_report();
    return r.applied | (static_cast<unsigned long long>(r.checkreqprot) << 8);
}''',
        ])
        cpp = work / "report.cpp"
        cpp.write_text(source)
        if os.name == "nt":
            ndk = native_toolchain.provider_ndk(os.environ.get("ANDROID_NDK_HOME"))
            clang = ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe"
            linker = clang.with_name("ld.lld.exe")
            dll = work / "report.dll"
            obj = work / "report.obj"
            subprocess.run([str(clang), "--target=x86_64-pc-windows-msvc", "-ffreestanding",
                            "-fno-stack-protector", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra", "-Werror",
                            "-c", str(cpp), "-o", str(obj)], check=True, capture_output=True)
            subprocess.run([str(linker), "-flavor", "link", "/dll", "/noentry", "/out:" + str(dll),
                            str(obj)], check=True, capture_output=True)
        else:
            dll = work / "report.so"
            subprocess.run([shutil.which("c++"), "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                            str(cpp), "-o", str(dll)], check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(dll))
        if os.name == "nt":
            import _ctypes
            cls.addClassCleanup(_ctypes.FreeLibrary, cls.lib._handle)
        cls.lib.evaluate.argtypes = [ctypes.c_int] * 6
        cls.lib.evaluate.restype = ctypes.c_ulonglong

    def verdict(self, rc=0, reported_e=1, reported_c=0, origin=0, live_e=1, live_c=0):
        return self.lib.evaluate(rc, reported_e, reported_c, origin, live_e, live_c) & 255

    def test_observed_and_baseline_values_must_match(self):
        for origin in (0, 1):
            for e in (0, 1):
                for c in (0, 1):
                    with self.subTest(origin=origin, e=e, c=c):
                        self.assertEqual(self.verdict(reported_e=e, reported_c=c, origin=origin,
                                                     live_e=e, live_c=c), 1 if origin == 0 else 3)
                        self.assertEqual(self.verdict(reported_e=e, reported_c=c, origin=origin,
                                                     live_e=1-e, live_c=c), 0)
                        self.assertEqual(self.verdict(reported_e=e, reported_c=c, origin=origin,
                                                     live_e=e, live_c=1-c), 0)

    def test_confirmed_absence_is_distinct_from_unknown(self):
        for origin in (0, 1):
            with self.subTest(origin=origin):
                self.assertEqual(self.verdict(reported_c=-2, live_c=2, origin=origin), 1 if origin == 0 else 3)
                self.assertEqual(self.verdict(reported_c=-2, live_c=255, origin=origin), 0)
                self.assertEqual(self.verdict(reported_c=-2, live_c=0, origin=origin), 0)
                self.assertEqual(self.verdict(reported_c=-1, live_c=2, origin=origin), 0)

    def test_unknown_provider_values_are_not_a_wildcard(self):
        self.assertEqual(self.verdict(reported_e=-1), 0)
        self.assertEqual(self.verdict(reported_c=-1), 0)

    def test_failed_script_and_unreadable_live_values_fail(self):
        for rc in (70, 71, 72, 73, 74, 75, 76, 77, 126, 137, 255):
            self.assertEqual(self.verdict(rc=rc), 0)
        self.assertEqual(self.verdict(live_e=255), 0)
        self.assertEqual(self.verdict(live_c=255), 0)

    def test_app_unreadable_absent_node_round_trip(self):
        restored = test_restore.RestoreScriptTest().run_fixture(checkreqprot=-1, check_present=False)
        record = test_handoff_record.HandoffRecordTest().record(enforcing=restored["enforcing"],
            checkreqprot=restored["checkreqprot"], baseline=-1, rc=restored["code"])
        rc, enforcing, checkreqprot = map(int, record.split(":"))
        self.assertEqual(self.verdict(rc=rc, reported_e=enforcing, reported_c=checkreqprot,
                                     origin=1, live_e=int(restored["enforcing"]), live_c=2), 3,
                         f"GHOSTLOCK_RESTORE_UNVERIFIED:FAILED record={record}")


if __name__ == "__main__":
    unittest.main()
