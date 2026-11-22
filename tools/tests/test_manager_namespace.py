"""Verify the manager's Java/AIDL/JNI names agree after namespace changes."""
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANAGER = ROOT / "manager"


class ManagerNamespaceTest(unittest.TestCase):
    def test_namespace_matches_application_and_aidl(self):
        build = (MANAGER / "build.gradle.kts").read_text("utf-8")
        namespace = re.search(r'namespace = "([^"]+)"', build).group(1)
        self.assertEqual("com.maplesu.core", namespace)
        self.assertIn('applicationId = "dev.maplesu.manager"', build)
        package_path = namespace.replace(".", "/")
        for name in ("KernelSUApplication.kt", "ui/MainActivity.kt", "Natives.kt"):
            source = MANAGER / "src/main/java" / package_path / name
            self.assertTrue(source.is_file(), str(source))
            self.assertIn("package " + namespace, source.read_text("utf-8"))
        aidl = MANAGER / "src/main/aidl" / package_path / "IKsuInterface.aidl"
        self.assertIn("package " + namespace + ";", aidl.read_text("utf-8"))

    def test_profile_lookup_matches_java_type_and_shipped_jni(self):
        natives = MANAGER / "src/main/java/com/maplesu/core/Natives.kt"
        package = re.search(r"^package (\S+)", natives.read_text("utf-8")).group(1)
        descriptor = package.replace(".", "/") + "/Natives$Profile"
        cpp = ROOT / "third_party/kernelsu/applied/manager/app/src/main/cpp/jni.cc"
        lookups = re.findall(r'FindClass\("([^"]*Natives\$Profile)"\)', cpp.read_text("utf-8"))
        self.assertEqual([descriptor, descriptor], lookups)
        binary = MANAGER / "src/main/jniLibs/arm64-v8a/libmaplesu_ksu.so"
        if binary.is_file():
            self.assertIn(descriptor.encode() + b"\0", binary.read_bytes())

    def test_migration_resource_key_exists_in_both_locales(self):
        for locale in ("values", "values-zh-rCN"):
            xml = MANAGER / "src/main/res" / locale / "maplesu_migration.xml"
            self.assertIn('name="migration_family_maplesu"', xml.read_text("utf-8"))


if __name__ == "__main__":
    unittest.main()
