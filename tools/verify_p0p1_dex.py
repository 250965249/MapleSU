#!/usr/bin/env python
"""P0/P1 dex + native verification for the third-party-su change.

Checks that the required build actually contains both third-party su device tests
(Ultra and Normal/KSU) and the new authority/proxy classes, and that the packaged
L3 JNI library carries the streaming entry points. Read-only over the APKs.

Usage: python tools/verify_p0p1_dex.py <manager-debug.apk> <androidTest.apk>
"""
import hashlib
import json
import sys
import zipfile

MAIN_CLASSES = [
    "dev/maplesu/manager/runtime/authorization/ManagerSuperuserPolicy",
    "dev/maplesu/manager/runtime/authorization/SuperuserJournalStore",
    "dev/maplesu/manager/runtime/authorization/AuthorizationsSnapshot",
    "dev/maplesu/manager/runtime/authorization/SuperuserTransaction",
    "dev/maplesu/manager/runtime/authorization/SuperuserMigration",
    "dev/maplesu/manager/runtime/authorization/SuperuserOps",
    "dev/maplesu/manager/runtime/authorization/SuperuserTool",
    "dev/maplesu/manager/runtime/authorization/SuperuserControl",
    "dev/maplesu/manager/runtime/authorization/RootToolOutcome",
    "dev/maplesu/manager/runtime/authorization/PackageIdentityReader",
    "dev/maplesu/manager/runtime/authorization/SystemPackageSnapshotSource",
    "dev/maplesu/manager/runtime/HookSuEndpoint",
    "dev/maplesu/manager/runtime/SuSessionRegistry",
    "dev/maplesu/manager/runtime/SuAuditLog",
]

TEST_CLASSES = [
    # Ultra (hook) third-party su.
    "dev/maplesu/manager/jailbreak/UltraThirdPartySuAndroidTest",
    # Normal (KSU) third-party su.
    "dev/maplesu/manager/jailbreak/KsuThirdPartySuAndroidTest",
]

JNI_SYMBOLS = [
    b"Java_dev_maplesu_manager_runtime_NativeSu_startStreaming",
    b"Java_dev_maplesu_manager_runtime_NativeSu_commitStreaming",
    b"Java_dev_maplesu_manager_runtime_NativeSu_abortStreaming",
    b"Java_dev_maplesu_manager_runtime_NativeSu_reapStreaming",
    b"Java_dev_maplesu_manager_runtime_NativeSu_killStreaming",
]


def dex_blobs(apk):
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            if name.endswith(".dex"):
                yield name, archive.read(name)


def find(apk, classes):
    blobs = list(dex_blobs(apk))
    found, missing = {}, []
    for cls in classes:
        hit = next((name for name, data in blobs if cls.encode() in data), None)
        if hit is None:
            missing.append(cls)
        else:
            found[cls] = hit
    return found, missing, len(blobs)


def main():
    if len(sys.argv) != 3:
        print("usage: verify_p0p1_dex.py <manager-debug.apk> <androidTest.apk>")
        return 2
    main_apk, test_apk = sys.argv[1], sys.argv[2]
    report = {"mainApk": main_apk, "androidTestApk": test_apk}

    main_found, main_missing, main_dex = find(main_apk, MAIN_CLASSES)
    test_found, test_missing, test_dex = find(test_apk, TEST_CLASSES)
    report["main"] = {"dexFiles": main_dex, "found": main_found, "missing": main_missing}
    report["androidTest"] = {"dexFiles": test_dex, "found": test_found, "missing": test_missing}

    with zipfile.ZipFile(main_apk) as archive:
        name = "lib/arm64-v8a/libmaplesu_l3_su.so"
        so = archive.read(name) if name in archive.namelist() else b""
        report["native"] = {
            "entry": name,
            "present": bool(so),
            "sha256": hashlib.sha256(so).hexdigest() if so else "",
            "symbols": {symbol.decode(): (symbol in so) for symbol in JNI_SYMBOLS},
        }

    ok = not main_missing and not test_missing and all(report["native"]["symbols"].values())
    report["ok"] = ok
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
