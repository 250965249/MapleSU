#!/usr/bin/env python3
"""Emulate MapleSU's module-shape gate WITHOUT the manager.

Two checks are mirrored, because the manager uses both:

  1. dev/maplesu/manager/modules/ModuleTypeDetector.kt
       root-level `libmodule_*.so` whose first 4 bytes are \x7fELF  -> MAPLESU
       `module.prop` at root                                        -> KERNELSU evidence
       both                                                         -> AMBIGUOUS (rejected)
     ModuleInstallRouter: AMBIGUOUS -> MODULE_TYPE_AMBIGUOUS_CONFIRM_REQUIRED (dead end,
     both confirmed and unconfirmed branches return the same code), so such a package
     cannot be installed in any mode.

  2. dev/maplesu/manager/ModuleArchiveInspector.java + MapleSuModuleMetadata.java
       nativeEntry = root .so whose MapleSU descriptor parses
       metadata    = root module.prop
       metadata != null && nativeEntry != null -> AMBIGUOUS_MODULE_TYPE
       metadata == null && nativeEntry == null -> MISSING_MODULE_METADATA

Usage:
    py -3 tools/check_module_shape.py <module.zip> [more.zip ...]

Exit status 0 when every given archive is installable, 1 otherwise.
"""
import struct
import sys
import zipfile

ELF_MAGIC = b"\x7fELF"

# MapleSuModuleMetadata: ASCII markers + the field they delimit (see the Java table).
ENTRY_SYMBOL = b"\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x6d\x61\x69\x6e\x5f\x31\x38\x66\x64\x66\x33\x39\x33\x38\x38\x35\x33\x36\x33\x37\x31\x32\x33\x34\x39\x65\x66\x33\x64\x65\x35\x34\x31\x31\x62\x64\x35"
FIELDS = [
    ("name", b"de1f663bcae792d7c9ed1a21cdaeff00331fe11b074f0303e018f43998f8db3e",
     b"04429c3f7172e4cce7ac7a5d44b75631ce91777b5f2a5eec076a3a508a76fb17"),
    ("version", b"7dc74a2b86805f2cd0f45c6a82d384fd568e341c6f05af17c7229c9ba6d4318b",
     b"8dbc019a6e51fe8d4a3db9feaf05535d70879f35626050cd4131bfe323ecefc2"),
    ("description", b"05c62cd446c811e772c94d97fd546738328f7c6b9967ed135190ef37ff06d866",
     b"ed02c95e091c66100d6f2f4554f96392b2951b394ba042278eed8f236f43e1a3"),
    ("author", b"1f39b220291a2fb6e4fec95f179d0faf833ca534ef8ab2ffc4bd893768694451",
     b"d409c886fd6cedd694c1b126fd19eccd90e2463e04154c193effc7103ce63f1c"),
    ("id", b"b33dcddd88c07d079a8e0e9ec6ab976f15f2edba46cab91a61234cfbb982111c",
     b"3020d9a6c07a30e2649dd29a72d7e57121f0c0ca457b6d21dca5a69acbe6c2c4"),
]
KSU_ROOT_SCRIPTS = {"post-fs-data.sh", "service.sh", "customize.sh"}


def descriptor(data):
    """Return the MapleSU descriptor dict, or None when the .so is not a Ultra module."""
    if ENTRY_SYMBOL not in data:
        return None
    if len(data) < 64 or data[:4] != ELF_MAGIC:
        return None
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type != 3 or e_machine != 183:
        return None
    out = {}
    for name, begin, end in FIELDS:
        start = data.find(begin)
        if start < 0:
            return {"__invalid__": "%s marker missing" % name}
        stop = data.find(end, start + len(begin))
        if stop < 0:
            return {"__invalid__": "%s end marker missing" % name}
        raw = data[start + len(begin):stop]
        if len(raw) > 4096:
            return {"__invalid__": "%s field too long" % name}
        try:
            out[name] = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"__invalid__": "%s not utf-8" % name}
    if not (len(out.get("id", "")) == 32 and out["id"].isalnum()):
        return {"__invalid__": "id is not 32 alphanumerics: %r" % out.get("id")}
    return out


def inspect(path):
    z = zipfile.ZipFile(path)
    names = [n for n in z.namelist() if not n.endswith("/")]
    root_native = [n for n in names
                if "/" not in n and n.rsplit("/", 1)[-1].startswith("libmodule_")
                and n.endswith(".so") and z.read(n)[:4] == ELF_MAGIC]
    root_scripts = sorted(set(names) & KSU_ROOT_SCRIPTS)
    has_prop = "module.prop" in names
    native = {}
    for n in root_native:
        d = descriptor(z.read(n))
        if d and "__invalid__" not in d:
            native[n] = d

    # --- ModuleTypeDetector ---
    if root_native and has_prop:
        detector, route = "AMBIGUOUS", "MODULE_TYPE_AMBIGUOUS_CONFIRM_REQUIRED (rejected)"
    elif root_native:
        detector, route = "MAPLESU", "OK -> MAPLESU_ULTRA backend"
    elif has_prop or root_scripts:
        detector, route = "KERNELSU", "OK -> LITE_SCRIPT backend"
    else:
        detector, route = "UNKNOWN", "MODULE_TYPE_UNKNOWN_REJECTED"

    # --- ModuleArchiveInspector ---
    if has_prop and native:
        inspector = "AMBIGUOUS_MODULE_TYPE"
    elif native and not has_prop:
        inspector = "MAPLESU (type=MAPLESU, id=%s)" % next(iter(native.values()))["id"]
    elif has_prop:
        inspector = "KERNEL_SU"
    else:
        inspector = "MISSING_MODULE_METADATA"

    bad = detector in ("AMBIGUOUS", "UNKNOWN") or inspector.startswith(("AMBIGUOUS", "MISSING"))
    return dict(name=path, detector=detector, route=route, inspector=inspector,
                root_native=root_native, has_prop=has_prop, scripts=root_scripts,
                descriptor=native, ok=not bad)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    for path in argv[1:]:
        r = inspect(path)
        print("=" * 78)
        print("archive     :", r["name"])
        print("root .so    :", r["root_native"] or "-")
        print("module.prop :", "yes" if r["has_prop"] else "no")
        print("root scripts:", r["scripts"] or "-")
        print("detector    :", r["detector"], "|", r["route"])
        print("inspector   :", r["inspector"])
        for so, d in r["descriptor"].items():
            print("descriptor  : %s id=%s name=%r version=%r" % (so, d["id"], d["name"], d["version"]))
        print("verdict     :", "INSTALLABLE" if r["ok"] else "REJECTED")
        rc |= 0 if r["ok"] else 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
