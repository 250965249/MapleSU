"""Run the actual synchronous C loader against isolated owned files and DSOs."""
import os
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, "/source/scripts")
from policy_backend_identity import write_identity

root = Path("/tmp/maplesu-policy-loader")
work = Path("/output")
good = work / "loader-good.so"
missing = work / "loader-missing.so"
old = work / "loader-old.so"
(work / "loader-backend.c").write_text(r'''
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef VERSION
#define VERSION "new"
#endif
__attribute__((constructor)) static void loaded(void) {
    int fd = open("/tmp/maplesu-policy-loader/loaded", O_WRONLY|O_CREAT, 0600);
    if (fd >= 0) { write(fd, VERSION, 3); close(fd); }
}
int maplesu_environment_policy_start(const char* key) {
    if (strcmp(key, "fixture-key")) return 99;
    int fd = open("/tmp/maplesu-policy-loader/called", O_WRONLY|O_CREAT, 0600);
    if (fd < 0) return 98;
    write(fd, VERSION, 3); close(fd);
    return getenv("FIXTURE_BACKEND_FAIL") ? 1 : 0;
}
''')
(work / "loader-missing.c").write_text("int other(void) { return 0; }\n")
for source, dest in [(work / "loader-backend.c", good), (work / "loader-missing.c", missing)]:
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                    "-Wl,--build-id=0x" + bytes(range(20)).hex(),
                    str(source), "-o", str(dest)], check=True)
subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                "-Wl,--build-id=0x" + bytes(range(1, 21)).hex(),
                '-DVERSION="old"', str(work / "loader-backend.c"), "-o", str(old)], check=True)
def fixture_identity(path, build_id):
    data = path.read_bytes()
    note = bytes.fromhex("040000001400000003000000474e5500") + build_id
    at = data.index(note)
    assert at + len(note) <= 4096
    digest = hashlib.sha256(data).hexdigest()
    return dict(sha256=digest, size=len(data), noteHex=note.hex(), noteOffset=at,
                fileName=f"libmaplesu_policy_boot.{digest}.so")
identity = fixture_identity(good, bytes(range(20)))
old_identity = fixture_identity(old, bytes(range(1, 21)))
assert identity["sha256"] != old_identity["sha256"]
assert identity["size"] == old_identity["size"]
backend = root / "adb/maplesu/bin" / identity["fileName"]
for name, pinned in [("new", identity), ("old", old_identity)]:
    include = work / name
    include.mkdir(exist_ok=True)
    write_identity(include / "environment_backend_identity.h", pinned)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-I" + str(include), '-DMAPLESU_POLICY_DIRECTORY="/tmp/maplesu-policy-loader"',
        "/source/runtime/ultra/policy/environment_loader.c", "/source/runtime/tests/policy_loader_test.c",
        "-Wl,--wrap=getuid", "-Wl,--wrap=dlopen", "-Wl,--wrap=read", "-ldl",
        "-o", str(work / ("loader-test-" + name))], check=True)

def reset():
    if root.exists():
        shutil.rmtree(root)
    backend.parent.mkdir(parents=True, mode=0o700)
    shutil.copyfile(good, backend)
    backend.chmod(0o700)

def run(name, expected, called=False, change=lambda: None, helper="new", **variables):
    reset()
    change()
    result = subprocess.run([str(work / ("loader-test-" + helper)), str(expected)], env=dict(os.environ, **variables),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, (name, result.stdout, result.stderr)
    assert (root / "called").exists() == called, name
    assert (root / "loaded").exists() == called, name
    if called:
        assert (root / "called").read_text() == helper, name
    return name

tests = [run("valid backend", 0, True),
    run("backend error", 6, True, FIXTURE_BACKEND_FAIL="1"),
    run("non-root", 1, FIXTURE_NONROOT="1"),
    run("missing key", 1, FIXTURE_NULL_KEY="1"),
    run("missing file", 2, change=backend.unlink),
    run("world writable file", 2, change=lambda: backend.chmod(0o777)),
    run("setuid file", 2, change=lambda: backend.chmod(0o4700)),
    run("unsafe directory", 2, change=lambda: backend.parent.chmod(0o777)),
    run("truncated ELF rejected before dlopen", 7, change=lambda: backend.write_bytes(b"invalid")),
    run("unpaired missing-entry DSO rejected before dlopen", 7, change=lambda: shutil.copyfile(missing, backend)),
    run("hardlinked file", 2, change=lambda: os.link(backend, root / "alias"))]

def symlink_file():
    backend.unlink()
    backend.symlink_to(good)
tests.append(run("symlink file", 2, change=symlink_file))
def fifo_file():
    backend.unlink()
    os.mkfifo(backend, 0o700)
tests.append(run("FIFO does not block", 2, change=fifo_file))
def replace_file():
    shutil.copyfile(missing, root / "replacement.so")
    (root / "replacement.so").chmod(0o700)
tests.append(run("validated inode survives path replacement", 0, True, replace_file, FIXTURE_REPLACE="1"))
tests.append(run("same-size old version rejected before constructors", 7,
                 change=lambda: shutil.copyfile(old, backend)))
def legacy_only():
    backend.unlink()
    shutil.copyfile(old, backend.parent / "libmaplesu_policy_boot.so")
tests.append(run("no fallback to unversioned backend", 2, change=legacy_only))
def coexist():
    shutil.copyfile(old, backend.parent / old_identity["fileName"])
    (backend.parent / old_identity["fileName"]).chmod(0o700)
    shutil.copyfile(old, backend.parent / "libmaplesu_policy_boot.so")
tests.append(run("new helper ignores retained old versions", 0, True, change=coexist))
def incomplete_staging():
    backend.unlink()
    (backend.parent / ("." + identity["fileName"] + ".partial")).write_bytes(good.read_bytes()[:128])
tests.append(run("interrupted publication is not loadable", 2, change=incomplete_staging))
def old_only():
    backend.unlink()
    shutil.copyfile(old, backend.parent / old_identity["fileName"])
    (backend.parent / old_identity["fileName"]).chmod(0o700)
tests.append(run("new helper rejects old-only rollback state", 2, change=old_only))
tests.append(run("old helper loads retained version while new backend is prepared", 0, True,
                 change=coexist, helper="old"))
tests.append(run("rollback helper still works after interrupted new publication", 0, True,
                 change=old_only, helper="old"))
tests.append(run("interrupted identity read retries", 0, True, FIXTURE_READ_EINTR="1"))
tests.append(run("short identity reads complete", 0, True, FIXTURE_SHORT_READ="1"))
tests.append(run("identity read EOF rejects before constructors", 7, FIXTURE_READ_EOF="1"))
def invalid_elf():
    data = bytearray(good.read_bytes())
    data[:4] = b"nope"
    backend.write_bytes(data)
tests.append(run("invalid paired ELF fails in dlopen", 4, change=invalid_elf))
def missing_entry():
    data = missing.read_bytes()
    assert len(data) < identity["size"]
    backend.write_bytes(data + bytes(identity["size"] - len(data)))
tests.append(run("paired ELF without entry fails dlsym", 5, change=missing_entry))
print(f"PASS {len(tests)} synchronous loader filesystem/DSO cases")
