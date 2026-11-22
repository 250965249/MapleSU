#!/usr/bin/env python3
"""Run the real m031/m032 history I/O bodies without kernel/device execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
SDK = Path(__file__).resolve().parents[1]
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"
MEMBERS = {
    31: ("module_base_kernel_idle_mem.cpp", "detail_idle_mem_history"),
    32: ("module_base_kernel_hook_disable_flag.cpp", "detail_hook_disable_flag_history"),
}


def receipt(path):
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("--out must be empty")
    out.mkdir(parents=True, exist_ok=True)
    public = SDK.parent / "include"
    production = [SDK / "src/module_base" / name for name, _ in MEMBERS.values()]
    before = [receipt(path) for path in production]
    shim = out / "host-include/sys"
    shim.mkdir(parents=True)
    (shim / "system_properties.h").write_text(
        '#pragma once\n#define PROP_VALUE_MAX 92\nextern "C" int __system_property_get(const char*, char*);\n',
        encoding="utf-8")
    docker = ["docker.exe", "run", "--rm", "--pull", "never", "--network", "none",
              "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--tmpfs", "/tmp:rw,size=128m", "--tmpfs", "/data:rw,size=1m,mode=0777",
              "--mount", f"type=bind,source={SDK},target=/sdk,readonly",
              "--mount", f"type=bind,source={public},target=/upstream-include,readonly",
              "--mount", f"type=bind,source={out},target=/work", "-w", "/work",
              "--entrypoint", "/bin/sh", IMAGE]
    commands, rows = [], []

    def run(name, argv):
        argv = [str(value) for value in argv]
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        (out / (name + ".log")).write_text(done.stdout + done.stderr, encoding="utf-8")
        commands.append({"name": name, "argv": argv, "exit": done.returncode})
        if done.returncode:
            raise RuntimeError(name + ": " + done.stderr[-3000:])
        return done.stdout

    for idx, (name, namespace) in MEMBERS.items():
        api = "reset_idle_memory" if idx == 31 else "reset_hook_flags"
        getters = (["get_idle_mem_start_path", "get_idle_mem_next_path", "get_idle_mem_end_path"] if idx == 31
                   else ["get_hook_disable_flag_start_path", "get_hook_disable_flag_next_path", "get_hook_disable_flag_end_path"])
        harness = f'''#include <algorithm>
#include "/sdk/src/module_base/{name}"
#include <iostream>
static int label_calls = 0;
static int fail_label = 0;
static bool label_contract = true;
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {{
    return "0123456789abcdef123456789abcdef0123456789abcdef012";
}}
extern "C" int __wrap_setxattr(const char*, const char* name, const void* value, size_t size, int flags) {{
    ++label_calls;
    static constexpr char context[] = "u:object_r:kernel:s0";
    label_contract = label_contract && strcmp(name, "security.selinux") == 0 && size == sizeof(context)
                     && memcmp(value, context, sizeof(context)) == 0 && flags == 0;
    if (label_calls == fail_label) {{ errno = EIO; return -1; }}
    return 0;
}}
int main() {{
    using namespace kernel_module::{namespace};
    int failures = 0;
    auto check = [&](const char* name, bool pass) {{
        std::cout << "{{\\\"member\\\":{idx},\\\"case\\\":\\\"" << name
                  << "\\\",\\\"passed\\\":" << (pass ? "true" : "false") << "}}\\n";
        if (!pass) ++failures;
    }};
    const uint64_t word = UINT64_C(0x0102030405060708);
    check("normal-write", write_file_u64("/work/word-{idx}.bin", word));
    uint64_t value = 0;
    check("normal-read", read_file_u64("/work/word-{idx}.bin", value) && value == word);
    check("full-write-error", !write_file_u64("/dev/full", word));
    check("null-write-error", !write_file_u64(nullptr, word));
    check("missing-parent-write-error", !write_file_u64("/work/missing-parent/word.bin", word));
    check("missing-read-error", !read_file_u64("/work/missing.bin", value));
    for (size_t size : {{0u, 7u, 8u, 9u}}) {{
        const std::string path = "/work/input-{idx}-" + std::to_string(size);
        {{
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            const char bytes[9] = {{1,2,3,4,5,6,7,8,9}};
            file.write(bytes, size);
        }}
        value = UINT64_C(0xabcdef);
        bool ok = read_file_u64(path.c_str(), value);
        check(("read-length-" + std::to_string(size)).c_str(),
              size == 8 ? (ok && value == UINT64_C(0x0807060504030201)) : (!ok && value == UINT64_C(0xabcdef)));
    }}
    const std::string root = "/data/0123456789abcdef";
    std::filesystem::create_directories(root);
    std::string paths[] = {{{getters[0]}(), {getters[1]}(), {getters[2]}()}};
    for (const auto& path : paths) write_file_u64(path.c_str(), word);
    check("reset-success", maplesu::allocation_history::{api}() == KModErr::OK);
    bool all_zero = true, modes = true;
    for (const auto& path : paths) {{
        value = word;
        all_zero = all_zero && read_file_u64(path.c_str(), value) && value == 0;
        struct stat st = {{}};
        modes = modes && stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0777;
    }}
    check("reset-exact-zeros", all_zero);
    check("reset-original-label-mode-contract", modes && label_calls == 3 && label_contract);
    check("reset-repeat", maplesu::allocation_history::{api}() == KModErr::OK);
    label_calls = 0; fail_label = 2;
    check("reset-first-label-error", maplesu::allocation_history::{api}() == KModErr::ERR_SET_FILE_SELINUX && label_calls == 2);
    label_calls = 0; fail_label = 0;
    std::filesystem::remove(paths[1]);
    std::filesystem::create_symlink("/dev/full", paths[1]);
    check("reset-write-error-stops-before-label", maplesu::allocation_history::{api}() == KModErr::ERR_MODULE_WRITE_FILE && label_calls == 0);
    std::filesystem::remove_all(root);
    check("reset-dev-path-fallback", maplesu::allocation_history::{api}() == KModErr::OK && {getters[0]}().rfind("/dev/", 0) == 0);
    return failures ? 1 : 0;
}}
'''
        (out / f"test-{idx}.cpp").write_text(harness, encoding="utf-8")
        run(f"host-compile-{idx}", [*docker, "-c", 'exec "$@"', "sh", "g++", "-std=c++20", "-O1",
            "-ffunction-sections", "-fdata-sections", "-I/work/host-include", "-I/upstream-include",
            "-I/sdk/include", f"test-{idx}.cpp", "-Wl,--gc-sections,--wrap=setxattr", "-o", f"test-{idx}"])
        stdout = run(f"host-runtime-{idx}", [*docker, "-c", 'exec "$@"', "sh", f"./test-{idx}"])
        rows += [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]

    sys.path.insert(0, str(SDK / "tools"))
    import sdk_common as S
    manifest = [json.loads(line) for line in (SDK / "manifest.jsonl").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    compiler = S.DEFAULT_NDK / S.TOOLCHAIN_SUBDIR / "clang++.exe"
    run("ndk-version", [compiler, "--version"])
    objects = []
    for idx, (name, _) in MEMBERS.items():
        entry = next(row for row in manifest if row["idx"] == idx)
        target = out / (name + ".o")
        flags = S.profile_flags(entry["flagsProfile"], "cxx", entry.get("extraFlags", []))
        run(f"ndk-compile-{idx}", [compiler, *flags, "-I", public, "-I", SDK / "include", "-MMD",
            "-MF", str(target) + ".d", "-c", production[idx - 31], "-o", target])
        objects.append({"idx": idx, "profile": entry["flagsProfile"], "extraFlags": entry.get("extraFlags", []), **receipt(target)})
    preserved = before == [receipt(path) for path in production]
    result = {"schema": "maplesu-history-storage-test/1", "image": IMAGE,
              "sourceInputs": before, "sourceInputsPreserved": preserved,
              "kernelExecution": False, "androidExecution": False, "deviceAccess": False,
              "boundary": "Real source/public headers; declaration-only Android property shim; unrelated code removed by section GC.",
              "commands": commands, "cases": rows, "objects": objects,
              "passed": preserved and len(rows) == 34 and all(row["passed"] for row in rows)}
    (out / "RESULTS.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "cases": len(rows), "ndkObjects": len(objects), "out": str(out)}))
    if not result["passed"]:
        raise RuntimeError("History storage checks failed")


if __name__ == "__main__":
    main()
