#!/usr/bin/env python3
"""Run the current native legacy dispatcher with the actual resource helpers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"


def extract(text, signature, structure=False):
    start = text.index(signature)
    brace = text.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end + int(structure)]


def replace_once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    kernel = ROOT / "runtime/ultra/identity/kernel/manager_management.c"
    legacy = ROOT / "runtime/ultra/identity/kernel/manager_legacy_hook.inc"
    shared_fixture = ROOT / "runtime/maplesu-sdk/sdk/tests/p5_legacy_provider_fixture.cpp"
    inputs = [Path(__file__).resolve(), HERE / "fixture.cpp", kernel, legacy, shared_fixture,
              ROOT / "runtime/ultra/authorization/request_protocol.h",
              ROOT / "runtime/ultra/authorization/execution_frame.h",
              ROOT / "runtime/ultra/authorization/legacy_hook_private.h"]
    before = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    source = kernel.read_text(encoding="utf-8")
    prefix = shared_fixture.read_text(encoding="utf-8").split("// EXACT_FUNCTIONS")[0]
    resource = extract(source, "enum msu_management_backend {", True) + "\n" + extract(
        source, "struct msu_management_resource {", True)
    prefix = replace_once(prefix, "struct msu_management_resource{bool publication=false;};", resource)
    prefix = replace_once(prefix, "struct msu_publication{mutex operation;", "struct msu_publication{struct msu_runtime_service* service=nullptr;mutex operation;")
    prefix = replace_once(prefix, " u64 next_session=1;", " msu_management_resource resources[64]{};u64 next_resource=1;\n u64 next_session=1;")
    stubbed = ["msu_management_shape", "msu_management_release_all", "msu_management_alloc",
               "msu_management_exec", "msu_management_write", "msu_management_resource", "msu_management_release",
               "msu_management_credentials"]
    prefix = "\n".join(line for line in prefix.splitlines() if not any(
        f" {name}(" in line or f"* {name}(" in line for name in stubbed)
        and line != "static msu_management_resource resource;") + "\n"
    (out / "prefix.inc").write_text(prefix, encoding="utf-8")
    signatures = ["static void msu_management_clear_resource(", "static int msu_management_release(",
                  "static int msu_management_release_all(",
                  "static struct msu_management_resource *msu_management_resource_domain(",
                  "static struct msu_management_resource *msu_management_resource(",
                  "static int msu_management_alloc_domain(", "static int msu_management_alloc(",
                  "static int msu_management_write(", "static int msu_management_exec(",
                  "static bool msu_management_shape(", "int msu_management_validate_credentials(void *context)\n{",
                  "static int msu_management_credentials("]
    functions = "\n\n".join(extract(source, name) for name in signatures)
    # The production source is C. The fixture is C++ solely to reuse the existing
    # task/cred provider seams; implicit void* conversions are explicit.
    functions = functions.replace("bytes = vmalloc(", "bytes = (unsigned char *)vmalloc(")
    functions = functions.replace("maplesu_standard_frame_valid(resource->address,", "maplesu_standard_frame_valid((const unsigned char *)resource->address,")
    functions = functions.replace("msu_management_check(context)", "msu_management_check((msu_management_session*)context)")
    (out / "functions.inc").write_text(functions, encoding="utf-8")
    (out / "legacy.inc").write_text(legacy.read_text(encoding="utf-8").replace(
        "session = kzalloc(", "session = (msu_management_session*)kzalloc("), encoding="utf-8")
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:rw,size=32m", "-e", "ASAN_OPTIONS=detect_leaks=1",
              "-e", "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
              "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/work", "-w", "/work", IMAGE]
    command = [*docker, "g++", "-std=c++20", "-O1", "-g", "-fsanitize=address,undefined",
               "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-I/work",
               "-I/repo/runtime/ultra/authorization", "/repo/" + (HERE / "fixture.cpp").relative_to(ROOT).as_posix(),
               "-o", "native-management-test"]
    results = []
    for name, argv in [("compile", command), ("test", [*docker, "./native-management-test"])]:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace")
        text = done.stdout + done.stderr
        (out / f"{name}.log").write_text(text, encoding="utf-8")
        print(text, end="")
        results.append({"name": name, "argv": argv, "exit": done.returncode})
        if done.returncode:
            break
    stable = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in before.items())
    passed = stable and len(results) == 2 and all(not r["exit"] for r in results)
    (out / "results.json").write_text(json.dumps({"passed": passed, "sources": before, "sourcesUnchanged": stable,
        "functions": signatures, "commands": results,
        "scope": "actual native legacy scope/dispatch, resource and credential session helpers; allocator, page permission, JIT call, credential replacement and task-state APIs are seams; no device"}, indent=2) + "\n", encoding="utf-8")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
