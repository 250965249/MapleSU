"""Exercise the actual authenticated EXEC scope; provider operations are fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "jailbreak-providers/root-loader/module/maplesu_boot_sdk.c"
PRIVATE = ROOT / "runtime/ultra/authorization"


def function(source, name):
    start = source.rfind("\n", 0, source.index(name + "(")) + 1
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text(encoding="utf-8")
    structure = source[source.index("struct sdk_legacy_scope {"):]
    structure = structure[:structure.index("};") + 2]
    bodies = structure + "\n" + "\n".join(function(source, name) for name in
        ("legacy_scope_begin", "legacy_scope_end"))
    (out / "scope.inc").write_text(bodies, encoding="utf-8")
    fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "legacy_hook_private.h"
#define MSU_PH_NOCFI
typedef uintptr_t uptr;
typedef unsigned long long u64;
extern unsigned char msu_boot_sdk_legacy_scope_start[], msu_boot_sdk_legacy_scope_end[];
static void zero(void *p, unsigned long n) { memset(p, 0, n); }
static int get_count, put_count, binds, begins, ends, get_error, end_error;
static u64 bind_result, begin_result;
static struct maplesu_legacy_hook_provider provider;
static int lease;
static int get(const struct maplesu_legacy_hook_provider **p, void **l) {
    ++get_count; *p = &provider; *l = &lease; return get_error;
}
static void put(void *l) { assert(l == &lease); ++put_count; }
static u64 bind(u64 base, u64 bytes) {
    ++binds; assert(base == (uintptr_t)msu_boot_sdk_legacy_scope_start);
    assert(bytes && base + bytes == (uintptr_t)msu_boot_sdk_legacy_scope_end);
    return bind_result;
}
static u64 begin(u64 token) { ++begins; assert(token == bind_result); return begin_result; }
static int end(u64 token) { ++ends; assert(token == begin_result); return end_error; }
static int (*legacy_provider_get)(const struct maplesu_legacy_hook_provider **, void **);
static void (*legacy_provider_put)(void *);
#include "scope.inc"
static void reset(void) {
    get_count = put_count = binds = begins = ends = get_error = end_error = 0;
    bind_result = 123; begin_result = 456;
    provider = (struct maplesu_legacy_hook_provider){
        .magic = MAPLESU_LEGACY_HOOK_MAGIC, .schema = MAPLESU_LEGACY_HOOK_SCHEMA,
        .length = sizeof provider, .bind_function = (uintptr_t)bind,
        .begin_function = (uintptr_t)begin, .end_function = (uintptr_t)end,
        .dispatch_function = 1 };
    legacy_provider_get = get; legacy_provider_put = put;
}
int main(void) {
    struct sdk_legacy_scope scope;
    reset(); legacy_provider_get = 0;
    legacy_scope_begin(&scope); assert(!scope.scope && !get_count && !put_count);
    reset(); legacy_provider_put = 0;
    legacy_scope_begin(&scope); assert(!scope.scope && !get_count && !put_count);
    reset(); get_error = -2;
    legacy_scope_begin(&scope); assert(!scope.scope && get_count == 1 && !put_count);
    for (int i = 0; i < 7; ++i) {
        reset();
        switch (i) {
        case 0: provider.magic = 0; break;
        case 1: provider.schema = 0; break;
        case 2: provider.length = 0; break;
        case 3: provider.bind_function = 0; break;
        case 4: provider.begin_function = 0; break;
        case 5: provider.end_function = 0; break;
        case 6: provider.dispatch_function = 0; break;
        }
        legacy_scope_begin(&scope); assert(!scope.scope && get_count == 1 && put_count == 1 && !begins);
    }
    reset(); bind_result = 0;
    legacy_scope_begin(&scope); assert(!scope.scope && binds == 1 && !begins && put_count == 1);
    reset(); begin_result = 0;
    legacy_scope_begin(&scope); assert(!scope.scope && begins == 1 && put_count == 1);
    for (int i = 0; i < 2; ++i) {
        reset(); end_error = i ? -116 : 0;
        legacy_scope_begin(&scope); assert(scope.scope == begin_result && !put_count);
        assert(legacy_scope_end(&scope) == end_error && ends == 1 && put_count == 1);
        assert(!scope.provider && !scope.lease && !scope.scope);
        assert(legacy_scope_end(&scope) == 0 && ends == 1 && put_count == 1);
    }
    printf("{\"groups\":14,\"passed\":true}");
    return 0;
}
'''
    path = out / "scope_test.c"
    path.write_text(fixture, encoding="utf-8")
    compiler = Path("C:/msys64/ucrt64/bin/gcc.exe")
    env = dict(os.environ, PATH=str(compiler.parent) + os.pathsep + os.environ.get("PATH", ""))
    command = [str(compiler), "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I" + str(PRIVATE), "-I" + str(out), str(path), "-o", str(out / "scope.exe")]
    compiled = subprocess.run(command, capture_output=True, text=True, env=env)
    (out / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    result = subprocess.run([str(out / "scope.exe")], capture_output=True, text=True, env=env) if not compiled.returncode else compiled
    (out / "run.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    report = {"sourceSha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "command": command, "compileExit": compiled.returncode, "exitCode": result.returncode,
        "scope": "Production begin/end bodies; uintptr_t adapts LP64 pointers to LLP64; native provider/task APIs are fixtures, no device execution"}
    if not result.returncode:
        report.update(json.loads(result.stdout))
    (out / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
