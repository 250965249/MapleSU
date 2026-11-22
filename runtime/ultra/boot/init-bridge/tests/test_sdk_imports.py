"""Narrow source/lookup fixtures; not target ABI, CFI or loading qualification.

The import fixture supplies int/size_t random declarations and mocks resolution;
it never calls a resolved address. Producer checks preprocess the current real
source with includes removed, so they cover branch selection, not a kernel TU.
Run only through the central evidence executor after producer owner integration.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

BRIDGE = Path(__file__).resolve().parents[1]
AFTER = BRIDGE.parents[3]
PRODUCER = AFTER / "jailbreak-providers/root-loader/module/maplesu_boot_sdk.c"
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")
INCLUDES = re.compile(r"^\s*#\s*include[^\n]*", re.MULTILINE)
DEFINITIONS = r"""
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#define noinline __attribute__((noinline))
#define __user
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
typedef unsigned int gfp_t;
typedef struct { unsigned long pgprot; } pgprot_t;
struct cred; struct task_struct; struct pt_regs;
struct maplesu_legacy_hook_provider;
int maplesu_legacy_hook_provider_get(const struct maplesu_legacy_hook_provider **, void **);
void maplesu_legacy_hook_provider_put(void *);
void get_random_bytes(void *, RANDOM_LENGTH);
long copy_from_user_nofault(void *, const void *, size_t);
long copy_to_user_nofault(void *, const void *, size_t);
long copy_from_kernel_nofault(void *, const void *, size_t);
long copy_to_kernel_nofault(void *, const void *, size_t);
void *vmalloc(unsigned long);
void *__vmalloc_node_range(unsigned long, unsigned long, unsigned long,
    unsigned long, gfp_t, pgprot_t, unsigned long, int, const void *);
void vfree(const void *);
void caches_clean_inval_pou(unsigned long, unsigned long);
struct cred *prepare_creds(void);
int commit_creds(struct cred *);
const struct cred *get_task_cred(struct task_struct *);
void __put_cred(struct cred *);
#define MEMORY(name) int msu_native_##name(unsigned long a, int b) { return !!a + b; }
MEMORY(set_memory_ro)
MEMORY(set_memory_rw)
MEMORY(set_memory_x)
MEMORY(set_memory_nx)
static unsigned int checked_calls, address_calls;
static int resolver_error;
static int msu_init_bridge_resolve_cfi(const char *name, const void *reference,
    unsigned long *address)
{
    assert(name && reference && address);
    ++checked_calls;
    if (resolver_error) return resolver_error;
    *address = 0x1000;
    return 0;
}
static unsigned long msu_init_bridge_lookup(const char *name)
{
    assert(name);
    ++address_calls;
    return 0x2000;
}
"""
CASES = r"""
int main(void)
{
    assert(!msu_init_bridge_checked_lookup(NULL));
    assert(!msu_init_bridge_checked_lookup("get_random_bytes"));
    assert(!msu_init_bridge_checked_lookup("unknown"));
    assert(!checked_calls && !address_calls);
    assert(!strcmp(sdk_symbols[ARRAY_SIZE(sdk_symbols) - 2].name, "maplesu_legacy_hook_provider_get"));
    assert(!strcmp(sdk_symbols[ARRAY_SIZE(sdk_symbols) - 1].name, "maplesu_legacy_hook_provider_put"));
    for (unsigned int i = 0; i < ARRAY_SIZE(sdk_symbols); ++i) {
        unsigned int before = checked_calls;
        resolver_error = -EPERM;
        assert(!msu_init_bridge_checked_lookup(sdk_symbols[i].name));
        assert(checked_calls == before + 1 && !sdk_symbols[i].address);
        resolver_error = 0;
        assert(msu_init_bridge_checked_lookup(sdk_symbols[i].name) == 0x1000);
        assert(checked_calls == before + 2);
        assert(msu_init_bridge_checked_lookup(sdk_symbols[i].name) == 0x1000);
        assert(checked_calls == before + 2);
    }
    assert(msu_init_bridge_checked_lookup("vmalloc") == 0x1000);
    assert(msu_init_bridge_checked_lookup("set_memory_ro") == 0x1000);
    assert(msu_init_bridge_checked_lookup("_text") == 0x2000);
    assert(address_calls == 1);
    return 0;
}
"""


class SdkImportChecks(unittest.TestCase):
    def test_imports_without_random_binding_accept_both_declared_prototypes(self):
        original = (BRIDGE / "native_sdk_imports.c").read_bytes()
        source_text = INCLUDES.sub("", original.decode("utf-8"))
        for length in ("int", "size_t"):
            with self.subTest(random_length=length), tempfile.TemporaryDirectory(
                    prefix="bridge-sdk-imports-") as directory:
                output = Path(directory)
                source = output / "fixture.c"
                source.write_text(DEFINITIONS.replace("RANDOM_LENGTH", length)
                                  + source_text + CASES, encoding="utf-8")
                binary = output / "fixture.exe"
                # Match the prepared kernel's zero-filled trailing-field policy.
                subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra",
                                "-Wno-missing-field-initializers",
                                "-Werror", "-UNDEBUG", str(source), "-o", str(binary)],
                               check=True, timeout=25)
                subprocess.run([str(binary)], check=True, timeout=5)
        self.assertEqual((BRIDGE / "native_sdk_imports.c").read_bytes(), original)

    def preprocess_producer(self, native):
        source = INCLUDES.sub("", PRODUCER.read_text(encoding="utf-8"))
        argv = [CC, "-E", "-P", "-Werror", "-x", "c", "-",
                "-DMSU_BS_STATIC_BOOTSTRAP=0", "-DMSU_BS_ENVIRONMENT=0",
                "-DMSU_INIT_BRIDGE_CFI_NONE=1"]
        if native:
            argv.append("-DMSU_BOOT_SDK_NATIVE=1")
        return subprocess.run(argv, input=source, text=True, capture_output=True,
                              check=True, timeout=10).stdout

    def test_native_producer_uses_installed_credential_without_random_dependency(self):
        source = self.preprocess_producer(True)
        self.assertNotRegex(source, r"\b(?:random_bytes|get_random_bytes)\b",
                            "producer owner must guard declaration, RESOLVE and required check")
        self.assertIn("root_key[n] = native_credential[n]", source)
        self.assertIn("msu_sdk_bind_key(root_key, delta)", source)
        self.assertIn("memcmp(root_key, native_credential, MSU_BOOT_SDK_KEY_BYTES)", source)

    def test_non_native_producer_keeps_random_generation_and_required_lookup(self):
        source = self.preprocess_producer(False)
        self.assertIn("random_bytes(random, sizeof random)", source)
        self.assertRegex(source, r'random_bytes\s*=\s*\(void\s*\*\)lookup_name\("get_random_bytes"\)')
        self.assertRegex(source, r"!\s*random_bytes\b")


if __name__ == "__main__":
    unittest.main()
