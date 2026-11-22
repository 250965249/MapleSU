"""Static policy tests for the maplesu-ghostlock P0 contract layer.

These assert properties of the source tree, not device behaviour: the layer must
be structurally unable to touch a device or a kernel, must not carry reference
material, must stay freestanding-friendly, and must keep its documented schema
and error-code contract in sync with the code.

Design: docs/patching/skroot-pro-logic-port-design-2026-10-29.md (§3, §5 P0, §6).

Note: every forbidden token in this file is assembled from fragments. That keeps
the G-P0-5 raw grep over this directory clean while still letting the tests name
what they refuse (the alternative would be a scanner that matches itself).
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
SRC = ROOT / "src"
INCLUDE = ROOT / "include"
TESTS = ROOT / "tests"
GATES = ROOT / "gates"


def _join(*parts: str) -> str:
    return "".join(parts)


EXPECTED_KEYS = [
    "msk_spec_version",
    "release",
    "kernel_phys_load",
    "kernel_phys_offset",
    "page_offset",
    "selinux_enforcing_off",
    "init_cred_off",
    "task_real_cred_off",
    "task_cred_off",
    "task_seccomp_off",
    "task_comm_off",
    "waiter_shift",
    "kernelsnitch_collisions",
]

# Calls that would give this layer the ability to act on a device or a process.
BANNED_CODE_TOKENS = [
    _join("op", "en("),
    _join("op", "enat("),
    _join("fop", "en("),
    _join("io", "ctl("),
    _join("sys", "call("),
    _join("fo", "rk("),
    _join("clo", "ne("),
    _join("pt", "race("),
    _join("mount", "("),
    _join("po", "pen("),
    _join("sys", "tem("),
    _join("exec", "ve"),
    _join("exec", "v("),
    _join("exec", "l("),
    _join("sock", "et("),
    _join("unl", "ink("),
    _join("chm", "od("),
    _join("setx", "attr"),
    _join("dl", "open"),
    _join("mm", "ap("),
    _join("ki", "ll("),
    _join("ch", "root("),
    _join("re", "boot("),
    _join("ins", "mod"),
    _join("rm", "mod"),
    _join("init", "_module"),
    _join("finit", "_module"),
    _join("delete", "_module"),
]

BANNED_PATHS = ["/dev/", "/proc/", "/sys/", "/system/", "/data/"]

BANNED_REFERENCE_TOKENS = [
    _join("root", "Key"),
    _join("libcve2026", "_43499"),
    _join("COMPACT", "_WAITER"),
    _join("module_su", "_redirect"),
    _join("sk", "_spec/"),
    _join("ghostleaf", "_"),
    _join("permission", "manager"),
    _join("SkBoot", "Patcher"),
    _join("ks", "ud"),
    _join("install", ".mode"),
]

ALLOWED_SYSTEM_HEADERS = {"stddef.h", "stdint.h"}


def strip_c_comments(text: str) -> str:
    """Remove // and /* */ comments so prose cannot trip the token scan."""
    out = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "/" and index + 1 < length and text[index + 1] == "/":
            while index < length and text[index] != "\n":
                index += 1
        elif char == "/" and index + 1 < length and text[index + 1] == "*":
            index += 2
            while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                index += 1
            index += 2
        else:
            out.append(char)
            index += 1
    return "".join(out)


def code_files():
    return sorted(list(SRC.glob("*.c")) + list(INCLUDE.glob("*.h")))


def all_implementation_files():
    return sorted(list(code_files()) + [TESTS / "msk_tests.c"] + list(GATES.glob("*.py")))


class TestNoDeviceReach(unittest.TestCase):
    def test_no_banned_code_tokens(self):
        for path in code_files():
            code = strip_c_comments(path.read_text(encoding="utf-8"))
            for token in BANNED_CODE_TOKENS:
                self.assertNotIn(
                    token,
                    code,
                    "%s contains %r: the contract layer must stay pure" % (path.name, token),
                )

    def test_no_banned_paths(self):
        for path in code_files():
            code = strip_c_comments(path.read_text(encoding="utf-8"))
            for fragment in BANNED_PATHS:
                self.assertNotIn(fragment, code, "%s references %r" % (path.name, fragment))

    def test_no_system_headers_beyond_allowed(self):
        include_rx = re.compile(r'#include\s*<([^>]+)>')
        for path in code_files():
            for header in include_rx.findall(path.read_text(encoding="utf-8")):
                self.assertIn(
                    header,
                    ALLOWED_SYSTEM_HEADERS,
                    "%s includes <%s>: only freestanding headers are allowed"
                    % (path.name, header),
                )

    def test_only_own_project_headers(self):
        include_rx = re.compile(r'#include\s*"([^"]+)"')
        for path in code_files():
            for header in include_rx.findall(path.read_text(encoding="utf-8")):
                self.assertTrue(
                    header.startswith("msk_") and header.endswith(".h"),
                    "%s includes %r: only msk_* headers are allowed" % (path.name, header),
                )

    def test_no_dynamic_allocation_or_stdio(self):
        for path in code_files():
            code = strip_c_comments(path.read_text(encoding="utf-8"))
            for token in ("malloc(", "calloc(", "realloc(", "free(", "printf(", "fprintf(",
                          "snprintf(", "strcpy(", "strcat(", "sprintf("):
                self.assertNotIn(token, code, "%s uses %s" % (path.name, token))


class TestNoReferenceMaterial(unittest.TestCase):
    def test_no_reference_identifiers_in_code(self):
        for path in code_files():
            text = path.read_text(encoding="utf-8")
            for token in BANNED_REFERENCE_TOKENS:
                self.assertNotIn(
                    token,
                    text,
                    "%s carries reference-implementation material (%r)" % (path.name, token),
                )

    def test_no_reference_identifiers_in_gate_and_tests(self):
        for path in all_implementation_files():
            text = path.read_text(encoding="utf-8")
            for token in BANNED_REFERENCE_TOKENS:
                if token.startswith("/") or token.endswith("("):
                    continue
                self.assertNotIn(
                    token,
                    text,
                    "%s carries reference-implementation material (%r)" % (path.name, token),
                )

    def test_readme_declares_non_functional_and_origin(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("NOT FUNCTIONAL", readme)
        self.assertIn("NOT FOR DEVICE", readme)
        self.assertIn("参考实现", readme)
        self.assertIn("提权原语", readme)


class TestEncodingAndIsolation(unittest.TestCase):
    def test_implementation_files_are_ascii(self):
        for path in all_implementation_files():
            try:
                path.read_bytes().decode("ascii")
            except UnicodeDecodeError as error:
                self.fail("%s is not ASCII: %s" % (path.name, error))

    def test_readme_is_utf8(self):
        text = (ROOT / "README.md").read_bytes().decode("utf-8")
        self.assertIn("MSK1", text)

    def test_not_registered_in_build(self):
        self.assertFalse((ROOT / "CMakeLists.txt").exists(),
                         "this layer must not be registered in CMake")
        self.assertFalse((ROOT / "build.py").exists(),
                         "this layer must not carry a build entry point")
        providers_cmake = (REPO / "jailbreak-providers" / "CMakeLists.txt").read_text(
            encoding="utf-8")
        self.assertNotIn("maplesu-ghostlock", providers_cmake)

    def test_production_gate_untouched(self):
        gate = REPO / "jailbreak-providers" / "check_traceless_invariants.py"
        self.assertTrue(gate.is_file())
        text = gate.read_text(encoding="utf-8")
        self.assertNotIn("maplesu-ghostlock", text,
                         "the production gate must not be wired to this layer")

    def test_gate_files_exist(self):
        self.assertTrue((GATES / "run_gates.py").is_file())
        self.assertTrue((GATES / "toolchain.py").is_file())


class TestApiSurface(unittest.TestCase):
    def test_public_api_is_declared(self):
        headers = {
            "msk_spec.h": ("msk_spec_parse", "msk_spec_parse_ex", "msk_spec_validate",
                           "msk_spec_accept_release", "msk_spec_digest",
                           "msk_spec_schema_digest", "struct msk_binding"),
            "msk_plan.h": ("msk_plan_build", "msk_plan_validate", "msk_plan_page_layout_accepts",
                           "msk_machine_arm", "msk_machine_step", "msk_machine_reset",
                           "msk_machine_effect", "msk_ops_ready", "struct msk_ops",
                           "MSK_PLAN_STEPS", "MSK_VERIFY_NONE"),
            "msk_handoff.h": ("msk_handoff_render", "msk_ready_parse", "msk_failure_from_status",
                              "MSK_READY_MAGIC", "struct msk_handoff_input"),
            "msk_digest.h": ("msk_sha256", "msk_sha256_init", "msk_sha256_update",
                             "msk_sha256_final"),
        }
        for name, symbols in headers.items():
            text = (INCLUDE / name).read_text(encoding="utf-8")
            for symbol in symbols:
                self.assertIn(symbol, text, "%s must declare %s" % (name, symbol))

    def test_every_declared_function_is_defined(self):
        declaration_rx = re.compile(r"\b(msk_[a-z0-9_]+)\s*\(")
        sources = "\n".join(path.read_text(encoding="utf-8") for path in SRC.glob("*.c"))
        for header in INCLUDE.glob("*.h"):
            text = strip_c_comments(header.read_text(encoding="utf-8"))
            for name in set(declaration_rx.findall(text)):
                if name == "msk_lit":
                    continue
                self.assertRegex(
                    sources,
                    r"\b%s\s*\(" % re.escape(name),
                    "%s is declared in %s but not defined in src/" % (name, header.name),
                )

    def test_error_codes_are_unique_and_ordered(self):
        values = {}
        # Negative status values only: hop/verify/state enumerations reuse 0..8
        # as ordinal values and are not status codes.
        code_rx = re.compile(r"\b(MSK_[A-Z][A-Z0-9_]*)\s*=\s*(-\d+)")
        for header in INCLUDE.glob("*.h"):
            for name, value in code_rx.findall(header.read_text(encoding="utf-8")):
                number = int(value)
                self.assertNotIn(number, values,
                                 "%s reuses status value %d (also %s)"
                                 % (name, number, values.get(number)))
                values[number] = name
        expected = {
            "MSK_EINCOMPLETE": -2,
            "MSK_EUNSUPPORTED": -3,
            "MSK_EUNKNOWNKEY": -6,
            "MSK_EDUPLICATE": -7,
            "MSK_EBADVERSION": -9,
            "MSK_PLAN_INCOMPLETE": -41,
            "MSK_SM_EREENTRY": -62,
            "MSK_HANDOFF_ERESTORE_WEAK": -83,
            "MSK_READY_WRONG_BOOT": -93,
        }
        for name, number in expected.items():
            self.assertEqual(values.get(number), name)

    def test_plan_and_hop_counts(self):
        plan = (INCLUDE / "msk_plan.h").read_text(encoding="utf-8")
        self.assertIn("MSK_PLAN_STEPS 9u", plan)
        hops = re.findall(r"MSK_HOP_([A-Z_]+)\s*=\s*(\d+)", plan)
        verifies = re.findall(r"MSK_VERIFY_([A-Z_]+)\s*=\s*(\d+)", plan)
        # Eight real hops plus the COUNT sentinel; nine verdicts plus COUNT.
        self.assertEqual(len(hops), 9, "eight hops: design's seven plus restore")
        self.assertEqual(len(verifies), 10, "nine verdict kinds including NONE")
        self.assertIn(("RESTORE", "5"), hops)
        self.assertIn(("RESTORE_READBACK", "7"), verifies)
        self.assertIn(("MAGIC_ROUNDTRIP", "8"), verifies)

    def test_no_token_formatter_is_exposed(self):
        """Userspace must not be able to mint a readiness token (C10/R-9)."""
        handoff = (INCLUDE / "msk_handoff.h").read_text(encoding="utf-8")
        self.assertNotRegex(handoff, r"msk_ready_(format|emit|build|make)\s*\(")
        source = (SRC / "msk_handoff.c").read_text(encoding="utf-8")
        emitted = set(re.findall(r"\b(msk_ready_[a-z0-9_]+)\s*\(", source))
        self.assertEqual(emitted, {"msk_ready_parse"},
                         "only the accept-only parser may exist")


class TestReadmeContract(unittest.TestCase):
    def setUp(self):
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_schema_block_matches_schema_constant(self):
        marker = "<!-- MSK1-SCHEMA-KEYS -->"
        self.assertIn(marker, self.readme)
        after = self.readme.split(marker, 1)[1]
        block = after.split("```text", 1)[1].split("```", 1)[0]
        keys = [line.strip() for line in block.splitlines() if line.strip()]
        self.assertEqual(keys, EXPECTED_KEYS)

    def test_gates_documented(self):
        for name in ("G-P0-1", "G-P0-2", "G-P0-3", "G-P0-4", "G-P0-5"):
            self.assertIn(name, self.readme)
        self.assertIn("checks=26", self.readme)
        self.assertIn("SUMMARY PASS (5/5 gates)", self.readme)
        self.assertIn("run_gates.py", self.readme)

    def test_boundary_list_is_explicit(self):
        for phrase in ("一机一码", "boot", "SELinux", "Provider method", "C1–C10"):
            self.assertIn(phrase, self.readme)

    def test_restore_contract_is_documented(self):
        for marker in ("# MSK-RESTORE:begin", "# MSK-RESTORE:readback",
                       "# MSK-RESTORE:end", "restore", "readback"):
            self.assertIn(marker, self.readme)


if __name__ == "__main__":
    unittest.main()
