"""Cross-file test for the step-3 errno -> token mapping (design §7.1).

Three files describe the same decision, and each one alone is easy to edit without the
others noticing:

  * `module/maplesu_root.c` prints the *classified* reason for a failed init
    ("kallsyms_lookup_name not found", "helper exec failed %d", ...);
  * `dirtyfrag/adapter/bootstrap.c` turns the errno into a loader-layer token and then
    overrides it with a handover-layer token when that printk is in the ring-buffer
    dump it just took (`ir_errno_token`);
  * the derived contract (`contracts/*.json → handover.failureReturnsAppMapping`)
    records the table, and `JailbreakExecutor.IR_FAILURE` must accept both namespaces.

So this test is table-driven from the contract: for every recorded printk → token pair,
the printk must exist in the module, the token must be returned by `ir_errno_token`
for exactly that printk, and the App's regex must accept the namespace. A change to
any one side fails here, on the host, instead of producing a mislabelled device
failure.

No device, no compiler: pure text and one JSON file.

Run: python -m unittest discover -s jailbreak-providers/root-loader/tests
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROOT_LOADER = ROOT / "jailbreak-providers" / "root-loader"
MODULE = ROOT_LOADER / "module" / "maplesu_root.c"
BOOTSTRAP = ROOT / "jailbreak-providers" / "dirtyfrag" / "adapter" / "bootstrap.c"
EXECUTOR = ROOT / "manager" / "src" / "main" / "java" / "dev" / "maplesu" / "manager" / \
    "jailbreak" / "JailbreakExecutor.kt"
CONTRACTS = sorted((ROOT_LOADER / "contracts").glob("*.json"))


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _function(text: str, name: str) -> str:
    match = re.search(r"(?m)^[A-Za-z_][^\n;{}]*?(?<![A-Za-z0-9_])" + re.escape(name) +
                      r"\s*\(", text)
    if not match:
        return ""
    brace = text.find("{", match.end())
    if brace < 0:
        return ""
    depth = 0
    for position in range(brace, len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:position + 1]
    return ""


class HandoverTokenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (MODULE, BOOTSTRAP, EXECUTOR):
            if not path.is_file():
                raise unittest.SkipTest("missing input: %s" % path)
        if not CONTRACTS:
            raise unittest.SkipTest("no contract present")
        cls.contract = json.loads(CONTRACTS[0].read_text(encoding="utf-8"))
        cls.module = _text(MODULE)
        cls.bootstrap = _text(BOOTSTRAP)
        cls.executor = _text(EXECUTOR)
        cls.mapping = cls.contract["handover"]["failureReturnsAppMapping"]
        cls.classifier = _function(cls.bootstrap, "ir_errno_token")

    def test_01_the_classifier_exists(self):
        self.assertTrue(self.classifier, "ir_errno_token is missing from bootstrap.c")

    def test_02_loader_layer_table_is_the_documented_one(self):
        table = self.mapping["loaderLayer"]
        self.assertEqual({"EKEYREJECTED", "EOPNOTSUPP", "ENODEV", "EIO", "other"},
                         set(table))
        for errno_name, token in table.items():
            if errno_name == "other":
                # The fallback is the initial value, not an `if`.
                self.assertIn('"%s"' % token, self.classifier)
                continue
            self.assertRegex(
                self.classifier,
                r"errno_value == %s\)\s*token = \"%s\"" % (errno_name, token),
                "no loader-layer branch for %s -> %s" % (errno_name, token))

    def test_03_every_handover_override_exists_on_all_three_sides(self):
        overrides = self.mapping["handoverOverrides"]
        self.assertGreaterEqual(len(overrides), 5)
        for entry in overrides:
            printk, token = entry["printk"], entry["token"]
            # (1) the module really prints it
            self.assertIn(printk, self.module,
                          "maplesu_root.c does not print %r" % printk)
            # (2) the bootstrap turns exactly that printk into exactly that token
            block = self.classifier
            self.assertIn('klog_tail_contains("%s")' % printk, block,
                          "ir_errno_token does not look for %r" % printk)
            # Find the return statement that follows the contains() check.
            index = block.find('klog_tail_contains("%s")' % printk)
            following = block[index:index + 400]
            self.assertRegex(
                following,
                r'return "%s"' % re.escape(token),
                "the override for %r does not return %s" % (printk, token))
            # (3) the App's verdict regex accepts the namespace
            self.assertTrue(token.startswith("MAPLESU_HANDOVER_"))
            self.assertIn("(?:MAPLESU|SKROOT)_(?:IR|HANDOVER)_[A-Z_]+", self.executor,
                          "IR_FAILURE does not accept the handover namespace")

    def test_04_module_returns_are_the_documented_five(self):
        returns = self.contract["handover"]["failureReturns"]
        expected = {"-ENOSYS": "-38", "-ENOENT": "-2", "-EINVAL": "-22",
                    "-ENOMEM": "-12", "-ENODEV": "-19"}
        self.assertEqual(set(expected), set(returns))
        for errno_name, literal in expected.items():
            self.assertIn("return %s;" % literal, self.module,
                          "maplesu_root.c does not return %s (%s)"
                          % (errno_name, literal))

    def test_05_each_override_token_is_reachable_and_unique(self):
        tokens = [entry["token"] for entry in self.mapping["handoverOverrides"]]
        # NO_UMH is deliberately shared by three printks (three ways for the handover
        # pair to be unusable); every other token belongs to exactly one printk, so a
        # new printk cannot silently reuse a meaning.
        counts = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1
        self.assertEqual(3, counts.get("MAPLESU_HANDOVER_NO_UMH"))
        for token, count in counts.items():
            if token == "MAPLESU_HANDOVER_NO_UMH":
                continue
            self.assertEqual(1, count, "%s is claimed by %d printks" % (token, count))

    def test_06_the_app_regex_is_the_expanded_one(self):
        self.assertIn('Regex("maplesu-dirtyfrag: ir: FAILED '
                      '((?:MAPLESU|SKROOT)_(?:IR|HANDOVER)_[A-Z_]+)")', self.executor)
        # ... and it still matches both shapes.
        pattern = re.compile(r"maplesu-dirtyfrag: ir: FAILED ((?:MAPLESU|SKROOT)_(?:IR|HANDOVER)_[A-Z_]+)")
        for token in ("MAPLESU_IR_MODULE_INVALID", "MAPLESU_HANDOVER_NO_EXEC", "SKROOT_IR_MODULE_INVALID", "SKROOT_HANDOVER_NO_EXEC"):
            match = pattern.search("maplesu-dirtyfrag: ir: FAILED %s errno=19" % token)
            self.assertIsNotNone(match, token)
            self.assertEqual(token, match.group(1))


if __name__ == "__main__":
    unittest.main()
