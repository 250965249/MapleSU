"""Replay the retained k22 executor through its existing producer; no image migration.

Only three frozen records and existing small captures are read. Translating every
captured address by the executor base preserves branch bytes and needs just 124
zero fixture bytes, which are not claimed to be a native kernel preimage.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))

from specgen import a64, kallsyms
from specgen.recipe import Recipe, RenderError, render


ORACLE = ROOT / "tools/specgen/specgen/recipes/k22.json"
CAPTURES = ROOT / "docs/dual-mode/impl/_work/2026-11-16/evidence/legacy-hook-upgrade-qualification-r1"
EXECUTOR = "__drm_printfn_coredump"


def executor_recipe():
    oracle = Recipe.load(ORACLE)
    return Recipe(oracle.id, oracle.reference_release,
                  [record for record in oracle.records if record.symbol == EXECUTOR])


def captured_executor(case):
    symbols, branches = {}, {}
    for line in (CAPTURES / f"case-{case}.stdout.log").read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] == "WINDOW":
            symbols[fields[1]] = int(fields[2])
            if fields[1] == EXECUTOR:
                body = bytes.fromhex(fields[-1].removeprefix("hex="))[:124]
        elif fields[0] == "CALLEE" and fields[2] != "null":
            symbols[fields[1]] = int(fields[2])
        elif fields[0] == "LOCAL_BRANCH" and fields[1] == EXECUTOR:
            branches[int(fields[2])] = (fields[3], int(fields[4]), fields[5])
    # The retained recipe names the one-argument release contract. Case07's
    # captured target is explicitly execmem_free; no allocation alias is inferred.
    release = branches[80]
    if release[2] == "execmem_free":
        symbols["module_memfree"] = release[1]
    base = symbols[EXECUTOR]
    table = kallsyms.SymbolTable(124, 0, 0,
        sorted((offset - base, "T", name) for name, offset in symbols.items()), {})
    return body, table, branches, base


class LegacyExecutorProducerTest(unittest.TestCase):
    def test_existing_producer_reproduces_both_complete_captures(self):
        recipe = executor_recipe()
        self.assertEqual([(record.delta, record.length) for record in recipe.records],
                         [(0, 88), (88, 16), (104, 20)])
        for case in ("07", "17"):
            with self.subTest(case=case):
                captured, table, branches, base = captured_executor(case)
                records = render(recipe, table, bytes(124), b"A" * 48)
                produced = b"".join(record.replacement for record in records)
                self.assertEqual(produced, captured)
                self.assertEqual(len(produced), 124)
                self.assertEqual([at for at in range(0, 124, 4)
                                  if a64.le32(produced, at) == 0xD63F0140], [56])
                for at, (operation, target, _owner) in branches.items():
                    if at < 124:
                        word = a64.le32(produced, at)
                        self.assertEqual(a64.is_bl(word), operation == "BL")
                        self.assertEqual(a64.decode_branch(word, base + at), target)
                self.assertEqual(branches[80][2],
                                 "execmem_free" if case == "07" else "module_memfree")

    def test_release_target_is_relocated_and_missing_target_is_reported(self):
        recipe = executor_recipe()
        _captured, table, _branches, _base = captured_executor("17")
        original = b"".join(record.replacement
                            for record in render(recipe, table, bytes(124), b"A" * 48))
        moved = kallsyms.SymbolTable(124, 0, 0,
            [(offset + (4 if name == "module_memfree" else 0), kind, name)
             for offset, kind, name in table.rows], {})
        changed = b"".join(record.replacement
                           for record in render(recipe, moved, bytes(124), b"A" * 48))
        self.assertNotEqual(changed[80:84], original[80:84])
        self.assertEqual(changed[:80] + changed[84:], original[:80] + original[84:])
        missing = kallsyms.SymbolTable(124, 0, 0,
            [row for row in table.rows if row[2] != "module_memfree"], {})
        with self.assertRaisesRegex(RenderError, "TARGET_SYMBOL_MISSING:module_memfree"):
            render(recipe, missing, bytes(124), b"A" * 48)


if __name__ == "__main__":
    unittest.main()
