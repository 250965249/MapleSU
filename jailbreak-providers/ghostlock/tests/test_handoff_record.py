"""Execute the restore-record shell tail extracted from the production adapter."""
import ast
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from test_restore import BASH, ROOT, baseline_probe


class HandoffRecordTest(unittest.TestCase):
    def record(self, *, enforcing="1", checkreqprot="0", baseline=0, rc=0):
        source = (ROOT / "adapter/handoff.cpp").read_text()
        start = source.index('"\\n)\\nRESTORE_RC=$?\\n"')
        end = source.index('"exec "', start)
        tail = "".join(ast.literal_eval(literal) for literal in
                       re.findall(r'"(?:\\.|[^"\\])*"', source[start:end]))
        tail = tail[tail.index("RESTORE_RC=$?"):]
        tail = tail.replace("/sys/fs/selinux/", "$FIXTURE/")
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, value in (("enforce", enforcing), ("checkreqprot", checkreqprot)):
                if value is not None:
                    (directory / name).write_text(value + "\n")
            script = (f'FIXTURE="$PWD"\nBASELINE_CHECKREQPROT={baseline}\n'
                      + baseline_probe().replace("/sys/fs/selinux", "$FIXTURE") +
                      f'(exit {rc})\n' + tail +
                      'printf "%s:%s:%s\\n" "$RESTORE_RC" "$ENF" "$CRP"\n')
            (directory / "record.sh").write_text(script, newline="\n")
            result = subprocess.run([BASH, "record.sh"], cwd=directory, capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

    def test_boolean_values_and_restore_exit_code_survive_serialization(self):
        for enforcing in ("0", "1"):
            for checkreqprot in ("0", "1"):
                for rc in (0, 76):
                    with self.subTest(enforcing=enforcing, checkreqprot=checkreqprot, rc=rc):
                        self.assertEqual(self.record(enforcing=enforcing,
                                                     checkreqprot=checkreqprot, rc=rc),
                                         f"{rc}:{enforcing}:{checkreqprot}")

    def test_only_expected_absence_is_serialized_as_absent(self):
        self.assertEqual(self.record(checkreqprot=None, baseline=-2), "0:1:-2")
        self.assertEqual(self.record(checkreqprot=None, baseline=-1), "0:1:-2")
        self.assertEqual(self.record(checkreqprot="0", baseline=-2), "0:1:0")

    def test_missing_or_malformed_values_are_numeric_unknowns(self):
        for value in (None, "", "u", "2", "0\n1"):
            with self.subTest(value=value):
                self.assertEqual(self.record(enforcing=value), "0:-1:0")
                self.assertEqual(self.record(checkreqprot=value), "0:1:-1")
        self.assertEqual(self.record(checkreqprot="u", baseline=-2), "0:1:-1")


if __name__ == "__main__":
    unittest.main()
