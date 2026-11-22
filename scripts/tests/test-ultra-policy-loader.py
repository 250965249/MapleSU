"""Replay the policy loader against already-built baseline payloads, without Kbuild."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--payloads", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
payloads = args.payloads.resolve()
names = ("android12-5.10", "android13-5.15", "android14-6.1", "android15-6.6",
         "android16-6.12", "android17-6.18")
sources = ["runtime/ultra/policy/kernel_payload.cpp", "runtime/ultra/policy/kernel_layout.cpp",
           "runtime/ultra/policy/kernel_payload_loader.cpp", "runtime/tests/kernel_payload_loader_test.cpp"]
headers = ["runtime/ultra/policy/policy_layout_slots.h", "runtime/ultra/policy/kernel_layout.h",
           "runtime/ultra/policy/kernel_payload_loader.h", "runtime/tests/kernel_payload_io_fixture.h"]
dynamic_sources = ["runtime/tests/kernel_dynamic_payload_test.cpp", "runtime/tests/policy_dynamic_access_fixture.c",
                   "runtime/ultra/policy/kernel/policy_dynamic_layout.h"]
inputs = [root / name for name in sources + headers + dynamic_sources]
dynamic = {}
for name in names:
    path = payloads / name / "policy-view.so"
    inputs.append(path)
    with path.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".dynsym")
        dynamic[name] = bool(symbols and symbols.get_symbol_by_name("maplesu_policy_layout"))
    if dynamic[name]:
        inputs.append(payloads / name / "compiled-layout.json")
    btf = payloads / name / "vmlinux.btf"
    if btf.is_file():
        inputs.append(btf)
before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
flags = "-UNDEBUG -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
common = "c++ -std=c++20 " + flags + "-I/source/runtime/ultra/policy "
with tempfile.TemporaryDirectory(prefix="maplesu-policy-loader-") as output:
    commands = []
    if not all(dynamic.values()):
        commands.append(common + " ".join("/source/" + s for s in sources) + " -o /output/loader-test")
    if any(dynamic.values()):
        commands.append("cc -std=gnu11 " + flags + "-I/source/runtime/ultra/policy "
                        "-I/source/runtime/ultra/policy/kernel /source/runtime/tests/policy_dynamic_access_fixture.c "
                        "-c -o /output/dynamic-access.o")
    for i, name in enumerate(names):
        image = f"/payloads/{name}/policy-view.so"
        if not dynamic[name]:
            commands.append(f"/output/loader-test {image}" + (" dynamic-scs" if i >= 2 else ""))
            continue
        target = Path(output) / name
        target.mkdir()
        layout = json.loads((payloads / name / "compiled-layout.json").read_text(encoding="utf-8"))
        lines = ['#include "kernel_layout.h"',
                 'inline std::vector<maplesu::module_policy::LayoutType> compiled_layout() { return {']
        for item in layout:
            fields = ",".join('{"%s",%d,%d}' % (f["name"], f["bit_offset"], f["bit_size"])
                              for f in item["fields"])
            lines.append('{"%s",%d,{%s}},' % (item["name"], item["size"], fields))
        lines.append("}; }")
        (target / "compiled-layout.h").write_text("\n".join(lines) + "\n", encoding="utf-8")
        commands.append(common + f"-I/output/{name} " +
                        " ".join("/source/" + s for s in sources[:3]) +
                        " /source/runtime/tests/kernel_dynamic_payload_test.cpp /output/dynamic-access.o " +
                        f"-o /output/{name}/loader-test")
        btf = f" /payloads/{name}/vmlinux.btf" if (payloads / name / "vmlinux.btf").is_file() else ""
        commands.append(f"/output/{name}/loader-test {image}{btf}")
    argv = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={root},target=/source,readonly",
            "--mount", f"type=bind,source={payloads},target=/payloads,readonly",
            "--mount", f"type=bind,source={output},target=/output",
            "ghcr.io/ylarod/ddk-min:android15-6.6-20260828", "sh", "-c", " && ".join(commands)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=result.returncode == 0,
              exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr,
              sourceSha256={name: before[str(root / name)] for name in sources + headers + dynamic_sources},
              payloadSha256={name: before[str(payloads / name / "policy-view.so")] for name in names},
              layoutSha256={name: before[str(payloads / name / "compiled-layout.json")]
                            for name in names if dynamic[name]},
              btfSha256={name: before[str(payloads / name / "vmlinux.btf")]
                         for name in names if (payloads / name / "vmlinux.btf").is_file()},
              dynamicPayload=dynamic,
              inputsUnchanged=before == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
              sanitizers=["ASan", "UBSan"], deviceAccess=False, kernelIoSimulated=True,
              scope="Actual userland loader against six previously-built payloads; no kernel execution or device access")
args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
print(json.dumps(record, indent=2))
raise SystemExit(0 if record["passed"] and record["inputsUnchanged"] else 1)
