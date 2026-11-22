"""Compare frozen C++ results and root-loader Python on identical real BTF bytes."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def module_at(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected_source(path, names, namespace):
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names:
            nodes.append(node)
        if isinstance(node, ast.Assign):
            identifiers = {n.id for target in node.targets for n in ast.walk(target)
                           if isinstance(n, ast.Name)}
            if identifiers & names:
                nodes.append(node)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)


def anonymous_cases(raw, btf):
    fields = []
    for owner in btf.types[1:]:
        if owner[1] == 4 and btf.name(owner[0]) == "task_struct":
            at = next(owner[5] + i * 12 for i in range(owner[2])
                      if btf.name(btf.u32(owner[5] + i * 12)) == "seccomp")
            fields.append(at)
    type_id = btf.u32(fields[0] + 4)
    while btf.types[type_id][1] in (8, 9, 10, 11, 18):
        type_id = btf.types[type_id][3]
    owner = btf.types[type_id]
    mode = next(owner[5] + i * 12 for i in range(owner[2])
                if btf.name(btf.u32(owner[5] + i * 12)) == "mode")
    mode_name, scalar = btf.u32(mode), btf.u32(mode + 4)
    first = len(btf.types)
    header, offset, size, strings, _ = struct.unpack_from("<IIIII", raw, 4)

    def append(extra, updates):
        data = bytearray(raw)
        for at, value in updates:
            struct.pack_into("<I", data, at, value)
        data[header + offset + size:header + offset + size] = extra
        struct.pack_into("<I", data, 12, size + len(extra))
        struct.pack_into("<I", data, 16, strings + len(extra))
        return data

    inner = struct.pack("<IIIIII", 0, 4 << 24 | 1, owner[3], mode_name, scalar, 8)
    outer = struct.pack("<IIIIII", 0, 4 << 24 | 1, owner[3], 0, first, 0)
    yield "seccomp-mode-anonymous-owner", append(inner + outer,
        [(at + 4, first + 1) for at in fields])
    wrapper = struct.pack("<IIIIII", 0, 4 << 24 | 1, owner[3], btf.u32(fields[0]), type_id, 0)
    yield "seccomp-anonymous-task-owner", append(wrapper,
        [(position, value) for at in fields for position, value in ((at, 0), (at + 4, first))])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payloads", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    names = ["jailbreak-providers/root-loader/boot_sdk_build.py",
             "jailbreak-providers/root-loader/build_root_module.py",
             "scripts/policy_btf_abi.py", "scripts/tests/test-boot-sdk-dynamic.py",
             "scripts/tests/test-boot-sdk-seccomp-common.py"]
    before = {}
    for name in names:
        data = (ROOT / name).read_bytes()
        before[name] = digest(data)
        target = output / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    frozen = output / "source"
    sdk = module_at("frozen_boot_sdk_build", frozen / names[0])
    btf_ns = dict(struct=struct, Path=Path)
    selected_source(frozen / names[1], {"Btf", "SymbolTable", "GateFailure", "BTF_MAGIC",
        "BTF_STRUCT", "BTF_UNION", "BTF_SKIP"}, btf_ns)
    helper = module_at("frozen_policy_btf", frozen / names[2])
    fixture_ns = dict(struct=struct)
    selected_source(frozen / names[3], {"seccomp_cases"}, fixture_ns)
    previous = json.loads((args.previous / "verification.json").read_text())
    assert previous["passed"] and previous["sourcesUnchanged"]
    previous_rows = {(row["kernel"], row["case"]): row for row in previous["results"]}
    receipt = json.loads((args.previous.parent / "RECEIPT.json").read_text())
    assert digest((args.previous / "probe").read_bytes()) == receipt["artifacts"]["green-r3/probe"]["sha256"]
    run = ["docker", "run", "--rm", "-i", "--pull", "never", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount",
        f"type=bind,source={args.previous.resolve()},target=/previous,readonly", "--mount",
        f"type=bind,source={output},target=/output,readonly", receipt["dockerImage"],
        "sh", "-c", 'while IFS= read -r path; do /previous/probe "$path"; code=$?; '
        'printf "__MAPLESU_EXIT__:%s\\n" "$code"; done']
    worker = subprocess.Popen(run, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rows, inputs = [], {}
    active = output / "active.btf"
    symbols_path = output / "symbols.tsv"
    try:
        for kernel, environment in [("android14-6.1", 0), ("android15-6.6", 1),
                                    ("android16-6.12", 1), ("android17-6.18", 0)]:
            source = (args.payloads / kernel / "vmlinux.btf").resolve()
            raw = source.read_bytes()
            inputs[kernel] = dict(path=str(source), bytes=len(raw), sha256=digest(raw))
            btf = helper.Btf(raw)
            known, _ = fixture_ns["seccomp_cases"](raw, btf, environment)
            fixtures = [("reference", raw)] + [(name, data) for name, data, _, _ in known]
            fixtures += list(anonymous_cases(raw, btf))
            function_names = set(btf.functions)
            # Address presence is a fixture: BTF files carry no kallsyms addresses.
            fixture_names = (set(sdk.SYMBOLS) - {"__start_notes", "__stop_notes"}) | {
                "caches_clean_inval_pou"}
            candidates = set(sdk.ENV_SYMBOLS) | {"module_memfree", "execmem_free", "vmalloc",
                "vmalloc_noprof", "__vmalloc_node_range", "__vmalloc_node_range_noprof"}
            fixture_names |= candidates & function_names
            symbols_path.write_text("0\tT\t_text\n" + "".join(
                f"{4096 + i * 4}\tT\t{name}\n" for i, name in enumerate(sorted(fixture_names - {"_text"}))),
                encoding="utf-8")
            symbols = btf_ns["SymbolTable"](symbols_path)
            for case, data in fixtures:
                sha = digest(data)
                prior = previous_rows.get((kernel, case))
                if prior:
                    assert prior["btfSha256"] == sha
                    cpp = dict(exitCode=prior["exitCode"], stdout=prior["stdout"], source="frozen-green-r3")
                else:
                    active.write_bytes(data)
                    worker.stdin.write(b"/output/active.btf\n")
                    worker.stdin.flush()
                    lines = []
                    while True:
                        line = worker.stdout.readline().decode("utf-8", errors="replace")
                        if not line:
                            raise RuntimeError("Frozen probe exited before result")
                        if line.startswith("__MAPLESU_EXIT__:"):
                            cpp = dict(exitCode=int(line.split(":", 1)[1]), stdout="".join(lines).strip(),
                                       source="frozen-probe-new-anonymous-input")
                            break
                        lines.append(line)
                    active.unlink()
                fields = dict(item.split("=", 1) for item in cpp["stdout"].split() if "=" in item)
                parsed = btf_ns["Btf"](bytes(data))
                try:
                    facts = sdk.environment_facts(parsed, symbols)
                    py_error = None
                except Exception as error:
                    facts, py_error = {}, type(error).__name__ + ": " + str(error)
                compiled = sdk.derive(SimpleNamespace(Btf=btf_ns["Btf"]), bytes(data), symbols,
                    parsed.struct("kprobe")["size"], {"defines": {
                        "MSU_PH_PAGE_BYTES": 4096, "MSU_PH_REGS_PC": 256}})
                cpp_env, cpp_mode = int(fields.get("environment", 0)), int(fields.get("seccomp", 0))
                py_env, py_mode = facts.get("MSU_BS_ENVIRONMENT", 0), facts.get("MSU_BS_SECCOMP_OFFSET", 0)
                rows.append(dict(kernel=kernel, case=case, btfSha256=sha, cpp=cpp,
                    cppBaseQualified=cpp["exitCode"] == 0, cppEnvironment=cpp_env, cppSeccomp=cpp_mode,
                    pythonParsed=True, pythonEnvironment=py_env, pythonSeccomp=py_mode, pythonError=py_error,
                    pythonCompileFacts={"defines": compiled.get("defines"),
                        "capabilities": compiled.get("capabilities"), "environmentAbi": compiled.get("environmentAbi")},
                    sameEnvironment=cpp_env == py_env, samePublishedSeccomp=cpp_mode == py_mode))
                (output / "progress.json").write_text(json.dumps(rows, indent=2) + "\n")
        worker.stdin.close()
        assert worker.wait(timeout=30) == 0
    finally:
        if worker.poll() is None:
            worker.terminate()
        active.unlink(missing_ok=True)
    source_now = {name: digest((ROOT / name).read_bytes()) for name in names}
    report = dict(at=datetime.now(timezone.utc).isoformat(), sourceSha256=before,
        sourcesUnchanged=before == source_now, currentSourceSha256=source_now,
        cppPreviousSourceSha256=previous["sourceSha256"], cppProbeSha256=digest((args.previous / "probe").read_bytes()),
        cppPreviousVerificationSha256=digest((args.previous / "verification.json").read_bytes()),
        cppCommand=run, inputs=inputs, results=rows,
        differences=[row for row in rows if not row["sameEnvironment"] or not row["samePublishedSeccomp"]],
        symbolScope="Synthetic presence/addresses fixture; FUNC candidates from each original BTF; no image/ASLR/device proof",
        baseScope="C++ exit0 is actual BTF base qualification; Python derive emits compile facts and defers dynamic base qualification to CONFIGURE",
        deviceAccess=False, sdkOrApkBuild=False)
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(cases=len(rows), differences=len(report["differences"]),
                         sourcesUnchanged=report["sourcesUnchanged"])))


if __name__ == "__main__":
    main()
