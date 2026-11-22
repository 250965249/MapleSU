"""Generate a conservative cross-image contract from the actual Kbuild artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from policy_btf_abi import Btf
from policy_payload_inspect import inspect_payload

# These data objects are consumed through the compiled layout/config contract.
# Functions without BTF are accepted only for the fixed ARM64 cache/string
# ABIs, with exact native/alternative entry bytes checked before allocation.
DATA = {"kasan_flag_enabled", "kmalloc_caches", "memstart_addr", "selinux_blob_sizes", "selinux_state",
        "dynamic_scs_enabled", "sel_handle_status_ops", "mem_alloc_profiling_key", "init_task"}
NATIVE = {"caches_clean_inval_pou", "__flush_icache_range", "memcpy", "memset", "strlen", "strcmp"}
ROOT = Path(__file__).resolve().parents[1]
PROFILE_POLICY = ROOT / "runtime/ultra/policy/kernel_compatibility_profiles.json"


def complete_profiles(directory, record):
    policy = json.loads(PROFILE_POLICY.read_text())
    if policy["schemaVersion"] != 1:
        raise ValueError("Unknown config profile policy")
    for profile in policy["profilesBySeries"].get(record["kernelSeries"], []):
        variant = {k: v for k, v in profile.items() if k in record["config"] and record["config"][k] != v}
        if not variant or variant in record["equivalentConfigs"]:
            continue
        # A declared variant is a requirement to compile and compare, never an
        # instruction to bypass the runtime config/layout/ABI checks.
        with tempfile.TemporaryDirectory(prefix="policy-config-proof-", dir=directory.parent) as temporary:
            work = Path(temporary)
            target_config = work / "target.config"
            target_config.write_text("\n".join(k + "=" + json.dumps(v) if v not in ("y", "m", "n") and
                not re.fullmatch(r"\d+|0x[0-9a-fA-F]+", v) else k + "=" + v
                for k, v in (record["config"] | variant).items()) + "\n")
            subprocess.run([sys.executable, ROOT / "scripts/build-ultra-policy-config-equivalence.py",
                "--reference", directory, "--target-config", target_config, "--output", work / "proof"], check=True)
            proved = work / "proof" / directory.name
            proof = json.loads((proved / "config-equivalence.json").read_text())
            new = next(p for p in proof["profiles"] if p["config"] == variant)
            for name in {new["payload"], new["header"], new["layout"], *new["sourceSha256"]}:
                source, dest = proved / name, directory / name
                if dest.exists() and dest.read_bytes() != source.read_bytes():
                    raise ValueError("Config proof would replace existing input: " + name)
                if not dest.exists():
                    shutil.copyfile(source, dest)
            proof_path = directory / "config-equivalence.json"
            existing = json.loads(proof_path.read_text()) if proof_path.exists() else dict(profiles=[])
            existing["profiles"].append(new)
            proof_path.write_text(json.dumps(existing, indent=2) + "\n")
        generate(directory)
        return True


def config(path):
    result = {}
    for line in path.read_text().splitlines():
        if line.startswith("CONFIG_"):
            name, value = line.split("=", 1)
            result[name] = json.loads(value) if value.startswith('"') else value
    return result


def generate(directory, complete=True):
    metadata = json.loads((directory / "target-identity.json").read_text())
    symbols = {line.split()[-1] for line in (directory / "System.map").read_text().splitlines() if line.split()}
    image = inspect_payload(directory / "policy-view.so", symbols)
    btf = Btf((directory / "vmlinux.btf").read_bytes())
    required = set(image["imports"] + metadata["requiredLoaderSymbols"])
    if metadata["dynamicScs"]:
        required.update([metadata["scsFunction"], "static_key_count", "dynamic_scs_enabled"])
    functions, native = [], []
    for name in sorted(required - DATA):
        if name in btf.functions:
            functions.append(dict(name=name, signature=btf.function(name)))
        elif metadata["dynamicScs"] and name == metadata.get("scsFunction"):
            # The early ARM64 SCS patcher may be absent from BTF. Its argument
            # count is captured from the native header; use captured image
            # bytes as the additional runtime guard, never a guessed prototype.
            assert metadata["scsArguments"] in (2, 3)
            replay = metadata["nativeScsReplay"]
            code = (directory / "native-scs.bin").read_bytes()
            assert hashlib.sha256(code).hexdigest() == replay["sha256"]
            at = replay["entry"] - replay["base"]
            assert 0 <= at <= len(code) - 16
            native.append(dict(name=name, runtimeFirst16=[code[at:at + 16].hex()]))
        elif name in NATIVE:
            entry = next(item for item in metadata["nativeCodeAbi"] if item["name"] == name)
            assert entry["runtimeFirst16"] and all(len(bytes.fromhex(code)) == 16 for code in entry["runtimeFirst16"])
            native.append(entry)
        else:
            raise ValueError("Unverified imported function ABI: " + name)
    dependencies, commands = set(), []
    for source in (directory / "maplesu_policy_view.mod").read_text().splitlines():
        path = directory / ("." + Path(source).name + ".cmd")
        command = path.read_text()
        commands.append(path)
        dependencies.update("CONFIG_" + name for name in re.findall(
            r"\$\(wildcard include/config/([A-Z0-9_]+)\)", command))
    if not dependencies or not functions:
        raise ValueError("Empty compile/ABI contract")
    reference = config(directory / "target.config")
    equivalence = directory / "config-equivalence.json"
    profiles = []
    proof_inputs = []
    if equivalence.exists():
        proof_inputs.append(equivalence)
        proof = json.loads(equivalence.read_text())
        for profile in proof["profiles"]:
            variant = directory / profile["payload"]
            if variant.read_bytes() != (directory / "policy-view.so").read_bytes():
                raise ValueError("Config equivalence payload differs")
            override = profile["config"]
            if not override or not set(override) <= dependencies:
                raise ValueError("Config equivalence fields")
            header = directory / profile["header"]
            expected = "".join("#undef " + key + "\n" +
                ("" if value == "n" else "#define " + key + " " + ("1" if value == "y" else value) + "\n")
                for key, value in sorted(override.items()))
            if header.read_text() != expected:
                raise ValueError("Config equivalence header differs")
            proof_inputs.extend([variant, header])
            if "layout" in profile:
                layout = directory / profile["layout"]
                if json.loads(layout.read_text()) != json.loads((directory / "compiled-layout.json").read_text()):
                    raise ValueError("Config equivalence layout differs")
                proof_inputs.append(layout)
            for source, digest in profile["sourceSha256"].items():
                if hashlib.sha256((directory / source).read_bytes()).hexdigest() != digest:
                    raise ValueError("Config equivalence input changed")
            profiles.append(override)
    files = ["policy-view.so", "vmlinux.btf", "target.config", "target-identity.json", "compiled-layout.json"]
    declarations = directory / 'config-declarations.json'
    declaration_config = []
    if declarations.exists():
        proof = json.loads(declarations.read_text())
        generator = ROOT / 'scripts/policy_config_declarations.py'
        required_inputs = {p.name for p in commands} | {'policy-view.so', 'compiled-layout.json', 'target.config'}
        if (proof['schemaVersion'] != 1 or not proof['sourceSha256'] or
            proof.get('generatorSha256') != hashlib.sha256(generator.read_bytes()).hexdigest() or
            set(proof['inputSha256']) != required_inputs):
            raise ValueError('Invalid config declaration proof')
        for name, digest in proof['inputSha256'].items():
            if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Stale config declaration proof: ' + name)
        declaration_config = proof['configs']
        if not set(declaration_config) <= dependencies:
            raise ValueError('Unconsumed config declaration proof')
        if len(set(declaration_config)) != len(declaration_config):
            raise ValueError('Duplicate config declaration proof')
        proof_inputs.append(declarations)
    record = dict(schemaVersion=1, kernelSeries=".".join(metadata["release"].split(".")[:2]),
                  config={name: reference.get(name, "n") for name in sorted(dependencies)},
                  equivalentConfigs=profiles, functions=functions, nativeCode=native,
                  declarationConfigs=declaration_config,
                  dataImports=sorted(required & DATA),
                  inputSha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in [*(directory / name for name in files), *commands, *proof_inputs]})
    (directory / "kernel-compatibility.json").write_text(json.dumps(record, indent=2) + "\n")
    if complete and complete_profiles(directory, record):
        return
    print(json.dumps(dict(kernelSeries=record["kernelSeries"], configFields=len(dependencies),
                         functionAbis=len(functions), nativeCodeEntries=len(native), equivalentConfigs=len(profiles))))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--no-complete-profiles", action="store_true",
                        help="Validate one isolated compiler proof without recursively building other profiles")
    args = parser.parse_args()
    generate(args.directory.resolve(), complete=not args.no_complete_profiles)
