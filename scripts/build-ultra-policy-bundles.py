"""Embed verified PIC candidates and their compiler-derived layouts for SDK testing.

Input directories are generated build artifacts, not an allowlist of supported
device models. Cross-image candidates additionally carry a compiler-derived
config contract, BTF function ABIs and native cache entry bytes.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from policy_payload_inspect import inspect_payload

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directories", nargs="+", type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
lines = ['// Generated SDK candidate data. Do not edit.', '#include "kernel_payload_loader.h"',
         'namespace maplesu::module_policy { namespace {']
records, bundles, identities = [], [], set()
profile_policy = json.loads((Path(__file__).resolve().parents[1] /
    "runtime/ultra/policy/kernel_compatibility_profiles.json").read_text())
if profile_policy["schemaVersion"] != 1:
    raise ValueError("unknown config profile policy")
for i, directory in enumerate(args.directories):
    metadata = json.loads((directory / "target-identity.json").read_text())
    layout = json.loads((directory / "compiled-layout.json").read_text())
    symbols = {row.split()[-1] for row in (directory / "System.map").read_text().splitlines() if row.split()}
    inspection = inspect_payload(directory / "policy-view.so", symbols)
    image = (directory / "policy-view.so").read_bytes()
    identity = metadata["buildId"]
    if not identity or identity in identities:
        raise ValueError("missing/duplicate target identity")
    identities.add(identity)
    page = metadata["pageSize"]
    if page not in (4096, 16384, 65536):
        raise ValueError("invalid page size")
    cache = metadata["cacheFunction"]
    if cache not in ("caches_clean_inval_pou", "__flush_icache_range"):
        raise ValueError("invalid cache function")
    expected_hooks = ["sel_write_context", "sel_write_access", "selinux_setprocattr", "sel_open_handle_status",
                      "sel_read_handle_status", "sel_mmap_handle_status", "sk_filter_trim_cap", "commit_creds", "__skb_try_recv_datagram"]
    if [h["name"] for h in metadata["hooks"]] != expected_hooks:
        raise ValueError("incomplete/out-of-order hook metadata")
    hooks = [bytes.fromhex(h["first16"]) for h in metadata["hooks"]]
    if any(len(h) != 16 for h in hooks) or not layout:
        raise ValueError("incomplete hook/layout metadata")
    lines.append(f'const uint8_t image_{i}[] = {{')
    for at in range(0, len(image), 32):
        lines.append(','.join(str(b) for b in image[at:at + 32]) + ',')
    lines.append('};')
    lines.append(f'std::vector<LayoutType> layout_{i}() {{ return {{')
    for item in layout:
        fields = ','.join('{%s,%d,%d}' % (json.dumps(f["name"]), f["bit_offset"], f["bit_size"])
                          for f in item["fields"])
        lines.append('{%s,%d,{%s}},' % (json.dumps(item["name"]), item["size"], fields))
    lines.append('}; }')
    hook_values = ','.join('{{' + ','.join(str(b) for b in h) + '}}' for h in hooks)
    scs_function = metadata.get("scsFunction")
    if metadata["dynamicScs"] and scs_function not in ("__pi_scs_patch", "scs_patch"):
        raise ValueError("missing dynamic SCS implementation")
    scs_arguments = metadata.get("scsArguments") if metadata["dynamicScs"] else 2
    if metadata["dynamicScs"] and scs_arguments not in (2, 3):
        raise ValueError("unknown native SCS ABI")
    if not isinstance(metadata.get("alternativesReturnsStatus"), bool):
        raise ValueError("missing native alternatives return ABI")
    compatibility = directory / "kernel-compatibility.json"
    contract_pointer = 'nullptr'
    if compatibility.exists():
        contract = json.loads(compatibility.read_text())
        if contract["schemaVersion"] != 1:
            raise ValueError("unknown compatibility contract")
        for profile in profile_policy["profilesBySeries"].get(contract["kernelSeries"], []):
            variant = {k: v for k, v in profile.items() if k in contract["config"] and contract["config"][k] != v}
            if variant and variant not in contract["equivalentConfigs"]:
                raise ValueError("missing compiler-verified config profile; regenerate compatibility contract: " +
                                 str(directory) + ": " + json.dumps(profile, sort_keys=True))
        for name, digest in contract["inputSha256"].items():
            if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
                raise ValueError("stale compatibility contract: " + name)
        pairs = lambda values: '{' + ','.join('{%s,%s}' % (json.dumps(k), json.dumps(v))
                                            for k, v in values.items()) + '}'
        funcs = '{' + ','.join('{%s,%s}' % (json.dumps(f["name"]), json.dumps(f["signature"]))
                              for f in contract["functions"]) + '}'
        native = '{' + ','.join('{%s,{%s}}' % (json.dumps(f["name"]),
            ','.join('{{' + ','.join(str(b) for b in bytes.fromhex(code)) + '}}'
                     for code in f["runtimeFirst16"])) for f in contract["nativeCode"]) + '}'
        profiles = '{' + ','.join(pairs(profile) for profile in contract["equivalentConfigs"]) + '}'
        declarations = '{' + ','.join(map(json.dumps, contract.get('declarationConfigs', []))) + '}'
        lines.append('const KernelPolicyCompatibility compatibility_%d{%s,%s,%s,%s,%s,%s};' %
                     (i, json.dumps(contract["kernelSeries"]), pairs(contract["config"]), profiles, funcs, native, declarations))
        contract_pointer = '&compatibility_%d' % i
    series = '.'.join(metadata['release'].split('.')[:2])
    bundles.append('{image_%d,%s,%d,%s,%s,{{%s}},layout_%d,%s,%d,%s,%s,%s}' %
                   (i, json.dumps(identity), page, 'true' if metadata["dynamicScs"] else 'false',
                    json.dumps(cache), hook_values, i, json.dumps(scs_function) if scs_function else 'nullptr',
                    scs_arguments, 'true' if metadata["alternativesReturnsStatus"] else 'false', contract_pointer, json.dumps(series)))
    inputs = ["policy-view.so", "compiled-layout.json", "target-identity.json", "System.map", "target.config"]
    records.append(dict(directory=str(directory), identity=identity, payload=inspection,
                        sourceSha256={n: hashlib.sha256((directory / n).read_bytes()).hexdigest() for n in inputs}))
lines.append('const KernelPolicyBundle bundles[] = {' + ',\n'.join(bundles) + '};')
lines.extend(['}', 'std::span<const KernelPolicyBundle> kernel_policy_bundles() { return bundles; }', '}'])
args.output.parent.mkdir(parents=True, exist_ok=True)
source = '\n'.join(lines) + '\n'
if not args.output.exists() or args.output.read_text(encoding='utf-8') != source:
    args.output.write_text(source, encoding='utf-8')
kernel_sources = [p for p in (Path(__file__).resolve().parents[1] / "runtime/ultra/policy/kernel").iterdir() if p.is_file()]
source_root = Path(__file__).resolve().parents[1]
receipt = dict(controlAbi=2, kernelSourceSha256={p.relative_to(source_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in kernel_sources}, generatedAt=datetime.now(timezone.utc).isoformat(), scope=__doc__, bundles=records,
               profilePolicySha256=hashlib.sha256((Path(__file__).resolve().parents[1] /
                   "runtime/ultra/policy/kernel_compatibility_profiles.json").read_bytes()).hexdigest(),
               generatedSourceSha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
               generatorSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               productionSdkChanged=False, deviceAccess=False)
args.output.with_suffix('.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('Generated', len(bundles), 'candidate payload bundles:', args.output)
