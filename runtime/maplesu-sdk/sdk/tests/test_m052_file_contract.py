#!/usr/bin/env python3
"""Replay the current m052 C++ file contract in an isolated Linux container.

This runs real installer/publisher bodies. Root, key and version are fixture
inputs; security.selinux is mapped to a user xattr. It does not execute Android.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile

DEFAULT_SDK = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).resolve().parent / "fixtures/m052"
IMAGE = "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"
WRAPS = ["fopen", "fwrite", "fflush", "fclose", "openat", "write", "fsync", "close",
         "renameat", "setxattr", "fsetxattr", "maplesu_publish_executable"]


def receipt(path):
    return dict(path=str(path), bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def write_headers(directory, blob):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "payload.bin").write_bytes(blob)
    (directory / "autorun_bootstrap_file_data.h").write_text(
        "#pragma once\nnamespace maplesu::sdk { static const unsigned char autorun_bootstrap_file_data[] = {\n" +
        ",".join("0x%02x" % value for value in blob) + "}; }\n", encoding="utf-8")
    (directory / "payload_assets.generated.h").write_text(
        '#pragma once\n#include "autorun_bootstrap_file_data.h"\n', encoding="utf-8")
    (directory / "payload_sizes.generated.h").write_text(
        "#pragma once\nnamespace maplesu::sdk { constexpr unsigned long kAutorunBootstrapPayloadSize = %d; }\n" % len(blob),
        encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, default=DEFAULT_SDK)
    parser.add_argument("--source-dir", type=Path, help="review override; default: SDK/src/maplesu_assets")
    parser.add_argument("--public-include", type=Path, help="default: SDK/../include")
    parser.add_argument("--out", type=Path, help="empty directory; default: a new system temp directory")
    parser.add_argument("--image", default=IMAGE, help="locally installed compiler image; never pulled")
    args = parser.parse_args()
    sdk = args.sdk.resolve()
    source = (args.source_dir or sdk / "src/maplesu_assets").resolve()
    public = (args.public_include or sdk.parent / "include").resolve()
    root = args.out.resolve() if args.out else Path(tempfile.mkdtemp(prefix="maplesu-m052-"))
    if root.exists() and any(root.iterdir()):
        parser.error("--out must be empty to retain an unambiguous run receipt")
    root.mkdir(parents=True, exist_ok=True)
    selected = []

    def copy(origin, relative):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)
        selected.append(receipt(origin))

    for name in ["maplesu_autorun_bootstrap_install.cpp", "maplesu_install_core.h",
                 "maplesu_install_env.h", "maplesu_install_platform.h", "maplesu_payload_assets.h",
                 "installer_ir/executable_publish.cpp", "installer_ir/executable_publish.h"]:
        copy(source / name, Path("current/src") / name)
    for name in ["module_err_def.h", "maplesu_sdk/maplesu_installer.h"]:
        copy(public / name, Path("current/include") / name)
    copy(sdk / "include/private_maple_runtime.h", "current/include/private_maple_runtime.h")
    copy(FIXTURE / "kernel_module_kit_umbrella.h", "current/host-stub/kernel_module_kit_umbrella.h")
    copy(FIXTURE / "m052_file_contract.cpp", "tests/m052_file_contract.cpp")
    helper = sdk / "assets/autorun_bootstrap.bin"
    selected.append(receipt(helper))
    blob = helper.read_bytes()
    token = (b"5d31494d2e18e3fdef2afaf740b0febc19229cb292f57ebc3bc1c96c6d70b709"
             b"8d2dc1f356b733e8c999e6ac85bdca24c8c74f03ae7d5b2a402e96804576e925" + b"\0" * 3968)
    offset = blob.index(token)
    variants = {"reference": blob, "short": b"\0"}
    for name in ["tail", "duplicate"]:
        value = bytearray(blob)
        if name == "tail":
            value[offset:offset + len(token)] = b"\0" * len(token)
        value[-len(token):] = token
        variants[name] = bytes(value)
    for name, value in variants.items():
        write_headers(root / "assets" / name, value)

    cases = []

    def case(name, operation="install", fault="none", length=48, rounds=1,
             status=0, unchanged=False, installed=False, reset=False,
             writes=None, variant="reference", payload=False):
        cases.append(dict(name=name, operation=operation, fault=fault, length=length,
                          rounds=rounds, status=status, unchanged=unchanged,
                          installed=installed, reset=reset, writes=writes, variant=variant,
                          payload=payload))

    case("install-success-nine-seeds", installed=True)
    case("install-repeat-nine-seeds", rounds=2, installed=True)
    case("key-min16", length=16, installed=True)
    case("key-max1023", length=1023, installed=True)
    case("helper-path-empty-and-owned", operation="path", rounds=2, unchanged=True)
    for operation in ["safe", "duplicate"]:
        case(operation + "-direct", operation=operation, reset=True)
        case(operation + "-root-error", operation=operation, fault="root", status=-12345, unchanged=True)
        case(operation + "-close-error", operation=operation, fault="flag-close", status=-19935)
    case("publish-outer-nine-preserved", fault="publish-outer", status=-19930, unchanged=True)
    case("publisher-short-write-retries", fault="publish-short", installed=True, writes=2)
    case("publisher-eintr-retries", fault="publish-eintr", installed=True, writes=2)
    for fault in ["publish-write", "publish-fsync-file", "publish-close", "publish-rename"]:
        case(fault, fault=fault, status=-19933, unchanged=True)
    case("publish-fsync-dir-after-rename", fault="publish-fsync-dir", status=-19933, payload=True)
    for fault in ["stream-short", "stream-eintr", "stream-flush", "stream-close"]:
        case(fault, fault=fault, status=-19933)
    case("empty-file-close-error", fault="empty-close", status=-19935)
    case("token-last-legal-position", variant="tail", installed=True)
    case("token-all-occurrences", variant="duplicate", installed=True)
    case("payload-shorter-than-token", variant="short", status=-19906, unchanged=True)

    output = root / "outputs"
    output.mkdir()
    commands = ["set -eu", "cd /case", "C=/opt/ddk/clang/clang-r510928",
                "export LD_LIBRARY_PATH=$C/lib/x86_64-unknown-linux-gnu"]
    wraps = " ".join("-Wl,--wrap=" + name for name in WRAPS)
    for variant in variants:
        commands.append(
            f"$C/bin/clang++ -stdlib=libc++ -std=c++20 -Oz -fno-builtin-fwrite "
            f"-fno-builtin-fflush -fno-builtin-fclose -ffunction-sections -fdata-sections "
            f"-Icurrent/host-stub -Icurrent/include -Icurrent/src -Iassets/{variant} "
            f"-DMAPLESU_PAYLOAD_ASSETS=1 -Wl,--gc-sections {wraps} tests/m052_file_contract.cpp "
            f"current/src/maplesu_autorun_bootstrap_install.cpp current/src/installer_ir/executable_publish.cpp "
            f"-o outputs/current-{variant}")
    for item in cases:
        commands.append(f"./outputs/current-{item['variant']} {item['operation']} {item['fault']} "
                        f"{item['length']} {item['rounds']} outputs/results/{item['name']} "
                        f"assets/{item['variant']}/payload.bin")
    (output / "run.sh").write_text("\n".join(commands) + "\n", encoding="utf-8", newline="\n")
    run = subprocess.run(["docker", "run", "--rm", "--pull", "never", "--network", "none",
                          "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                          "--mount", f"type=bind,source={root},target=/case",
                          "--entrypoint", "sh", args.image, "/case/outputs/run.sh"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    (output / "build-run.log").write_text(run.stdout + run.stderr, encoding="utf-8")
    rows = []
    if run.returncode == 0:
        for item in cases:
            path = output / "results" / item["name"] / "state.tsv"
            data = {}
            for line in path.read_text().splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2 and parts[0] not in ("trace", "file"):
                    data[parts[0]] = parts[1]
            checks = {"status": int(data["status"]) == item["status"],
                      "earlier_rounds_success": data["earlier_rounds_success"] == "1"}
            if item["fault"] != "none":
                checks["fault_actually_consumed"] = data["fault_hits"] == "1"
            for option, field in [("unchanged", "all_seed_files_unchanged"),
                                  ("installed", "install_files_match"), ("reset", "reset_files_match"),
                                  ("payload", "helper_payload_matches")]:
                if item[option]:
                    checks[field] = data[field] == "1"
            if item["writes"]:
                checks["write_retried"] = int(data["write_calls"]) >= item["writes"]
            rows.append(dict(case=item, actual=data, checks=checks, passed=all(checks.values()),
                             state=receipt(path)))
    image = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", args.image],
                           capture_output=True, text=True, check=True).stdout.strip()
    report = dict(schema="maplesu-m052-current-contract/1", image=args.image, image_id=image,
                  process_exit=run.returncode, device_acceptance=False, android_execution=False,
                  source_override=args.source_dir is not None, selected_inputs=selected,
                  runner=receipt(Path(__file__)), reference_helper=receipt(helper),
                  synthetic_payloads=[dict(variant=name, **receipt(root / "assets" / name / "payload.bin"))
                                      for name in variants if name != "reference"],
                  cases=rows, expected_cases=len(cases), passed=sum(row["passed"] for row in rows),
                  failed=sum(not row["passed"] for row in rows))
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"passed={report['passed']}/{len(cases)} failed={report['failed']} process_exit={run.returncode}")
    print(output / "report.json")
    if run.returncode:
        print((run.stdout + run.stderr)[-6000:])
    return int(run.returncode != 0 or len(rows) != len(cases) or report["failed"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
