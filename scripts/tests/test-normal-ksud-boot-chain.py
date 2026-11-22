"""Check the retained native boot chain without emulating Android init or kernel hooks."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = {}
    records = {}
    for tree in ("upstream", "applied"):
        base = ROOT / "third_party/kernelsu" / tree
        paths = ["kernel/runtime/ksud_integration.c", "kernel/core/init.c",
                 "userspace/ksuinit/src/main.rs", "userspace/ksuinit/src/init.rs",
                 "userspace/ksud/src/init_event.rs", "userspace/ksud/src/late_load.rs",
                 "kernel/runtime/ksud.h", "kernel/selinux/selinux.h"]
        text = {}
        for path in paths:
            file = base / path
            content = file.read_bytes()
            sources[file.relative_to(ROOT).as_posix()] = hashlib.sha256(content).hexdigest()
            text[path] = content.decode("utf-8")
        integration = text[paths[0]]
        declaration = integration.split("static const char KERNEL_SU_RC[] =", 1)[1].split("// clang-format on", 1)[0]
        declaration = re.sub(r"//[^\n]*", "", declaration)
        macros = {}
        for name in ("KERNEL_SU_DOMAIN", "KSUD_PATH"):
            definitions = "\n".join(text.values())
            value = re.search(r"(?m)^#define " + name + r'\s+("[^"\n]+")', definitions)
            assert value is not None, name
            macros[name] = ast.literal_eval(value.group(1))
        # Decode the actual C literals and the two retained header macros.
        tokens = re.findall(r'"(?:\\.|[^"\\])*"|KERNEL_SU_DOMAIN|KSUD_PATH', declaration)
        rc = "".join(ast.literal_eval(token) if token.startswith('"') else
                     macros[token] for token in tokens)
        events = {}
        event = None
        for line in rc.splitlines():
            if line.startswith("on "):
                event = line[3:]
            elif "exec " in line:
                events[event] = line.strip()
        assert events == {
            "post-fs-data": "exec u:r:ksu:s0 root -- /data/adb/ksud post-fs-data",
            "nonencrypted": "exec u:r:ksu:s0 root -- /data/adb/ksud services",
            "property:vold.decrypt=trigger_restart_framework": "exec u:r:ksu:s0 root -- /data/adb/ksud services",
            "property:sys.boot_completed=1": "exec u:r:ksu:s0 root -- /data/adb/ksud boot-completed",
        }
        init = text["userspace/ksuinit/src/init.rs"]
        normal_init = init.split("pub fn init() -> Result<()> {", 1)[1].split("\nfn ", 1)[0]
        assert 'load_module_from_path("/kernelsu.ko")' in normal_init
        assert 'execve(cstr!("/init"), argv, envp)' in text["userspace/ksuinit/src/main.rs"]
        assert "ksu_late_loaded = (current->pid != 1)" in text["kernel/core/init.c"]
        assert "ksu_ksud_init();" in text["kernel/core/init.c"]
        assert "ksu_syscall_table_hook(__NR_read" in integration
        assert "ksu_syscall_table_hook(__NR_fstat" in integration
        assert 'strcmp(dpath, "/system/etc/init/hw/init.rc")' in integration
        lifecycle = text["userspace/ksud/src/init_event.rs"]
        late = text["userspace/ksud/src/late_load.rs"]
        records[tree] = {"initEvents": events,
            "lifecycleSha256": hashlib.sha256(lifecycle.encode()).hexdigest(),
            "lateLoadStages": re.findall(r'init_event::run_stage\("([^"]+)"', late),
            "lifecycleStages": re.findall(r'run_stage\("([^"]+)"', lifecycle)}
    assert records["upstream"] == records["applied"]
    result = {"passed": True, "scope": "Source-level native boot chain and event identity; no kernel/init execution",
        "deviceAccess": False, "managerProcessRequiredByEventCommands": False,
        "sourceSha256": sources, "chains": records,
        "preconditions": ["PID 1 successfully loads the matching KernelSU LKM",
            "/data/adb/ksud is deployed before init events fire", "matching userspace/kernel UAPI",
            "safe mode and Magisk detection can skip module stages",
            "partition mounts require an enabled metamodule mount script"],
        "lateLoad": "Late-load runs its own stages in the current boot; a full reboot needs a persistent installed LKM"}
    (out / "verification.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("PASS: native init events and daemon module stages match the pinned KernelSU source")


if __name__ == "__main__":
    main()
