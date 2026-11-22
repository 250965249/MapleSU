"""Generate core-member recovery batches from the frozen archive census.

Reads  sdk/notes/recon/ARCHIVE-CENSUS.json  (258 rows, frozen snapshot order)
Skips members already owned by W2 work packages.
Writes sdk/notes/work/queue/CORE-QUEUE.json and batch-NN.txt files.

Pure stdlib; run with `py`.
"""
from __future__ import annotations

import json
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
CENSUS = SDK / "notes" / "recon" / "ARCHIVE-CENSUS.json"
OUT = SDK / "notes" / "work" / "queue"

# Owned by other work packages (do not assign twice).
W2_OWNED = {
    "module_base_kernel_request.o",       # M023
    "module_base_kernel_mem.o",           # PATCH (R5)
    "module_base_kernel_func_hook.o",     # HOOK (R1-R4)
    "module_base_cpu_icache_sync.o",      # already source-complete
    "maplesu_unsafe_su_install.o",         # PROGRAMS
    "maplesu_unsafe_resetprop_install.o",  # PROGRAMS
    "maplesu_unsafe_webui_loader_install.o",  # PROGRAMS
    "maplesu_autorun_bootstrap_install.o",    # PROGRAMS
}

GROUP_OF_PREFIX = {
    "cred": "kernel_offsets", "task_struct": "kernel_offsets", "mm_struct": "kernel_offsets",
    "vm_area_struct": "kernel_offsets", "dentry": "kernel_offsets", "fdtable": "kernel_offsets",
    "inode": "kernel_offsets", "file": "kernel_offsets", "file_struct": "kernel_offsets",
    "proc_ops": "kernel_offsets", "file_operations": "kernel_offsets", "inode_operations": "kernel_offsets",
    "miscdevice": "kernel_offsets", "super_block": "kernel_offsets", "renamedata": "kernel_offsets",
    "block_device": "kernel_offsets", "gendisk": "kernel_offsets", "address_space": "kernel_offsets",
    "seq_file": "kernel_offsets", "seq_operations": "kernel_offsets", "pte_fn_t": "kernel_offsets",
    "page": "kernel_offsets", "kstat": "kernel_offsets",
}

# Prefix groups kept together so one agent owns one coherent area.
BUCKETS = ["module_base", "patch", "maplesu_assets", "module_other", "misc"]


def bucket_of(name: str) -> str:
    stem = name[:-2] if name.endswith(".o") else name
    if stem.startswith("module_base_"):
        return "module_base"
    if stem.startswith("module_") or stem == "module_root":
        return "module_other"
    if stem.startswith("patch"):
        return "patch"
    if stem.startswith("maplesu_assets"):
        return "maplesu_assets"
    return "misc"


def main() -> int:
    data = json.loads(CENSUS.read_text(encoding="utf-8"))
    rows = data["members"]

    # kernel_offsets = the leading contiguous run of offset members (ordinals 1..26).
    offsets = []
    for row in rows:
        stem = row["name"][:-2]
        if GROUP_OF_PREFIX.get(stem) == "kernel_offsets":
            offsets.append(row)
        else:
            break

    offset_names = {r["name"] for r in offsets}
    rest = [
        r for r in rows
        if r["group"] == "core"
        and r["name"] not in offset_names
        and r["name"] not in W2_OWNED
    ]

    OUT.mkdir(parents=True, exist_ok=True)
    by_bucket: dict[str, list[dict]] = {b: [] for b in BUCKETS}
    for row in rest:
        by_bucket[bucket_of(row["name"])].append(row)

    # 8 batches, greedy longest-processing-time first for byte balance.
    n_batches = 8
    batches: list[list[dict]] = [[] for _ in range(n_batches)]
    load = [0] * n_batches
    pool: list[tuple[str, dict]] = []
    for b in BUCKETS:
        for row in sorted(by_bucket[b], key=lambda r: -r["bytes"]):
            pool.append((b, row))
    # Round-robin by bucket so each batch gets a mix, largest-first.
    for b in BUCKETS:
        rows_sorted = sorted(by_bucket[b], key=lambda r: -r["bytes"])
        for row in rows_sorted:
            i = min(range(n_batches), key=lambda k: load[k])
            batches[i].append(row)
            load[i] += row["bytes"]

    manifest = {"total": len(rest), "batches": []}
    for i, batch in enumerate(batches, start=1):
        # keep archive order inside the batch for readability
        batch.sort(key=lambda r: r["idx"])
        tag = f"batch-{i:02d}"
        lines = [
            "# idx(0-based) name layout bytes ir_match ir_path",
            "# NOTE: idx is the 0-based llvm-ar position (func_hook=29, cred.o=0).",
            "# Canonical metadata file name: manifest/<idx:04d>_<full member name incl .o>.json",
        ]
        for row in batch:
            ir = row.get("ir_path") or "-"
            lines.append(
                f"{row['idx']}\t{row['name']}\t{row['kind'].replace('llvm-', '')}\t"
                f"{row['bytes']}\t{row['ir_match']}\t{ir}"
            )
        (OUT / f"{tag}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        manifest["batches"].append({
            "tag": tag,
            "pkg": f"CORE-{i:02d}",
            "members": len(batch),
            "bytes": load[i - 1],
            "names": [r["name"] for r in batch],
        })

    manifest["offsets"] = [r["name"] for r in offsets]
    manifest["offsets_count"] = len(offsets)
    (OUT / "CORE-QUEUE.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"offsets={len(offsets)} rest={len(rest)} batches={n_batches}")
    for entry in manifest["batches"]:
        print(f"  {entry['tag']}: {entry['members']} members, {entry['bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
