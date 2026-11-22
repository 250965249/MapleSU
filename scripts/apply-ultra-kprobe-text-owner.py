#!/usr/bin/env python3
"""Apply the P5 logical text-owner integration to the selected ARM64 kernel.

This changes the real native producer, retaining native pre/simulate/post
dispatch. It does not install a redirect probe or qualify an unpatched target.
The exact replacements deliberately stop on an unsupported source generation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "runtime/ultra/identity/kernel/native-text"


def replace_once(text: str, before: str, after: str, path: Path) -> str:
    if text.count(before) != 1:
        raise ValueError(f"Unsupported native source: {path}: {before[:70]!r}")
    return text.replace(before, after, 1)


def transformed(kernel: Path) -> dict[Path, bytes]:
    result: dict[Path, bytes] = {}
    core = Path("kernel/kprobes.c")
    arm = Path("arch/arm64/kernel/probes/kprobes.c")
    decoder = Path("arch/arm64/kernel/probes/decode-insn.c")
    declaration = Path("arch/arm64/kernel/probes/decode-insn.h")
    for relative in (core, arm, decoder, declaration):
        text = (kernel / relative).read_text(encoding="utf-8")
        if "kprobe_text_owner" in text or "arm_kprobe_decode_opcode" in text:
            raise ValueError(f"Native integration already present: {relative}")
        if relative == core:
            text = replace_once(text, "#include <linux/kprobes.h>",
                "#include <linux/kprobes.h>\n#include <linux/kprobe_text_owner.h>", relative)
            anchor = "\n#ifdef CONFIG_OPTPROBES\n/* NOTE: This is protected by 'kprobe_mutex'. */"
            text = replace_once(text, anchor,
                '\n#include "kprobe_text_owner.inc"\n' + anchor, relative)
            text = replace_once(text,
                "static int prepare_kprobe(struct kprobe *p)\n{\n",
                "static int prepare_kprobe(struct kprobe *p)\n{\n"
                "#ifdef CONFIG_ARM64\n"
                "\t/* A ftrace IP-modify path has no ARM64 B simulation. */\n"
                "\tif (kprobe_ftrace(p) && kprobe_text_owner_lookup(p->addr, NULL, NULL))\n"
                "\t\treturn -EOPNOTSUPP;\n#endif\n", relative)
        elif relative == arm:
            text = replace_once(text, "#include <linux/kprobes.h>",
                "#include <linux/kprobes.h>\n#include <linux/kprobe_text_owner.h>", relative)
            text = replace_once(text, '#include "decode-insn.h"',
                '#include "decode-insn.h"\n#include "simulate-insn.h"', relative)
            text = replace_once(text,
                "post_kprobe_handler(struct kprobe *, struct kprobe_ctlblk *, struct pt_regs *);",
                "post_kprobe_handler(struct kprobe *, struct kprobe_ctlblk *, struct pt_regs *);\n"
                "static void __kprobes\n"
                "post_kprobe_handler_selected(struct kprobe *, struct kprobe_ctlblk *,\n"
                "                             struct pt_regs *, bool);", relative)
            text = replace_once(text,
                "\tunsigned long probe_addr = (unsigned long)p->addr;\n",
                "\tunsigned long probe_addr = (unsigned long)p->addr;\n\tu32 opcode;\n", relative)
            text = replace_once(text, "\t/* copy instruction */\n\tp->opcode = *p->addr;",
                "\t/* Native readers retain the real instruction beneath an owned B. */\n"
                "\tif (!kprobe_text_owner_lookup(p->addr, &opcode, NULL))\n"
                "\t\topcode = le32_to_cpu(*p->addr);\n"
                "\tp->opcode = cpu_to_le32(opcode);", relative)
            text = replace_once(text, "arm_kprobe_decode_insn(p->addr, &p->ainsn)",
                "arm_kprobe_decode_opcode(p->addr, opcode, &p->ainsn)", relative)
            text = replace_once(text,
                "\tu32 insn = le32_to_cpu(p->opcode);\n\n\taarch64_insn_patch_text(&addr, &insn, 1);",
                "\tu32 insn = le32_to_cpu(p->opcode);\n\n"
                "\tkprobe_text_owner_lookup(p->addr, NULL, &insn);\n"
                "\taarch64_insn_patch_text(&addr, &insn, 1);", relative)
            text = replace_once(text, "void __kprobes arch_remove_kprobe(struct kprobe *p)",
                "int arch_kprobe_text_owner_patch(void *address, u32 instruction)\n{\n"
                "\treturn aarch64_insn_patch_text(&address, &instruction, 1);\n}\n\n"
                "void __kprobes arch_remove_kprobe(struct kprobe *p)", relative)
            text = replace_once(text, "\tunsigned long slot;\n", "\tunsigned long slot;\n\tu32 branch;\n", relative)
            text = replace_once(text, "\n\tif (p->ainsn.xol_insn) {\n\t\t/* prepare for single stepping */",
                "\n\t/* The enabled owner's logical instruction is B: native pre,\n"
                "\t * B simulation and post precede the Hook gate. The displaced\n"
                "\t * original executes once in the Hook trampoline. Keep the\n"
                "\t * immutable original ainsn for disable and in-flight XOL; its\n"
                "\t * fall-through restore must not replace this B destination. */\n"
                "\tif (kprobe_text_owner_lookup(p->addr, NULL, &branch)) {\n"
                "\t\tsimulate_b_bl(branch, (long)p->addr, regs);\n"
                "\t\tpost_kprobe_handler_selected(p, kcb, regs, false);\n\t\treturn;\n\t}\n"
                "\n\tif (p->ainsn.xol_insn) {\n\t\t/* prepare for single stepping */", relative)
            text = replace_once(text,
                "post_kprobe_handler(struct kprobe *cur, struct kprobe_ctlblk *kcb, struct pt_regs *regs)\n{",
                "post_kprobe_handler_selected(struct kprobe *cur, struct kprobe_ctlblk *kcb,\n"
                "                             struct pt_regs *regs, bool restore)\n{", relative)
            text = replace_once(text, "\tif (cur->ainsn.xol_restore != 0)\n",
                "\tif (restore && cur->ainsn.xol_restore != 0)\n", relative)
            text = replace_once(text,
                "\nint __kprobes kprobe_fault_handler(struct pt_regs *regs, unsigned int fsr)",
                "\nstatic void __kprobes\n"
                "post_kprobe_handler(struct kprobe *cur, struct kprobe_ctlblk *kcb, struct pt_regs *regs)\n{\n"
                "\tpost_kprobe_handler_selected(cur, kcb, regs, true);\n}\n"
                "\nint __kprobes kprobe_fault_handler(struct pt_regs *regs, unsigned int fsr)", relative)
        elif relative == decoder:
            text = replace_once(text,
                "arm_kprobe_decode_insn(kprobe_opcode_t *addr, struct arch_specific_insn *asi)\n",
                "arm_kprobe_decode_opcode(kprobe_opcode_t *addr, u32 insn, struct arch_specific_insn *asi)\n", relative)
            text = replace_once(text, "\tu32 insn = le32_to_cpu(*addr);\n", "", relative)
            text += ("\n#ifdef CONFIG_KPROBES\nenum probe_insn __kprobes\n"
                "arm_kprobe_decode_insn(kprobe_opcode_t *addr, struct arch_specific_insn *asi)\n{\n"
                "\treturn arm_kprobe_decode_opcode(addr, le32_to_cpu(*addr), asi);\n}\n#endif\n")
        else:
            text = replace_once(text,
                "arm_kprobe_decode_insn(kprobe_opcode_t *addr, struct arch_specific_insn *asi);",
                "arm_kprobe_decode_insn(kprobe_opcode_t *addr, struct arch_specific_insn *asi);\n"
                "enum probe_insn __kprobes\n"
                "arm_kprobe_decode_opcode(kprobe_opcode_t *addr, u32 insn, struct arch_specific_insn *asi);", relative)
        result[relative] = text.encode("utf-8")
    result[Path("include/linux/kprobe_text_owner.h")] = (NATIVE / "kprobe_text_owner.h").read_bytes()
    result[Path("kernel/kprobe_text_owner.inc")] = (NATIVE / "kprobe_text_owner.inc").read_bytes()
    for name in ("legacy_hook_private.h", "request_protocol.h"):
        result[Path("include/linux/maplesu") / name] = (ROOT / "runtime/ultra/authorization" / name).read_bytes()
    return result


def verify_installed(kernel: Path) -> dict:
    """Verify all native producers and the exact private provider generation."""
    requirements = {
        "kernel/kprobes.c": (
            '#include <linux/kprobe_text_owner.h>',
            '#include "kprobe_text_owner.inc"',
            'if (kprobe_ftrace(p) && kprobe_text_owner_lookup(p->addr, NULL, NULL))',
        ),
        "arch/arm64/kernel/probes/kprobes.c": (
            '#include <linux/kprobe_text_owner.h>',
            '#include "simulate-insn.h"',
            'kprobe_text_owner_lookup(p->addr, &opcode, NULL)',
            'p->opcode = cpu_to_le32(opcode);',
            'arm_kprobe_decode_opcode(p->addr, opcode, &p->ainsn)',
            'kprobe_text_owner_lookup(p->addr, NULL, &insn);',
            'int arch_kprobe_text_owner_patch(void *address, u32 instruction)',
            'if (kprobe_text_owner_lookup(p->addr, NULL, &branch)) {\n'
            '\t\tsimulate_b_bl(branch, (long)p->addr, regs);\n'
            '\t\tpost_kprobe_handler_selected(p, kcb, regs, false);\n\t\treturn;',
            'post_kprobe_handler_selected(struct kprobe *cur, struct kprobe_ctlblk *kcb,\n'
            '                             struct pt_regs *regs, bool restore)',
            'if (restore && cur->ainsn.xol_restore != 0)',
            '\tpost_kprobe_handler_selected(cur, kcb, regs, true);',
        ),
        "arch/arm64/kernel/probes/decode-insn.c": (
            'arm_kprobe_decode_opcode(kprobe_opcode_t *addr, u32 insn, struct arch_specific_insn *asi)',
            '#ifdef CONFIG_KPROBES\nenum probe_insn __kprobes\n'
            'arm_kprobe_decode_insn(kprobe_opcode_t *addr, struct arch_specific_insn *asi)\n{\n'
            '\treturn arm_kprobe_decode_opcode(addr, le32_to_cpu(*addr), asi);\n}\n#endif',
        ),
        "arch/arm64/kernel/probes/decode-insn.h": (
            'arm_kprobe_decode_opcode(kprobe_opcode_t *addr, u32 insn, struct arch_specific_insn *asi);',
        ),
    }
    identities = []
    for relative, anchors in requirements.items():
        path = kernel / relative
        data = path.read_bytes()
        source = data.decode("utf-8").replace("\r\n", "\n")
        for anchor in anchors:
            if source.count(anchor) != 1:
                raise ValueError(f"Incomplete native integration: {relative}: {anchor[:70]!r}")
        identities.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest()})
    for relative, local in (
        ("include/linux/kprobe_text_owner.h", "kprobe_text_owner.h"),
        ("kernel/kprobe_text_owner.inc", "kprobe_text_owner.inc"),
    ):
        data = (kernel / relative).read_bytes()
        if data != (NATIVE / local).read_bytes():
            raise ValueError(f"Stale native provider generation: {relative}")
        identities.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest()})
    for name in ("legacy_hook_private.h", "request_protocol.h"):
        relative = "include/linux/maplesu/" + name
        data = (kernel / relative).read_bytes()
        if data != (ROOT / "runtime/ultra/authorization" / name).read_bytes():
            raise ValueError(f"Stale native provider ABI: {relative}")
        identities.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest()})
    return {"complete": True, "kernel": str(kernel.resolve()), "inputs": identities}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path, help="Actual selected kernel source directory")
    parser.add_argument("--output", type=Path, help="Write only affected files to a sparse source overlay")
    parser.add_argument("--check", action="store_true", help="Validate exact supported source; write nothing")
    parser.add_argument("--verify-installed", action="store_true", help="Verify all installed native producers; write nothing")
    args = parser.parse_args()
    kernel = args.kernel.resolve(strict=True)
    if args.verify_installed:
        print(json.dumps(verify_installed(kernel), indent=2))
        return
    output = args.output.resolve() if args.output else kernel
    rows = transformed(kernel)
    if args.check:
        print(f"Supported native producer: {len(rows)} affected files; no writes")
        return
    for relative, data in rows.items():
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if output == kernel and target.exists():
            backup = target.with_name(target.name + ".maplesu-p5-before")
            if backup.exists():
                raise FileExistsError(backup)
            shutil.copyfile(target, backup)
        target.write_bytes(data)
    print(f"Applied native logical text owner: {len(rows)} files in {output}")


if __name__ == "__main__":
    main()
