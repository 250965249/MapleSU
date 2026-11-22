"""Generate a per-release IR spec from a kernel image + its kallsyms dump.

This is W4 of the integration manual: `kernel image -> kallsyms -> locate
candidates -> build the patch table -> verify by reading it back`. It is
rule-driven, not offset-driven: the sites are found *inside* the named functions
by instruction pattern, so a new release needs a new image, not a new hand-typed
offset table.

Rules, all taken from manual section 4.4 (the 6.6.89 table) and written here as
patterns that the same functions exhibit on other builds:

  P1   inside avc_denied: the single `mov w0, #-0xd` that both the AVC_STRICT and
       the enforcing path converge on -> `mov w0, #0`.
  P3   __sys_setresuid entry: the first `paciasp` -> `b <cave>` (branch before the
       prologue, so the stub owns the LR).
  P3c  the stub itself, placed in a run of zero bytes at the tail of .text:
       `w0 == 0xDEAD` -> prepare_kernel_cred(&init_task) -> commit_creds, else
       restore LR, replay `paciasp`, continue at entry+4.

Two invariants are enforced before a spec is written:
  * every block's original bytes are read back from the image and must match what
    the rule predicted -- otherwise nothing is emitted (the module refuses
    mismatches too, so a bad spec must not exist in the first place);
  * `--expect-ref` compares the produced blocks with a reference spec file (the
    manual's published comboB table) and fails if a single byte differs. That is
    how the generator proves it reproduces the documented table instead of
    inventing its own.

Usage:
  build_ir_spec.py --image <Image> --symbols <symbols.tsv> --out <dir>
                   [--expect-ref <spec>] [--combo B|A]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import a64                       # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def recorded_path(path: Path) -> str:
    """The path a spec record stores: relative to the repository when the file lies inside it, so a record
    does not carry the directory layout of the machine that generated it."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


MAGIC_UID = 0xDEAD               # uid_t trigger; a 16-bit value, no real uid collides
CAVE_MIN_BYTES = 0x40            # the stub needs 60 bytes; require a little slack
CAVE_SCAN_LIMIT = 1 << 20        # do not walk more than 1 MiB back from _etext
PACIASP = 0xD503233F

# The logging entry point the module calls. `_printk` is the 6.x kallsyms name of
# the same function 5.10 exports as `printk`; earlier trees additionally carry
# `vprintk`. One reachable log function is enough, so resolve the first one that
# exists instead of demanding a single name per release.
PRINTK_CANDIDATES = ("_printk", "printk", "vprintk")

# The instruction the P1 rule rewrites: mov w0, #-0xd (-EACCES).
MOV_W0_EACCES = 0x12800180
MOV_W0_ZERO = 0x52800000
# Alternative P1 entry stub, kept so the candidate table can still be produced.
MOV_WZR_W0_RET = None            # built below with the encoder


class SpecError(SystemExit):
    pass


def fail(message: str) -> "SpecError":
    print("build_ir_spec: " + message, file=sys.stderr)
    raise SystemExit(message)


# --------------------------------------------------------------------------- #
# Inputs.
# --------------------------------------------------------------------------- #

def load_symbols(path: Path) -> dict:
    """`offset<TAB>type<TAB>name` (the layout the analysis tools emit)."""
    symbols = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        try:
            offset = int(parts[0])
        except ValueError:
            continue
        symbols.setdefault(parts[2], offset)
    if not symbols:
        fail("no symbols parsed from %s" % path)
    return symbols


def kernel_release(image: bytes) -> str:
    """The exact UTS_RELEASE, read from the kernel's own vermagic string."""
    pattern = re.compile(rb'([ -~]{10,90}) (SMP preempt mod_unload modversions aarch64)\x00')
    matches = [m for m in pattern.finditer(image)]
    if not matches:
        fail("no vermagic string in the image; cannot key the spec to a release")
    if len({m.group(1) for m in matches}) != 1:
        fail("image carries more than one vermagic release; refusing to guess")
    return matches[0].group(1).decode("ascii")


# --------------------------------------------------------------------------- #
# Rules.
# --------------------------------------------------------------------------- #

def find_avc_denied_deny(image: bytes, symbols: dict) -> int:
    """P1: the `mov w0, #-0xd` inside avc_denied."""
    start = required(symbols, "avc_denied")
    end = symbol_end(symbols, "avc_denied")
    hits = []
    for offset in range(start, end, 4):
        word = int.from_bytes(image[offset:offset + 4], "little")
        if word == MOV_W0_EACCES:
            hits.append(offset)
    if len(hits) != 1:
        fail("avc_denied has %d '-EACCES' returns, expected exactly 1" % len(hits))
    return hits[0]


def find_setresuid_entry(image: bytes, symbols: dict) -> int:
    """P3: the first instruction of __sys_setresuid (must be paciasp)."""
    start = required(symbols, "__sys_setresuid")
    word = int.from_bytes(image[start:start + 4], "little")
    if word != PACIASP:
        fail("__sys_setresuid does not start with paciasp (0x%08x); the entry rule "
             "would have to change for this build" % word)
    return start


def find_cave(image: bytes, symbols: dict, stub_size: int) -> int:
    """A run of zeros at the tail of .text, big enough for the stub."""
    etext = symbols.get("_etext")
    if etext is None:
        fail("no _etext symbol: cannot bound the cave search")
    need = max(stub_size, CAVE_MIN_BYTES)
    end = min(etext, len(image))
    start_limit = max(symbols.get("_stext", 0), end - CAVE_SCAN_LIMIT)
    cursor = end
    while cursor > start_limit:
        if image[cursor - 1] != 0:
            cursor -= 1
            continue
        run_end = cursor
        while cursor > start_limit and image[cursor - 1] == 0:
            cursor -= 1
        run_start = cursor
        if run_end - run_start >= need:
            # Prefer a 4-byte aligned start so the patcher sees whole instructions.
            aligned = (run_start + 3) & ~3
            if run_end - aligned >= need:
                return aligned
    fail("no zero cave of %d bytes in .text below _etext" % need)


def required(symbols: dict, name: str) -> int:
    if name not in symbols:
        fail("symbol %s is missing from the kallsyms dump" % name)
    return symbols[name]


def resolve_printk(symbols: dict) -> dict:
    """First available logging entry point, so 5.10 (`printk`) also generates.

    `_printk` is what 6.x kallsyms calls the same function; a pre-6.1 tree only
    exports `printk`/`vprintk`. The spec keeps the module's `#sym._printk` key
    when `_printk` exists (byte-identical to the shipped 6.6.89 spec) and uses
    the module's native `#sym.printk` key otherwise, so nothing in the module has
    to change.
    """
    for name in PRINTK_CANDIDATES:
        if name in symbols:
            return {"name": name, "offset": symbols[name], "fallback": name != "_printk"}
    fail("no logging symbol among %s; cannot build a spec"
         % ", ".join(PRINTK_CANDIDATES))


def symbol_end(symbols: dict, name: str) -> int:
    """Next symbol offset in the same section, else a bounded window."""
    start = required(symbols, name)
    following = [value for value in symbols.values() if start < value <= start + 0x4000]
    return min(following) if following else start + 0x400


def build_stub(cave: int, symbols: dict) -> tuple[bytes, list]:
    """The 15-instruction / 60-byte magic-uid gate, exactly as manual 4.4 P3c."""
    init_task = required(symbols, "init_task")
    prepare_kernel_cred = required(symbols, "prepare_kernel_cred")
    commit_creds = required(symbols, "commit_creds")
    setresuid = required(symbols, "__sys_setresuid")

    words = [
        (a64.str_pre(30, 31, -0x10), "save raw LR (we branch before paciasp)"),
        (a64.movz(9, MAGIC_UID), "w9 = magic uid"),
        (a64.cmp_reg(0, 9), "compare ruid against the magic value"),
        (a64.b_cond(cave + 12, cave + 48, a64.COND_NE), "not ours -> original prologue"),
        (a64.adrp(0, cave + 16, init_task), "x0 = &init_task"),
        (a64.add_imm(0, 0, init_task & 0xFFF), "+ offset inside the page"),
        (a64.bl(cave + 24, prepare_kernel_cred), "prepare_kernel_cred(&init_task)"),
        (a64.cbz_x(0, cave + 28, cave + 36), "allocation failed -> silent no-op"),
        (a64.bl(cave + 32, commit_creds), "commit_creds(new)"),
        (a64.mov_wzr(0), ".Lok: w0 = 0"),
        (a64.ldr_post(30, 31, 0x10), "restore LR"),
        (a64.ret(), "return"),
        (a64.ldr_post(30, 31, 0x10), ".Lorig: restore LR"),
        (a64.paciasp(), "replay the instruction we overwrote"),
        (a64.b(cave + 56, setresuid + 4), "continue at entry+4"),
    ]
    blob = bytearray()
    for index, (word, _) in enumerate(words):
        assert index * 4 == len(blob)
        blob += word.to_bytes(4, "little")
    return bytes(blob), [note for _, note in words]


# --------------------------------------------------------------------------- #
# Spec rendering.
# --------------------------------------------------------------------------- #

def render(release: str, symbols: dict, blocks: list, cave: int, stub: bytes,
           vectors_sig: int = 0, printk: dict | None = None,
           extra_meta: list | None = None) -> str:
    """Manual section 3.5 layout: #kernel/#key meta, then `off|orig|patched`."""
    printk = printk or resolve_printk(symbols)
    lines = [
        "#kernel=" + release,
        "#key=MapleSU00000000000000000000000000000000000000000",
        "# MapleSU IR spec (maplesu_ir.ko). Generated by tools/ir-gen/build_ir_spec.py."
        " Every block is an equal-length in-place patch.",
        "# The #sym.* lines are meta the offline verifier ignores and the module uses"
        " to reach kernel functions without importing a single symbol.",
        "",
        "#sym.aarch64_insn_patch_text=0x%x" % symbols["aarch64_insn_patch_text"],
    ]
    if printk["fallback"]:
        # 5.10 has no `_printk`; the module already accepts `sym.printk`, so the
        # value lands under that key. The comment keeps the reason in the file.
        lines.append("# _printk absent from this release; logging via %s" % printk["name"])
        lines.append("#sym.printk=0x%x" % printk["offset"])
    else:
        lines.append("#sym._printk=0x%x" % printk["offset"])
    lines += [
        "#sym.vectors=0x%x" % symbols["vectors"],
        # First four bytes at `vectors`: lets the module prove the VBAR_EL1
        # derivation is right before it reads anything at kbase.
        "#sig.vectors=0x%08x" % vectors_sig,
        "",
    ]
    for meta in (extra_meta or []):
        lines.append(meta)
    if extra_meta:
        lines.append("")
    for block in blocks:
        lines.append("# %s @0x%x  %s" % (block["id"], block["offset"], block["note"]))
        lines.append("%d|%s|%s" % (block["offset"], block["orig"], block["patched"]))
    lines.append("")
    return "\n".join(lines)


def parse_reference(path: Path) -> list:
    blocks = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) != 3:
            fail("reference spec has a malformed line: %r" % line)
        blocks.append((int(parts[0]), parts[1].lower(), parts[2].lower()))
    return blocks


# --------------------------------------------------------------------------- #
# Main.
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--expect-ref", default=None,
                        help="reference spec the generated blocks must equal")
    parser.add_argument("--name", default=None)
    args = parser.parse_args()

    image_path = Path(args.image)
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    symbols = load_symbols(Path(args.symbols))
    release = kernel_release(image)

    for needed in ("avc_denied", "__sys_setresuid", "aarch64_insn_patch_text",
                   "vectors", "init_task", "init_cred",
                   "prepare_kernel_cred", "commit_creds", "_etext"):
        if needed not in symbols:
            fail("image is missing symbol %s; cannot build a spec" % needed)
    printk = resolve_printk(symbols)

    cave = find_cave(image, symbols, stub_size=60)
    stub, stub_notes = build_stub(cave, symbols)

    blocks = []

    def add(block_id: str, offset: int, patched: bytes, note: str) -> None:
        orig = image[offset:offset + len(patched)]
        if len(orig) != len(patched):
            fail("block %s runs past the end of the image" % block_id)
        blocks.append({"id": block_id, "offset": offset, "orig": orig.hex(),
                       "patched": patched.hex(), "note": note,
                       "orig_bytes": orig, "patched_bytes": patched})

    p1 = find_avc_denied_deny(image, symbols)
    add("P1", p1, MOV_W0_ZERO.to_bytes(4, "little"),
        "avc_denied: -EACCES -> 0 (every SELinux denial becomes allow)")

    p3 = find_setresuid_entry(image, symbols)
    add("P3", p3, a64.b(p3, cave).to_bytes(4, "little"),
        "__sys_setresuid: entry hook -> magic-uid stub in the .text cave")

    add("P3c", cave, stub,
        "code cave: magic-uid check + commit_creds(prepare_kernel_cred(&init_task)))")

    # Nothing is emitted unless the image still holds the bytes we claim.
    for block in blocks:
        got = image[block["offset"]:block["offset"] + len(block["orig_bytes"])]
        if got != block["orig_bytes"]:
            fail("block %s does not read back from the image" % block["id"])

    if args.expect_ref:
        reference = parse_reference(Path(args.expect_ref))
        produced = [(b["offset"], b["orig"], b["patched"]) for b in blocks]
        if produced != reference:
            for index in range(max(len(produced), len(reference))):
                want = reference[index] if index < len(reference) else None
                got = produced[index] if index < len(produced) else None
                if want != got:
                    fail("block %d differs from the reference spec\n  reference: %s\n"
                         "  produced : %s" % (index, want, got))
            fail("generated blocks differ from the reference spec")

    # First four bytes at `vectors`, little endian: the module compares this with
    # what it reads at VBAR_EL1 before it trusts the derived kernel base.
    vectors_at = symbols["vectors"]
    vectors_sig = int.from_bytes(image[vectors_at:vectors_at + 4], "little")
    text = render(release, symbols, blocks, cave, stub, vectors_sig, printk)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = args.name or (release + ".ir.spec")
    spec_path = out_dir / name
    # newline="\n" is deliberate. The module compares the #kernel line byte for
    # byte against uname(2).release; a CRLF spec (the default text-mode translation
    # on Windows) would leave a stray \r and make every release look unsupported.
    spec_path.write_text(text, encoding="utf-8", newline="\n")

    record = {
        "spec": recorded_path(spec_path),
        "specSha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
        "release": release,
        "image": str(image_path),
        "imageSha256": digest,
        "imageBytes": len(image),
        "cave": {"offset": cave, "va": hex(a64.BASE + cave), "stubBytes": len(stub),
                 "notes": stub_notes},
        "printk": printk,
        "symbols": {name: symbols[name] for name in
                    ("avc_denied", "__sys_setresuid", "aarch64_insn_patch_text",
                     "vectors", "init_task", "init_cred",
                     "prepare_kernel_cred", "commit_creds", "_etext")},
        "blocks": [{"id": b["id"], "offset": b["offset"],
                    "orig": b["orig"], "patched": b["patched"], "note": b["note"]}
                   for b in blocks],
        "verifiedAgainstReference": args.expect_ref,
    }
    (out_dir / (name + ".json")).write_text(json.dumps(record, indent=2) + "\n",
                                            encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in record.items() if k != "blocks"}, indent=2))
    print("blocks: " + ", ".join("%s@0x%x" % (b["id"], b["offset"]) for b in blocks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
