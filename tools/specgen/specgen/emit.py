"""Emit a Ultra spec from a recipe, and derive every digest instead of pinning it.

The applier contract (``UltraKernelSpec.apply``) is repeated here exactly, because a generator
that disagrees with the applier is worse than no generator:

  * every record's ``original`` is checked against the *input* kernel before anything is written;
  * replacements are written in file order, so a later record wins inside an earlier range;
  * no byte outside a record's replacement range may change.

The derived values (patched kernel digest, changed byte count, and the boot digest after the
container rebuild) are computed here and handed to the caller as an oracle for a *generated*
plan; the pinned k22 values exist only inside the self-check.
"""
from __future__ import annotations

import hashlib

from . import recipe as recipe_module


class ApplyError(ValueError):
    pass


class PatchRecord:
    """One ``offset|orig|repl`` line."""

    def __init__(self, offset: int, original: bytes, replacement: bytes, role: str = ""):
        self.offset = offset
        self.original = original
        self.replacement = replacement
        self.role = role

    def __repr__(self) -> str:
        return "PatchRecord(%s@0x%X,%d)" % (self.role or "-", self.offset, len(self.replacement))


class Application:
    def __init__(self, kernel: bytes, changed: int, outside: int):
        self.kernel = kernel
        self.changed = changed
        self.outside = outside

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.kernel).hexdigest()


def text(records: list[PatchRecord]) -> str:
    return "".join("%d|%s|%s\n" % (record.offset, record.original.hex(), record.replacement.hex())
                   for record in records)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply(records: list[PatchRecord], kernel: bytes) -> Application:
    """Replay ``records`` on ``kernel`` with the applier's exact rules."""
    for index, record in enumerate(records):
        end = record.offset + max(len(record.original), len(record.replacement))
        if record.offset < 0 or end > len(kernel):
            raise ApplyError("RANGE:%d@0x%X" % (index, record.offset))
        if not record.original or not record.replacement:
            raise ApplyError("EMPTY:%d" % index)
        if kernel[record.offset:record.offset + len(record.original)] != record.original:
            raise ApplyError("ORIGINAL_MISMATCH:%d@0x%X" % (index, record.offset))
    patched = bytearray(kernel)
    for record in records:
        patched[record.offset:record.offset + len(record.replacement)] = record.replacement
    changed = 0
    outside = 0
    covered = bytearray(len(kernel))
    for record in records:
        for index in range(record.offset, record.offset + len(record.replacement)):
            covered[index] = 1
    for index in range(len(kernel)):
        if patched[index] == kernel[index]:
            continue
        changed += 1
        if not covered[index]:
            outside += 1
    if outside:
        raise ApplyError("OUTSIDE_SITES:%d" % outside)
    return Application(bytes(patched), changed, outside)


def generate(recipe, symbols, kernel: bytes, credential: bytes, struct_overrides=None):
    """Render the recipe for ``kernel`` and return ``(records, application)``."""
    rendered = recipe_module.render(recipe, symbols, kernel, credential, struct_overrides)
    records = [PatchRecord(item.site, item.orig, item.replacement, item.record.role)
               for item in rendered]
    return records, apply(records, kernel)


def address_residue(recipe, symbols, records: list[PatchRecord]) -> list[str]:
    """Report addresses left behind in a rendered blob that no relocation explains.

    Two shapes are checked, both of which have already cost one bug:

    * an ``adr``/``adrp`` whose computed target is outside its own record but which has no
      ``imm64_delta`` relocation - the displacement is frozen at the reference kernel's layout;
    * a 4 byte word that equals some symbol's file offset but is not covered by a ``u32_target``.

    On the reference kernel a stale address is *correct*, which is exactly why the applier's own
    checks can never catch it. This is the only check that can.
    """
    from . import a64

    problems = []
    for record, patch in zip(recipe.records, records):
        if not record.constructed and record.template is None:
            continue
        blob = patch.replacement
        covered = bytearray(len(blob))
        for reloc in record.relocs:
            width = 4
            if reloc.kind == "u16_struct":
                width = 2
            elif reloc.kind in ("init_path", "credential"):
                width = int(reloc.options["length"])
            elif reloc.kind == "imm64_delta":
                width = 4 * int(reloc.options["words"])
            for index in range(reloc.at, min(reloc.at + width, len(covered))):
                covered[index] = 1
        relocated_adr = {int(reloc.options["adr"]) for reloc in record.relocs
                         if reloc.kind == "imm64_delta"}
        for position in range(0, len(blob) - 3, 4):
            word = a64.le32(blob, position)
            # Printable windows are data (the init path, the argv[0] string), not instructions.
            if all(0x20 <= byte < 0x7F for byte in blob[position:position + 4]):
                continue
            if a64.is_adr(word):
                target = a64.decode_adr(word, patch.offset + position)
                if target is not None and not (
                        patch.offset <= target < patch.offset + len(blob)):
                    if position not in relocated_adr:
                        problems.append("%s: adr at +0x%X frozen to 0x%X"
                                        % (record.role, position, target))
            value = a64.le32(blob, position)
            if not covered[position] and symbols.is_symbol_start(value):
                problems.append("%s: unrelocated symbol offset 0x%X at +0x%X"
                                % (record.role, value, position))
    return problems


def site_match(recipe, records: list[PatchRecord]) -> tuple[int, int, list[str]]:
    """How many records still carry the reference release's pristine bytes.

    A record's ``original`` is always read from the target kernel, so it can never "fail" the
    applier's own check. That is exactly why the count matters: a kernel whose site bytes differ
    from the reference build is *not* the build the code blobs were compiled against, and a plan
    produced for it must not be labelled verified. Returns ``(matching, total, differing_roles)``.
    """
    matching = 0
    total = 0
    differing = []
    for record, patch in zip(recipe.records, records):
        if not record.reference_orig_sha256:
            continue
        total += 1
        if sha256_bytes(patch.original) == record.reference_orig_sha256:
            matching += 1
        else:
            differing.append(record.role)
    return matching, total, differing


def spec_text(recipe, symbols, records: list[PatchRecord], kernel_release: str,
              credential: bytes, note: str = "") -> str:
    """The ``offset|orig|repl`` document the applier parses."""
    lines = []
    lines.append("#generated by tools/specgen from recipe %s" % recipe.id)
    if note:
        lines.append("#%s" % note)
    lines.append("#origin=GENERATED")
    lines.append("#sites=%d" % len(records))
    lines.append("#kernel=%s" % kernel_release)
    lines.append("#key=%s" % credential.decode("ascii"))
    body = "".join("%d|%s|%s\n" % (record.offset, record.original.hex(),
                                   record.replacement.hex()) for record in records)
    return "\n".join(lines) + "\n" + body
