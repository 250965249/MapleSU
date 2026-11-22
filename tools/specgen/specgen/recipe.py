"""The Ultra patch *recipe*: site locators, byte templates and relocations.

A recipe is release-independent. It contains:

  * a **site locator** per record - a symbol name plus a byte delta inside that symbol, never a
    file offset, so it re-resolves on any kernel whose kallsyms decodes;
  * the replacement **bytes**, expressed either as a template blob (code) or as a field list that
    is assembled from rules (envelopes, the credential slot, the one-instruction stubs);
  * a **relocation** list for every field inside a blob that carries an address, so the address is
    recomputed for the target kernel instead of being copied from the reference one;
  * the credential contract: which field is the 48 byte key, and which are the init path that is
    derived from it.

Record order is part of the format: the applier writes records in file order, so two overlapping
records (the 0x8FCF7C cave and the two 8-byte gates inside it) depend on it.

Nothing in this module touches Android or the app's catalogue; it is host-side only.
"""
from __future__ import annotations

import json

from . import a64

SCHEMA = 1


class RecipeError(ValueError):
    pass


class Reloc:
    """One address-bearing field inside a record's replacement bytes."""

    KINDS = ("branch", "imm64_delta", "u32_target", "u32_self", "u32_const", "u16_struct",
             "init_path", "credential", "word")

    def __init__(self, at: int, kind: str, **options):
        if kind not in self.KINDS:
            raise RecipeError("RELOC_KIND_UNKNOWN:%s" % kind)
        self.at = at
        self.kind = kind
        self.options = options

    def to_json(self) -> dict:
        payload = {"at": self.at, "kind": self.kind}
        payload.update(self.options)
        return payload

    @staticmethod
    def from_json(payload: dict) -> "Reloc":
        options = {key: value for key, value in payload.items() if key not in ("at", "kind")}
        return Reloc(int(payload["at"]), payload["kind"], **options)


class Record:
    def __init__(self, role: str, symbol: str, delta: int, length: int, template: str | None,
                 relocs: list[Reloc], note: str = "", reference_orig_sha256: str | None = None):
        self.role = role
        self.symbol = symbol
        self.delta = delta
        self.length = length
        self.template = template
        self.relocs = relocs
        self.note = note
        # Digest of this site's pristine bytes on the *reference* release. Purely a diagnostic:
        # a kernel whose site bytes differ is not "the same build" and must not be called verified.
        self.reference_orig_sha256 = reference_orig_sha256

    @property
    def constructed(self) -> bool:
        """True when every byte comes from a rule (no template blob)."""
        return self.template is None

    def to_json(self) -> dict:
        payload = {
            "role": self.role,
            "site": {"symbol": self.symbol, "delta": self.delta},
            "length": self.length,
            "relocs": [reloc.to_json() for reloc in self.relocs],
        }
        if self.template is not None:
            payload["template"] = self.template
        if self.note:
            payload["note"] = self.note
        if self.reference_orig_sha256:
            payload["referenceOrigSha256"] = self.reference_orig_sha256
        return payload

    @staticmethod
    def from_json(payload: dict) -> "Record":
        return Record(
            role=payload["role"],
            symbol=payload["site"]["symbol"],
            delta=int(payload["site"].get("delta", 0)),
            length=int(payload["length"]),
            template=payload.get("template"),
            relocs=[Reloc.from_json(item) for item in payload.get("relocs", [])],
            note=payload.get("note", ""),
            reference_orig_sha256=payload.get("referenceOrigSha256"),
        )


class Recipe:
    def __init__(self, ident: str, reference_release: str, records: list[Record],
                 credential_length: int = 48, init_path_template: str = "/data/{key16}/init",
                 note: str = ""):
        self.id = ident
        self.reference_release = reference_release
        self.records = records
        self.credential_length = credential_length
        self.init_path_template = init_path_template
        self.note = note

    # -- persistence ------------------------------------------------------------------------
    def to_json(self) -> dict:
        return {
            "schema": SCHEMA,
            "id": self.id,
            "note": self.note,
            "referenceKernelRelease": self.reference_release,
            "credential": {
                "length": self.credential_length,
                "initPathTemplate": self.init_path_template,
            },
            "records": [record.to_json() for record in self.records],
        }

    def save(self, path) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(self.to_json(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")

    @staticmethod
    def load(path) -> "Recipe":
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if payload.get("schema") != SCHEMA:
            raise RecipeError("RECIPE_SCHEMA_UNSUPPORTED")
        credential = payload.get("credential", {})
        return Recipe(
            ident=payload["id"],
            reference_release=payload.get("referenceKernelRelease", ""),
            records=[Record.from_json(item) for item in payload["records"]],
            credential_length=int(credential.get("length", 48)),
            init_path_template=credential.get("initPathTemplate", "/data/{key16}/init"),
            note=payload.get("note", ""),
        )

    # -- credential contract ---------------------------------------------------------------
    def credential_record(self) -> Record:
        for record in self.records:
            if any(reloc.kind == "credential" for reloc in record.relocs):
                return record
        raise RecipeError("RECIPE_CREDENTIAL_SLOT_MISSING")

    def init_path_records(self) -> list[Record]:
        return [record for record in self.records
                if any(reloc.kind == "init_path" for reloc in record.relocs)]


def check_credential(credential: bytes, length: int = 48) -> None:
    """The contract the applier and the Lite engine share: ASCII alphanumerics only."""
    if len(credential) != length:
        raise RecipeError("CREDENTIAL_LENGTH:%d" % len(credential))
    if not all(chr(byte) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
               for byte in credential):
        raise RecipeError("CREDENTIAL_ALPHABET")


def init_path_for(credential: bytes, template: str = "/data/{key16}/init") -> str:
    """The device-side init path the Ultra envelope execs: ``/data/<key16>/init``."""
    return template.format(key16=credential[:16].decode("ascii"))


# --------------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------------

class Rendered:
    """One record resolved against a concrete kernel."""

    def __init__(self, record: Record, site: int, orig: bytes, replacement: bytes):
        self.record = record
        self.site = site
        self.orig = orig
        self.replacement = replacement

    @property
    def role(self) -> str:
        return self.record.role


class RenderError(ValueError):
    pass


def resolve_site(record: Record, symbols) -> int:
    """File offset of a record's site, from the symbol table only."""
    base = symbols.offset_of(record.symbol)
    if base is None:
        raise RenderError("SITE_SYMBOL_MISSING:%s:%s" % (record.role, record.symbol))
    site = base + record.delta
    if site < 0 or site + record.length > symbols.image_size:
        raise RenderError("SITE_OUT_OF_IMAGE:%s" % record.role)
    return site


def render(recipe: Recipe, symbols, kernel: bytes, credential: bytes,
           struct_overrides: dict | None = None) -> list[Rendered]:
    """Resolve every site and emit ``(orig, replacement)`` for the target kernel."""
    check_credential(credential, recipe.credential_length)
    path = init_path_for(credential, recipe.init_path_template).encode("ascii")
    structs = _resolve_struct_offsets(recipe, symbols, kernel, struct_overrides or {})
    rendered = []
    for record in recipe.records:
        site = resolve_site(record, symbols)
        if record.constructed:
            blob = bytearray(record.length)
        else:
            blob = bytearray(bytes.fromhex(record.template))
            if len(blob) != record.length:
                raise RenderError("TEMPLATE_LENGTH:%s:%d!=%d"
                                  % (record.role, len(blob), record.length))
        for reloc in record.relocs:
            _apply_reloc(reloc, blob, site, symbols, path, credential, structs, record)
        if len(blob) != record.length:
            raise RenderError("RENDER_LENGTH:%s" % record.role)
        orig = kernel[site:site + record.length]
        if len(orig) != record.length:
            raise RenderError("SITE_TRUNCATED:%s" % record.role)
        rendered.append(Rendered(record, site, orig, bytes(blob)))
    return rendered


def _apply_reloc(reloc: Reloc, blob: bytearray, site: int, symbols, path: bytes,
                 credential: bytes, structs: dict, record: Record) -> None:
    at = reloc.at
    kind = reloc.kind
    if kind == "word":
        word = _encode_word(reloc, site, symbols)
        blob[at:at + 4] = a64.u32(word)
        return
    if kind == "branch":
        target = _target(reloc, symbols)
        here = site + at
        opcode = reloc.options.get("op", "b")
        try:
            word = a64.encode_bl(here, target) if opcode == "bl" else a64.encode_b(here, target)
        except ValueError as error:
            raise RenderError("BRANCH:%s:%s" % (record.role, error))
        blob[at:at + 4] = a64.u32(word)
        return
    if kind == "imm64_delta":
        adr_at = int(reloc.options["adr"])
        reg = int(reloc.options.get("reg", 13))
        words = int(reloc.options["words"])
        target = _target(reloc, symbols)
        delta = target - (site + adr_at)
        encoded = a64.encode_imm64(reg, delta)
        if len(encoded) != words:
            raise RenderError("IMM64_WORD_COUNT:%s:%d!=%d" % (record.role, len(encoded), words))
        for index, word in enumerate(encoded):
            blob[at + index * 4:at + index * 4 + 4] = a64.u32(word)
        return
    if kind == "u32_target":
        blob[at:at + 4] = a64.u32(_target(reloc, symbols))
        return
    if kind == "u32_self":
        blob[at:at + 4] = a64.u32(site + int(reloc.options.get("delta", 0)))
        return
    if kind == "u32_const":
        blob[at:at + 4] = a64.u32(int(reloc.options["value"], 0))
        return
    if kind == "u16_struct":
        name = reloc.options["name"]
        if name not in structs:
            raise RenderError("STRUCT_OFFSET_UNRESOLVED:%s" % name)
        blob[at:at + 2] = a64.u16(structs[name])
        return
    if kind == "init_path":
        length = int(reloc.options.get("length", 28))
        field = path + b"\0"
        if len(field) > length:
            raise RenderError("INIT_PATH_TOO_LONG:%d" % len(field))
        blob[at:at + length] = field.ljust(length, b"\0")
        return
    if kind == "credential":
        length = int(reloc.options.get("length", 48))
        blob[at:at + length] = credential
        return
    raise RenderError("REPLOC_KIND_UNSUPPORTED:%s" % kind)


def _target(reloc: Reloc, symbols) -> int:
    target = reloc.options.get("target")
    if target is None:
        raise RenderError("REPLOC_TARGET_MISSING")
    symbol = target["symbol"]
    delta = int(target.get("delta", 0))
    base = symbols.offset_of(symbol)
    if base is None:
        raise RenderError("TARGET_SYMBOL_MISSING:%s" % symbol)
    return base + delta


def _encode_word(reloc: Reloc, site: int, symbols) -> int:
    op = reloc.options["op"]
    if op == "ret":
        return a64.RET
    if op == "nop":
        return a64.NOP
    if op == "movz":
        return a64.movz(int(reloc.options.get("rd", 0)), int(reloc.options["imm"]),
                        int(reloc.options.get("shift", 0)), int(reloc.options.get("sf", 1)))
    if op == "mov_wzr":
        # ``mov w<rd>, wzr`` = ORR w<rd>, wzr, wzr
        return 0x2A1F03E0 | int(reloc.options.get("rd", 0))
    if op == "branch":
        return _encode_branch_word(reloc, site, symbols)
    raise RenderError("WORD_OP_UNKNOWN:%s" % op)


def _encode_branch_word(reloc: Reloc, site: int, symbols) -> int:
    target = _target(reloc, symbols)
    here = site + reloc.at
    opcode = reloc.options.get("op_kind", "b")
    return a64.encode_bl(here, target) if opcode == "bl" else a64.encode_b(here, target)


# --------------------------------------------------------------------------------------------
# task_struct offsets
# --------------------------------------------------------------------------------------------

_STRUCT_RULES = {
    # ``prctl_get_seccomp`` is ``mrs xN, sp_el0 ; ldrsw xD, [xN, #seccomp] ; ret`` on the 6.6 GKI
    # build: the displacement is the field offset, read from the image, never assumed. Newer builds
    # reach the same field through a different shape (see the README), so a caller may pass the
    # offset explicitly instead of letting the scan fail.
    "task_struct.seccomp": ("prctl_get_seccomp", "ldrsw"),
}


def _resolve_struct_offsets(recipe: Recipe, symbols, kernel: bytes,
                            overrides: dict | None = None) -> dict:
    needed = {reloc.options["name"] for record in recipe.records
              for reloc in record.relocs if reloc.kind == "u16_struct"}
    resolved = {}
    for name in sorted(needed):
        if overrides and name in overrides:
            resolved[name] = int(overrides[name])
            continue
        rule = _STRUCT_RULES.get(name)
        if rule is None:
            raise RenderError("STRUCT_RULE_UNKNOWN:%s" % name)
        symbol, form = rule
        start = symbols.offset_of(symbol)
        if start is None:
            raise RenderError("STRUCT_ANCHOR_MISSING:%s" % symbol)
        resolved[name] = _scan_struct_offset(kernel, start, symbols, form)
    return resolved


def _scan_struct_offset(kernel: bytes, start: int, symbols, form: str) -> int:
    """Find ``<form> xD, [xN, #imm]`` right after a ``mrs xN, sp_el0`` in the anchor symbol."""
    end = symbols.next_offset(start) or (start + 256)
    end = min(end, start + 256, len(kernel) - 4)
    register = None
    position = start
    while position < end:
        word = a64.le32(kernel, position)
        if (word & 0xFFFFFFE0) == 0xD5384100:                # mrs xN, sp_el0
            register = word & 0x1F
        elif register is not None:
            if form == "ldrsw" and (word & 0xFFC00000) == 0xB9800000:
                if ((word >> 5) & 0x1F) == register:
                    # imm12 is scaled by the access size (32-bit here), i.e. by 4.
                    return ((word >> 10) & 0xFFF) << 2
            if word == a64.RET:
                register = None
        position += 4
    raise RenderError("STRUCT_OFFSET_NOT_FOUND")
