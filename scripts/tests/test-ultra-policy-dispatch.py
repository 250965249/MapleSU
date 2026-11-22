"""Emit the real SDK dispatcher offline, then replay both query routes in Unicorn.

No kernel symbols are resolved and no device is accessed. PAC authentication,
BTI enforcement and the SDK's live hook installer remain separate acceptance.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import random
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as R

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
blob = args.binary.read_bytes()
elf = ELFFile(io.BytesIO(blob))
dyn = elf.get_section_by_name(".dynsym")
symbols = {s.name: s for s in elf.get_section_by_name(".symtab").iter_symbols()}
MASK = (1 << 64) - 1
PREDICATE, HANDLER, ACTIVATION = 0xffff800012340000, 0xffff800012350000, 0xffff800012360000


def emit(operation, gated=True):
    base, stack, data, stop, heap = 0x1000000, 0x4000000, 0x5000000, 0x6000000, 0x7000000
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    pages = set()
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        for at in range((base + seg["p_vaddr"]) & ~4095,
                        (base + seg["p_vaddr"] + seg["p_memsz"] + 4095) & ~4095, 4096):
            if at not in pages:
                u.mem_map(at, 4096)
                pages.add(at)
        u.mem_write(base + seg["p_vaddr"], seg.data())
    for at, size in [(stack, 0x20000), (data, 0x10000), (stop, 0x10000), (heap, 0x800000)]:
        u.mem_map(at, size)
    imports = {base + elf.get_section_by_name(".plt")["sh_addr"] + 32 + 16 * i:
               dyn.get_symbol(r["r_info_sym"]).name
               for i, r in enumerate(elf.get_section_by_name(".rela.plt").iter_relocations())
               if dyn.get_symbol(r["r_info_sym"])["st_shndx"] == "SHN_UNDEF"}
    byname = {n: a for a, n in imports.items()}
    for name in (".rela.dyn", ".rela.plt"):
        sec = elf.get_section_by_name(name)
        if not sec:
            continue
        for reloc in sec.iter_relocations():
            sym = dyn.get_symbol(reloc["r_info_sym"])
            kind = reloc["r_info_type"]
            if kind == 1027:
                value = base + reloc["r_addend"]
            elif kind in (257, 1025, 1026):
                value = (base + sym["st_value"] if sym["st_shndx"] != "SHN_UNDEF"
                         else byname.get(sym.name, data + 0x9000)) + reloc["r_addend"]
            else:
                raise AssertionError(("ELF relocation", kind))
            u.mem_write(base + reloc["r_offset"], struct.pack("<Q", value & MASK))
    state = {"heap": heap, "sizes": {}, "callbacks": [], "tls": {}}

    def x(i):
        return u.reg_read(getattr(R, f"UC_ARM64_REG_X{i}"))

    def alloc(size):
        at = state["heap"]
        state["heap"] += (max(size, 1) + 15) & ~15
        assert state["heap"] < heap + 0x800000
        state["sizes"][at] = size
        return at

    def cstr(at):
        out = bytearray()
        for i in range(0x10000):
            ch = bytes(u.mem_read(at + i, 1))
            if ch == b"\0":
                return bytes(out)
            out.extend(ch)
        raise AssertionError("unterminated fixture string")

    def ret(value):
        link = x(30)
        u.reg_write(R.UC_ARM64_REG_X0, value & MASK)
        u.reg_write(R.UC_ARM64_REG_PC, link)

    def on_code(uc, pc, size, unused):
        if pc == stop:
            u.emu_stop()
            return
        if pc == stop + 0x100:
            ret(state["callbacks"].pop())
            return
        name = imports.get(pc)
        if not name:
            return
        if name in ("malloc", "aligned_alloc"):
            ret(alloc(x(0) if name == "malloc" else x(1)))
        elif name == "calloc":
            size = x(0) * x(1)
            at = alloc(size)
            u.mem_write(at, bytes(size))
            ret(at)
        elif name == "realloc":
            old, size = x(0), x(1)
            at = alloc(size)
            if old:
                u.mem_write(at, bytes(u.mem_read(old, min(size, state["sizes"][old]))))
            ret(at)
        elif name == "posix_memalign":
            u.mem_write(x(0), struct.pack("<Q", alloc(x(2))))
            ret(0)
        elif name == "free":
            ret(0)
        elif name in ("strlen", "__strlen_chk"):
            ret(len(cstr(x(0))))
        elif name in ("memcpy", "memmove", "__memcpy_chk", "__memmove_chk"):
            target = x(0)
            if x(2):
                u.mem_write(target, bytes(u.mem_read(x(1), x(2))))
            ret(target)
        elif name in ("memset", "__memset_chk"):
            target = x(0)
            if x(2):
                u.mem_write(target, bytes([x(1) & 255]) * x(2))
            ret(target)
        elif name == "memcmp":
            a, b = bytes(u.mem_read(x(0), x(2))), bytes(u.mem_read(x(1), x(2)))
            ret((a > b) - (a < b))
        elif name in ("strcmp", "strncmp"):
            a, b = cstr(x(0)), cstr(x(1))
            if name == "strncmp":
                a, b = a[:x(2)], b[:x(2)]
            ret((a > b) - (a < b))
        elif name in ("vsnprintf", "snprintf", "__vsnprintf_chk", "__snprintf_chk"):
            if x(1):
                u.mem_write(x(0), b"\0")
            ret(0)
        elif name in ("pthread_mutex_lock", "pthread_mutex_unlock", "pthread_rwlock_rdlock",
                      "pthread_rwlock_wrlock", "pthread_rwlock_unlock", "__cxa_atexit"):
            ret(0)
        elif name in ("getpid", "gettid"):
            ret(1234)
        elif name == "pthread_self":
            ret(data + 0x8000)
        elif name == "pthread_getspecific":
            ret(state["tls"].get(x(0), 0))
        elif name == "pthread_setspecific":
            state["tls"][x(0)] = x(1)
            ret(0)
        elif name == "pthread_key_create":
            u.mem_write(x(0), struct.pack("<I", 1))
            ret(0)
        elif name == "pthread_once":
            at, fn = x(0), x(1)
            if bytes(u.mem_read(at, 4)) != bytes(4):
                ret(0)
            else:
                u.mem_write(at, struct.pack("<I", 2))
                state["callbacks"].append(0)
                u.reg_write(R.UC_ARM64_REG_X30, stop + 0x100)
                u.reg_write(R.UC_ARM64_REG_PC, fn)
        elif name == "__errno":
            ret(data + 0x7000)
        else:
            raise AssertionError(("unhandled SDK emitter import", name))

    u.hook_add(UC_HOOK_CODE, on_code)
    # NDK CMake builds enable stack protection and use bionic's TLS canary.
    u.reg_write(R.UC_ARM64_REG_TPIDR_EL0, data + 0x8000)
    u.reg_write(R.UC_ARM64_REG_SP, stack + 0x10000)
    for i, value in enumerate((operation, PREDICATE, HANDLER, data, 0x4000, ACTIVATION if gated else 0)):
        u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), value)
    u.reg_write(R.UC_ARM64_REG_X30, stop)
    u.emu_start(base + symbols["maplesu_policy_dispatch_bytes"]["st_value"], stop + 4, count=3000000)
    assert u.reg_read(R.UC_ARM64_REG_PC) == stop
    length = x(0)
    assert 0 < length < 0x4000, length
    return bytes(u.mem_read(data, length))


def symbol_bytes(fragment):
    sym, = (s for name, s in symbols.items() if fragment in name)
    section = elf.get_section(sym["st_shndx"])
    offset = sym["st_value"] - section["sh_addr"]
    return section.data()[offset:offset + sym["st_size"]]


def replay(raw, operation, selected, seed, base, hidden=0, empty=False, active=True):
    rnd = random.Random(seed)
    stack, stop, original = 0x4000000, 0x5000000, 0x5100000
    ret_marker = symbol_bytes("hook_ret_mode_slot_flag")
    origin_marker = symbol_bytes("hook_origin_kaddr_slot_flag")
    assert raw.count(ret_marker) == raw.count(origin_marker) == 1
    code = bytearray(raw)
    # SDK's marker arrays contain 56 identifying bytes plus an 8-byte slot.
    struct.pack_into("<I", code, raw.index(ret_marker) + 56, 0xd65f03c0)
    struct.pack_into("<Q", code, raw.index(origin_marker) + 56, original)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for at, size in [(base, 0x10000), (stack, 0x10000), (stop, 4096),
                     (original, 4096), (PREDICATE, 4096), (HANDLER, 4096), (ACTIVATION, 4096)]:
        u.mem_map(at, size)
    u.mem_write(base, bytes(code))
    u.mem_write(ACTIVATION, struct.pack("<I", int(active)))
    # The installer trampoline pops the x0/x1 pair saved by call_original.
    # Relocation of the displaced real instruction remains installer acceptance.
    u.mem_write(original, struct.pack("<II", 0xa8c107e0, 0x1400003f))
    regs = [rnd.getrandbits(64) for _ in range(31)]
    if operation == 8:
        regs[4] = stack + 0x1000  # Native int *err must remain writable.
    for i, value in enumerate(regs):
        u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), value)
    sp = stack + 0x8000
    u.reg_write(R.UC_ARM64_REG_SP, sp)
    # Actual SDK before-hook shellcode is entered after an installer frame.
    u.mem_write(sp, struct.pack("<QQQQ", regs[28], 0, regs[29], stop) + bytes(80))
    u.reg_write(R.UC_ARM64_REG_X28, 0xbad28)
    u.reg_write(R.UC_ARM64_REG_X29, 0xbad29)
    calls = []
    result = (MASK - seed) if selected and active else 0x12340000 + seed
    original_calls = 0
    handler_calls = 0
    returned_skb = 0xffff800044440000 + seed * 256

    def tick(uc, pc, size, unused):
        nonlocal original_calls, handler_calls
        if pc == stop:
            u.emu_stop()
            return
        if pc not in (PREDICATE, HANDLER, original + 0x100):
            return
        argc = 6 if operation == 8 else 1 if operation == 7 else 4 if operation == 4 else 3
        if pc == PREDICATE:
            argc = 3
        values = [u.reg_read(getattr(R, f"UC_ARM64_REG_X{i}")) for i in range(argc)]
        link = u.reg_read(R.UC_ARM64_REG_X30)
        assert u.reg_read(R.UC_ARM64_REG_SP) % 16 == 0
        if pc == PREDICATE:
            assert values[:3] == [operation, regs[0] if operation in (2, 6, 7, 8) else 0,
                                  regs[1] if operation == 6 else 0]
            answer = int(selected)
        elif operation == 7 and pc == HANDLER:
            handler_calls += 1
            answer = MASK  # Callback result must not overwrite commit_creds.
        elif operation == 8 and pc == HANDLER:
            assert values[:3] == [regs[0], returned_skb, regs[2] & 0xffffffff]
            handler_calls += 1
            answer = 0 if handler_calls <= hidden else returned_skb
        else:
            assert values == regs[:argc], (operation, selected, values, regs[:argc])
            if pc == original + 0x100:
                original_calls += 1
            answer = (0 if empty and original_calls > hidden else returned_skb) if operation == 8 else result
            if operation == 8 and not answer:
                u.mem_write(regs[4], struct.pack('<i', -11))
        calls.append(pc)
        # All legal caller-saved GPR clobbers, flags, and LR. x18 is reserved by
        # the kernel and each callback's SCS push/pop must restore its value.
        for i in list(range(18)) + [30]:
            u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), rnd.getrandbits(64))
        u.reg_write(R.UC_ARM64_REG_NZCV, rnd.randrange(16) << 28)
        u.reg_write(R.UC_ARM64_REG_X0, answer)
        u.reg_write(R.UC_ARM64_REG_PC, link)

    u.hook_add(UC_HOOK_CODE, tick)
    u.emu_start(base, stop + 4, count=5000)
    assert u.reg_read(R.UC_ARM64_REG_PC) == stop
    if not active:
        assert calls == [original + 0x100], calls
        assert original_calls == 1 and handler_calls == 0
        if operation == 8: result = returned_skb
    elif selected and operation == 7:
        assert calls == [PREDICATE, original + 0x100, HANDLER], calls
        assert original_calls == handler_calls == 1
    elif selected and operation == 8:
        count = min(8, hidden + 1)
        expected = [PREDICATE] + [v for _ in range(count) for v in (original + 0x100, HANDLER)]
        if empty and hidden < 8:
            expected.pop()
        assert calls == expected, calls
        result = 0 if hidden >= 8 or empty else returned_skb
        if not result:
            assert struct.unpack('<i', u.mem_read(regs[4], 4))[0] == -11
    else:
        assert calls == [PREDICATE, HANDLER if selected else original + 0x100], calls
        if operation == 8:
            result = returned_skb
    assert u.reg_read(R.UC_ARM64_REG_X0) == result
    assert u.reg_read(R.UC_ARM64_REG_SP) == sp + 112
    assert [u.reg_read(getattr(R, f"UC_ARM64_REG_X{i}")) for i in range(18, 30)] == regs[18:30]


report = dict(generatedAt=datetime.now(timezone.utc).isoformat(), passed=False, cases=0,
              scope="Actual SDK byte generation and inspected non-PAC installer-frame replay; kernel callbacks are ABI fixtures",
              deviceAccess=False, liveKernelHook=False, hardwarePacVerified=False, hardwareBtiVerified=False,
              binarySha256=hashlib.sha256(blob).hexdigest(), dispatchers=[])
try:
    for operation in range(9):
        raw = emit(operation)
        (args.output / f"dispatcher-{operation}.bin").write_bytes(raw)
        # Dump only the code after the SDK data block; capstone stops on data.
        dis = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        dis.skipdata = True
        listing = [f"{i.address:04x} {i.mnemonic} {i.op_str}" for i in dis.disasm(raw, 0)]
        (args.output / f"dispatcher-{operation}.asm").write_text("\n".join(listing) + "\n")
        for active in (False, True):
            for selected in (False, True):
                for seed in range(16):
                    for base in (0x100000, 0x25000000):
                        replay(raw, operation, selected, seed, base, active=active)
                        report["cases"] += 1
                        if active and operation == 8 and selected:
                            for hidden, empty in [(0, True), (1, False), (3, True), (8, False)]:
                                replay(raw, operation, selected, seed, base, hidden, empty)
                                report["cases"] += 1
        legacy = emit(operation, gated=False)
        for selected in (False, True):
            replay(legacy, operation, selected, 123, 0x100000)
            report["cases"] += 1
        report["dispatchers"].append(dict(operation=operation, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    report["passed"] = True
finally:
    inputs = [Path(__file__), ROOT / "runtime/ultra/policy/kernel_payload_sdk.cpp",
              ROOT / "runtime/ultra/policy/kernel_payload_loader.h", ROOT / "runtime/tests/kernel_payload_sdk_probe.cpp",
              ROOT / "runtime/maplesu-sdk/lib/arm64-v8a/libkernel_module_kit_static.a"]
    report["sourceSha256"] = {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in inputs}
    (args.output / "sdk-dispatch-verification.json").write_text(json.dumps(report, indent=2) + "\n")
print("PASS", report["cases"], "real SDK dispatcher ABI replay cases")
