"""Exercise the product generator and its emitted AArch64 executor, offline.

Requires capstone/unicorn in the host Python. Hardware caches/TLBs are modeled
boundaries; this test does not certify a device boot.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from types import SimpleNamespace

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import generate

parser = argparse.ArgumentParser()
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--kernel", type=Path, default=ROOT / ".analysis/ace6-20261025/boot/kernel")
parser.add_argument("--symbols", type=Path, default=ROOT / "evidence/ultra-boot-matrix-20261103/verified/ace6ref/native-symbols.tsv")
parser.add_argument("--patched-kernel", type=Path)
parser.add_argument("--receipt", type=Path)
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
receipt = args.receipt or args.out / "generated.json"
patched = args.patched_kernel or args.out / "generated.raw"
options = SimpleNamespace(symbols=None, struct_offsets=None,
    recipe=ROOT / "tools/specgen/specgen/recipes/k22.json",
    java=str(native_toolchain.jdk_tool("java")),
    image_core=None, kernel=args.kernel, boot=None, out=args.out / "generated.spec",
    receipt=receipt, patched_kernel=patched, patched_boot=None, require_release=None)
if not receipt.exists():
    assert generate(options, b"F" * 48) == 0
stock, kernel = args.kernel.read_bytes(), patched.read_bytes()
meta = json.loads(receipt.read_text(encoding="utf-8-sig"))
assert hashlib.sha256(stock).hexdigest() == meta['baseKernelSha256'], 'receipt/stock mismatch'
records = {x["role"]: x for x in meta["records"]}
# Reported plans carry the BTF-derived reply slot; the original fixture uses 16.
cred_suid = meta.get('structOffsets', {}).get('cred.suid', 16)
symbols = {}
symbol_text = args.symbols.read_text(encoding="utf-8-sig")
if args.symbols.suffix == '.json':
    symbols = {name: offsets[0] for name, offsets in json.loads(symbol_text)['symbols'].items() if offsets}
else:
    for line in symbol_text.splitlines():
        fields = line.split('\t')
        name, offset = (fields[2], int(fields[0], 16)) if len(fields) >= 3 else (fields[0], int(fields[1]))
        symbols[name] = offset
allocator = symbols.get('module_alloc', symbols.get('execmem_alloc'))
release = symbols.get('module_memfree', symbols.get('execmem_free'))
assert allocator is not None and release is not None, 'Allocator/free ABI targets missing'
failures = []
def check(name, ok):
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        failures.append(name)

for name, size in [("die", 228), ("arm64_notify_die", 52), ("panic", 48),
                   ("__drm_printfn_coredump", 124), ("__dev_printk", 84)]:
    at = symbols[name]
    check("preserve original " + name, stock[at:at+size] == kernel[at:at+size])

BASE, DATA, STACK, BUFFER = 0x1000000, 0x5000000, 0x6000000, 0x7000000
REQUEST, CRED, SP = DATA + 0x6000, DATA + 0x2000, STACK + 0x8000
executor = BASE + records["__drm_printfn_coredump+0x0"]["offset"]
restore = BASE + records["arm64_notify_die+0x0"]["offset"]
page_shift = {1: 12, 2: 14, 3: 16}[(struct.unpack_from('<Q', stock, 24)[0] >> 1) & 3]

def replay(ro, execute, nx, rw, pages=1):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, (len(kernel) + 4095) & ~4095)
    u.mem_write(BASE, kernel)
    for at in (DATA, STACK, BUFFER):
        u.mem_map(at, 0x10000)
    u.reg_write(reg.UC_ARM64_REG_SP, SP)
    u.reg_write(reg.UC_ARM64_REG_X11, REQUEST)
    u.reg_write(reg.UC_ARM64_REG_X17, CRED)
    u.mem_write(REQUEST + 68, struct.pack("<Q", BUFFER))
    u.mem_write(REQUEST + 80, struct.pack("<I", pages))
    calls, invalidated = [], []
    statuses = {BASE + symbols[n]: (label, status) for n, label, status in
        [("set_memory_ro", "ro", ro), ("set_memory_x", "x", execute),
         ("set_memory_nx", "nx", nx), ("set_memory_rw", "rw", rw)]}
    def hook(uc, address, size, _):
        if address in statuses or address == BASE + release:
            kind, status = statuses.get(address, ("free", 0))
            calls.append(kind)
            assert uc.reg_read(reg.UC_ARM64_REG_X0) == BUFFER, (kind, "buffer lost")
            if kind != "free":
                assert uc.reg_read(reg.UC_ARM64_REG_X1) == pages, (kind, "page count lost")
            # AAPCS permits these calls to destroy every caller-saved register.
            link = uc.reg_read(reg.UC_ARM64_REG_X30)
            for i in range(19):
                uc.reg_write(getattr(reg, "UC_ARM64_REG_X" + str(i)), 0xdead0000 + i)
            uc.reg_write(reg.UC_ARM64_REG_X0, status & 0xffffffff)
            uc.reg_write(reg.UC_ARM64_REG_PC, link)
        elif address == BUFFER:
            calls.append("executed")
            expected_pages = [(BUFFER >> 12) + i * (1 << (page_shift - 12)) for i in range(pages)]
            assert invalidated == expected_pages, ('TLB publication before BLR', invalidated, expected_pages)
            assert uc.reg_read(reg.UC_ARM64_REG_X17) == CRED + cred_suid, "reply pointer lost"
            u.mem_write(CRED + cred_suid, struct.pack("<Q", 0x123456789abcde00))
            uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
        elif address == restore:
            uc.emu_stop()
        elif bytes(uc.mem_read(address, 4)) == bytes.fromhex("6c8308d5"):
            invalidated.append(uc.reg_read(reg.UC_ARM64_REG_X12))
            uc.reg_write(reg.UC_ARM64_REG_PC, address + 4)  # Modeled VAAE1IS boundary
        elif bytes(uc.mem_read(address, 4)) in (bytes.fromhex("1f7508d5"), bytes.fromhex("1f7108d5")):
            uc.reg_write(reg.UC_ARM64_REG_PC, address + 4)  # IC IALLU/IALLUIS boundary
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(executor + 4, 0, count=300)
    assert u.reg_read(reg.UC_ARM64_REG_PC) == restore, "executor did not return"
    assert u.reg_read(reg.UC_ARM64_REG_SP) == SP, "executor unbalanced SP"
    reply = struct.unpack("<Q", bytes(u.mem_read(CRED + cred_suid, 8)))[0]
    if ro or execute:
        assert not invalidated, 'Permission failure published an executable translation'
    return calls, reply, invalidated

results = []
for name, statuses, expected in [
    ("success", (0, 0, 0, 0), ["ro", "x", "executed", "nx", "rw", "free"]),
    ("RO failure", (-22, 0, 0, 0), ["ro", "nx", "rw", "free"]),
    ("X failure", (0, -22, 0, 0), ["ro", "x", "nx", "rw", "free"]),
    ("NX cleanup failure", (0, 0, -22, 0), ["ro", "x", "executed", "nx"]),
    ("RW cleanup failure", (0, 0, 0, -22), ["ro", "x", "executed", "nx", "rw"]),
]:
    try:
        calls, reply, invalidated = replay(*statuses)
        expected_reply = 0x123456789abcde00 if not any(statuses) else (-19999 & ((1 << 64)-1))
        check(name, calls == expected and reply == expected_reply)
        results.append({"case": name, "calls": calls, "reply": hex(reply), "tlbiPages": invalidated})
    except Exception as error:
        check(name + ": " + str(error), False)

try:
    calls, reply, invalidated = replay(0, 0, 0, 0, pages=3)
    check('multi-page TLB publication', len(invalidated) == 3 and reply == 0x123456789abcde00)
    results.append({'case': 'multi-page TLB publication', 'calls': calls,
                    'tlbiPages': invalidated, 'pageShift': page_shift, 'reply': hex(reply)})
except Exception as error:
    check('multi-page TLB publication: ' + str(error), False)

# Enter the dispatch after filename/key decoding and replay the actual emitted
# comparisons, staging release, allocation tail and credential reply store.
gate = BASE + records['die+0x0']['offset']
instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(
    kernel[records['die+0x0']['offset']:records['die+0x0']['offset']+272], gate))
dispatch = next(i.address for i in instructions if i.mnemonic == 'cmp' and i.op_str == 'w12, #0x31')
tail = BASE + records['die+0xD4']['offset']
for name, flag, size, expected, reply in [
    ('staging release command 5', 53, 4096, ['free'], 0),
    ('allocation tail', 48, 4096, ['tail', 'alloc', 'resume'], BUFFER),
    ('zero-size allocation tail', 48, 0, ['tail', 'resume'], 0),
]:
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, (len(kernel)+4095)&~4095)
    u.mem_write(BASE, kernel)
    for at in (DATA, STACK, BUFFER): u.mem_map(at, 0x10000)
    for register, value in [(reg.UC_ARM64_REG_SP, SP), (reg.UC_ARM64_REG_X11, REQUEST),
                            (reg.UC_ARM64_REG_X12, flag), (reg.UC_ARM64_REG_X17, CRED),
                            (reg.UC_ARM64_REG_X0, BUFFER)]:
        u.reg_write(register, value)
    u.mem_write(REQUEST+76, struct.pack('<I', size))
    calls = []
    def gate_hook(uc, address, instruction_size, _):
        if address == restore: uc.emu_stop()
        elif address == tail:
            assert address == gate+272
            calls.append('tail')
        elif address == gate+196:
            calls.append('resume')
        elif address in (BASE+allocator, BASE+release):
            allocating = address != BASE+release
            calls.append('alloc' if allocating else 'free')
            if allocating and 'module_alloc' not in symbols:
                assert uc.reg_read(reg.UC_ARM64_REG_X0) == 0, 'execmem type must be DEFAULT'
                assert uc.reg_read(reg.UC_ARM64_REG_X1) == size, 'execmem size lost in adapter'
            else:
                assert uc.reg_read(reg.UC_ARM64_REG_X0) == (size if allocating else BUFFER)
            link = uc.reg_read(reg.UC_ARM64_REG_X30)
            for i in range(19): uc.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(i)), 0xdead0000+i)
            uc.reg_write(reg.UC_ARM64_REG_X0, BUFFER if allocating else 0xdead)
            uc.reg_write(reg.UC_ARM64_REG_PC, link)
    u.hook_add(UC_HOOK_CODE, gate_hook)
    u.emu_start(dispatch, 0, count=100)
    actual = struct.unpack('<Q', bytes(u.mem_read(CRED+cred_suid, 8)))[0]
    check(name, calls == expected and actual == reply and
          u.reg_read(reg.UC_ARM64_REG_SP) == SP and u.reg_read(reg.UC_ARM64_REG_PC) == restore)
    results.append({'case': name, 'calls': calls, 'reply': hex(actual)})
(args.out / "regression.json").write_text(json.dumps({"cases": results, "failures": failures, "credSuid": cred_suid,
    "kernelSha256": hashlib.sha256(kernel).hexdigest(), "baseKernelSha256": hashlib.sha256(stock).hexdigest(),
    "symbolFile": str(args.symbols), "deviceVerification": False}, indent=2))
raise SystemExit(bool(failures))
