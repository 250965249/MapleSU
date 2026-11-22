"""Replay the delivered ARM64 bootstrap completion and next-boot protection branches.

Only filesystem/libc boundaries and unrelated string/logging helpers are modeled.
The completion decision, fork branch and next-boot protection are real instructions.
"""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as r

MASK = (1 << 64) - 1
STACK, HEAP = 0x400000, 0x500000
SAFE = b'/data/fixture/init.safe_flag'
WORK = b'/data/fixture/init.boot_session.work'
COMPLETED = b'/data/fixture/init.boot_session.completed'
BOOT_ID = b'/proc/sys/kernel/random/boot_id'
BOOT = b'11111111-2222-3333-4444-555555555555\n'
# Android ARM64 asm/fcntl.h uses 0100000 for O_NOFOLLOW.
O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC, O_CREAT, O_WRONLY = 0o100000, 0o4000, 0o2000000, 0o100, 1


class Bootstrap:
    def __init__(self, blob, base=0, failure=None, fork_result=100, boot_id=BOOT):
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.base, self.failure, self.fork_result = base, failure, fork_result
        self.boot_id = boot_id
        self.files, self.events = {SAFE: b'1'}, []
        self.descriptors = {}
        self.heap = HEAP
        self.elf = ELFFile(io.BytesIO(blob))
        high = max(s['p_vaddr'] + s['p_memsz'] for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD')
        self.u.mem_map(base, (high + 4095) & ~4095)
        for s in self.elf.iter_segments():
            if s['p_type'] == 'PT_LOAD':
                self.u.mem_write(base + s['p_vaddr'], s.data())
        self.u.mem_map(STACK, 0x20000)
        self.u.mem_map(HEAP, 0x20000)
        self.u.reg_write(r.UC_ARM64_REG_SP, STACK + 0x8000)
        self.u.reg_write(r.UC_ARM64_REG_X22, STACK + 0x8080)
        self.put_string(STACK + 0x8008, SAFE)
        dyn, plt = self.elf.get_section_by_name('.dynsym'), self.elf.get_section_by_name('.plt')
        self.plt = {plt['sh_addr'] + 32 + i * 16: dyn.get_symbol(rel['r_info_sym']).name
                    for i, rel in enumerate(self.elf.get_section_by_name('.rela.plt').iter_relocations())}
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def alloc(self, value):
        at = self.heap
        self.heap += (len(value) + 31) & ~15
        self.u.mem_write(at, value)
        return at

    def put_string(self, at, value):
        if len(value) <= 22:
            raw = bytes([len(value) * 2]) + value + b'\0'
            self.u.mem_write(at, raw.ljust(24, b'\0'))
        else:
            pointer = self.alloc(value + b'\0')
            self.u.mem_write(at, struct.pack('<QQQ', (len(value) | 15) + 2, len(value), pointer))

    def cstr(self, at):
        return bytes(self.u.mem_read(at, 512)).split(b'\0')[0]

    def string(self, at):
        first = bytes(self.u.mem_read(at, 24))
        if first[0] & 1:
            _, size, ptr = struct.unpack('<QQQ', first)
            return bytes(self.u.mem_read(ptr, size))
        return first[1:1 + (first[0] >> 1)]

    def x(self, n):
        return self.u.reg_read(getattr(r, 'UC_ARM64_REG_X' + str(n)))

    def returned(self, value=0):
        lr = self.x(30)
        # Catch reliance on caller-saved registers surviving libc calls.
        for i in range(19):
            self.u.reg_write(getattr(r, 'UC_ARM64_REG_X' + str(i)), 0xbad000 + i)
        self.u.reg_write(r.UC_ARM64_REG_X0, value & MASK)
        self.u.reg_write(r.UC_ARM64_REG_PC, lr)

    def hook(self, uc, address, size, context):
        at = address - self.base
        if at in (0xa9688, 0xa88bc):
            self.end = at
            uc.emu_stop()
        elif at == 0xaab80:  # Error -> diagnostic string, not a state decision.
            self.put_string(self.x(8), str(self.x(0)).encode())
            self.returned()
        elif at == 0xac66c:  # Installed executable path.
            self.put_string(self.x(8), b'/data/fixture/init')
            self.returned()
        elif at == 0x5d254:  # std::string::append.
            self.put_string(self.x(0), self.string(self.x(0)) + self.cstr(self.x(1)))
            self.returned(self.x(0))
        elif at == 0x9f200:
            self.returned()
        elif at == 0xaac9c:  # Existing boot-id persistence boundary.
            path = self.string(self.x(0))
            assert path == WORK
            self.events.append('publish-work')
            if self.failure != 'receipt':
                self.files[path] = self.boot_id
            self.returned(self.failure != 'receipt')
        elif at == 0xb0718:  # Existing one-byte flag persistence boundary.
            path, value = self.string(self.x(0)), str(self.x(1)).encode()
            assert path == SAFE and value in (b'1', b'2', b'3')
            self.files[path] = value
            self.events.append('flag-' + value.decode())
            self.returned()
        elif at == 0xa55e4:
            self.events.append('clear-crash-log')
            self.returned()
        elif at in self.plt:
            name = self.plt[at]
            if name == 'fork':
                self.events.append('fork')
                self.returned(self.fork_result)
            elif name == 'sleep':
                self.events.append('sleep-' + str(self.x(0)))
                self.returned()
            elif name in ('printf', 'fprintf', 'sync'):
                self.returned()
            elif name == 'strlen':
                self.returned(len(self.cstr(self.x(0))))
            elif name == 'strcmp':
                left, right = self.cstr(self.x(0)) + b'\0', self.cstr(self.x(1)) + b'\0'
                self.returned(next((a - b for a, b in zip(left, right) if a != b), 0))
            elif name == 'memcpy':
                target = self.x(0)
                self.u.mem_write(target, bytes(self.u.mem_read(self.x(1), self.x(2))))
                self.returned(target)
            elif name == '__errno':
                self.returned(HEAP + 0x1f000)
            elif name == 'syscall':
                self.syscall()
            elif name == '_exit':
                self.end = 'child-exit'
                uc.emu_stop()
            else:
                raise AssertionError(('unexpected libc call', name, hex(at)))

    def syscall(self):
        # New completion writer uses the Android ARM64 ABI through libc syscall().
        nr, fd = self.x(0), self.x(1)
        error = None
        if nr == 56:  # openat
            path = self.cstr(self.x(2))
            assert fd & 0xffffffff == (-100 & 0xffffffff)  # AT_FDCWD
            if path == SAFE:
                assert self.x(3) == O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC and self.x(4) == 0
                self.events.append('open-safe')
                if self.failure == 'open': error = 13
                value = 11
            elif path == BOOT_ID:
                assert self.x(3) == O_NOFOLLOW | O_CLOEXEC and self.x(4) == 0
                value = 12
            elif path == COMPLETED:
                assert self.x(3) == O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC and self.x(4) == 0o600
                self.events.append('open-completion')
                self.files.setdefault(path, b'')
                value = 13
            else:
                raise AssertionError(('unexpected open path', path))
            if not error:
                assert value not in self.descriptors
                self.descriptors[value] = path
        elif nr == 63:  # read current boot ID
            assert fd == 12 and self.descriptors.get(fd) == BOOT_ID and self.x(3) == 38
            data = self.boot_id[:self.x(3)]
            if data: self.u.mem_write(self.x(2), data)
            value = len(data)
        elif nr == 80:  # fstat: Android ARM64 struct stat.
            path = self.descriptors.get(fd)
            assert (fd == 11 and path == SAFE) or (fd == 13 and path == COMPLETED)
            st = bytearray(128)
            mode = 0o040700 if path == SAFE and self.failure == 'type' else 0o100600
            struct.pack_into('<III', st, 16, mode, 1, 0)
            struct.pack_into('<q', st, 48, len(self.files[path]))
            self.u.mem_write(self.x(2), bytes(st))
            value = 0
        elif nr == 68:  # pwrite64
            path = self.descriptors.get(fd)
            assert self.x(4) == 0
            if fd == 11 and path == SAFE:
                assert self.x(3) == 1
                value = 1
                self.events.append('write-safe')
                if self.failure == 'write': error = 5
                elif self.failure == 'short': value = 0
                else: self.files[SAFE] = bytes(self.u.mem_read(self.x(2), 1))
            elif fd == 13 and path == COMPLETED:
                assert self.x(3) == 37
                self.files[COMPLETED] = bytes(self.u.mem_read(self.x(2), 37))
                self.events.append('write-completion')
                value = 37
            else:
                raise AssertionError(('unexpected pwrite fd', fd, path))
        elif nr == 82:  # fsync
            path = self.descriptors.get(fd)
            assert (fd == 11 and path == SAFE) or (fd == 13 and path == COMPLETED)
            self.events.append('sync-safe' if path == SAFE else 'sync-completion')
            if path == SAFE and self.failure == 'sync': error = 5
            value = 0
        elif nr == 57:
            path = self.descriptors.pop(fd, None)
            assert (fd, path) in ((11, SAFE), (12, BOOT_ID), (13, COMPLETED))
            if path == SAFE and self.failure == 'close': error = 5
            value = 0
        else:
            raise AssertionError(('unexpected syscall', nr))
        if error:
            self.u.mem_write(HEAP + 0x1f000, struct.pack('<I', error))
            value = -1
        self.returned(value)

    def finish(self, rc=0):
        self.u.reg_write(r.UC_ARM64_REG_X19, rc & MASK)
        self.u.emu_start(self.base + 0xa95b8, self.base + 0x140000, count=10000)
        return self.files[SAFE]

    def begin(self):
        self.u.emu_start(self.base + 0xa88c4, self.base + 0xa88d4, count=1000)

    def next_boot(self, protect=1):
        # The parsed value is 1 or 3, which enters the real failed-boot branch.
        if self.files[SAFE] in (b'1', b'3'):
            self.u.reg_write(r.UC_ARM64_REG_W23, protect)
            self.u.emu_start(self.base + 0xa88a0, self.base + 0x140000, count=1000)
            return self.end == 0xa88bc
        return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--helper', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    blob, cases = a.helper.read_bytes(), []

    def check(label, fn):
        try:
            fn()
            cases.append(dict(name=label, passed=True))
            print('PASS', label)
        except AssertionError as error:
            cases.append(dict(name=label, passed=False, detail=str(error)))
            print('FAIL', label, str(error))

    for base in (0, 0x10000, 0x70000000):
        for label, fork in [('child-lost', 100), ('fork-fails', -1), ('quick-reboot', 100)]:
            def success(base=base, fork=fork):
                b = Bootstrap(blob, base, fork_result=fork)
                flag = b.finish()
                assert flag == b'2', ('successful module initialization left an armed failure marker', flag, b.events)
                assert b.files.get(COMPLETED) == BOOT
                assert b.files.get(WORK) == BOOT
                assert b.next_boot(), 'normal reboot entered protection'
                assert 'fork' not in b.events, b.events
            check(label + '-aslr-' + hex(base), success)

    def error_return():
        b = Bootstrap(blob)
        assert b.finish(-19999) == b'1'
        assert WORK not in b.files, ('failed initialization was reported Running', b.events)
        assert not b.next_boot(), 'real incomplete bootstrap bypassed protection'
        assert b.files[SAFE] == b'3'
        assert not b.next_boot(), 'protection must persist until controlled repair'
    check('initialization-error-preserves-protection', error_return)

    def no_completion():
        b = Bootstrap(blob)
        assert not b.next_boot()
        assert b.files[SAFE] == b'3'
    check('crash-before-completion-preserves-protection', no_completion)

    def invalid_boot_id():
        for boot_id in (b'', BOOT[:-1], BOOT + b'0', b'g' * 36 + b'\n', BOOT.replace(b'-', b'0', 1)):
            b = Bootstrap(blob, boot_id=boot_id)
            assert b.finish() == b'1', ('invalid boot ID disabled protection', boot_id, b.events)
            assert COMPLETED not in b.files and WORK not in b.files
            assert not b.next_boot(), 'an invalid completion receipt bypassed protection'
    check('invalid-boot-id-preserves-protection-and-no-receipt', invalid_boot_id)

    def repeated_reboots():
        files = {SAFE: b'2'}
        for cycle in range(20):
            boot_id = f'11111111-2222-3333-4444-{cycle:012d}\n'.encode()
            b = Bootstrap(blob, boot_id=boot_id)
            b.files = files.copy()
            assert b.next_boot(), ('normal reboot entered protection', cycle)
            b.begin()
            assert b.files[SAFE] == b'1'
            assert b.finish() == b'2', ('completion did not disarm protection', cycle)
            assert b.files[COMPLETED] == boot_id
            assert b.files[WORK] == boot_id
            assert b.events.index('sync-completion') < b.events.index('write-safe')
            assert b.events.index('sync-safe') < b.events.index('publish-work')
            files = b.files
    check('twenty-reboots-with-distinct-boot-ids', repeated_reboots)

    def adapter_abi():
        b = Bootstrap(blob)
        sp = b.u.reg_read(r.UC_ARM64_REG_SP)
        expected = {19: 0, **{i: 0x12340000 + i for i in range(20, 31)}}
        for index, value in expected.items():
            b.u.reg_write(getattr(r, 'UC_ARM64_REG_X' + str(index)), value)
        b.u.emu_start(0xa95b8, 0xa95bc, count=10000)
        assert {i: b.x(i) for i in expected} == expected
        assert b.u.reg_read(r.UC_ARM64_REG_SP) == sp
        assert b.x(8) == sp + 0x110
        assert b.files[SAFE] == b'2' and WORK not in b.files
    check('adapter-preserves-callee-registers-stack-and-continuation', adapter_abi)

    def disabled():
        b = Bootstrap(blob)
        assert b.next_boot(protect=0)
    check('existing-protection-option-preserved', disabled)

    for failure in ('open', 'type', 'write', 'short', 'sync'):
        def io_error(failure=failure):
            b = Bootstrap(blob, failure=failure)
            b.finish()
            assert WORK not in b.files, ('uncommitted state was reported Running', failure, b.events)
        check('completion-io-' + failure, io_error)

    def receipt_error():
        b = Bootstrap(blob, failure='receipt')
        assert b.finish() == b'2'
        assert WORK not in b.files
        assert b.next_boot(), 'receipt failure must allow another clean initialization'
    check('receipt-failure-does-not-rearm-completed-bootstrap', receipt_error)

    def close_error():
        b = Bootstrap(blob, failure='close')
        b.finish()
        assert WORK not in b.files
    check('completion-io-close', close_error)

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(dict(helperSha256=hashlib.sha256(blob).hexdigest(),
        harnessSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        actualBootstrapInstructions=True, deviceVerification=False, cases=cases,
        passed=all(c['passed'] for c in cases)), indent=2) + '\n')
    raise SystemExit(0 if all(c['passed'] for c in cases) else 1)


if __name__ == '__main__':
    main()
