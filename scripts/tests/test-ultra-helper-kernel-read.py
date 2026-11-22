"""Replay actual cold SDK/helper symbol resolvers and nofault callbacks offline."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn import arm64_const as R

ROOT = Path(__file__).resolve().parents[2]
BASE, STACK, DATA, STOP, HEAP = 0x1000000, 0x4000000, 0x5000000, 0x6000000, 0x7000000
KBASE = 0xffff800000000000
APPEND, SOURCE = KBASE + 0x2000000, KBASE + 0x3000ff8
LOOKUP, NOFAULT, COPY_USER = KBASE + 0x110000, KBASE + 0x150000, KBASE + 0x151000
KCODE, KSTACK, KREQ, KCRED, KSTOP = 0x100000, 0x400000, 0x500000, 0x600000, 0x700000
MASK = (1 << 64) - 1
DECODER = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
SIGNED = lambda value: value if value < 1 << 63 else value - (1 << 64)
SHA = lambda value: hashlib.sha256(value).hexdigest()
READ_NAME = '_ZN13kernel_module23request_kernel_read_memEmPvj'
SYMBOL_NAME = '_ZN13kernel_module20kallsyms_lookup_nameEPKcRNS_9SymbolHitENS_15SymbolMatchModeE'
EXEC_NAME = '_ZN13kernel_module32execute_kernel_asm_func_with_bufEPKhjRm'
PARSER_NAME = '_ZN13kernel_module20parser_root_key_infoEPKcRi'


class Replay:
    def __init__(self, blob, helper, config):
        self.blob, self.helper, self.config = blob, helper, config
        self.elf = ELFFile(io.BytesIO(blob))
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.state = dict(heap=HEAP, allocations={}, tls={}, imports=set(), callbacks=[],
                          metadata=[], reads=[], lookups=[], kernelLookups=[], parser=0,
                          coldDiscovery=0, sequence=[], readerDepth=0, maxReaderDepth=0)
        elf, u = self.elf, self.u
        symbols = elf.get_section_by_name('.symtab')
        self.symbols = {s.name: s['st_value'] for s in symbols.iter_symbols()} if symbols else {}
        self.reader = 0xc48e8 if helper else self.symbols[READ_NAME]
        self.lookup = 0xbac9c if helper else self.symbols[SYMBOL_NAME]
        self.execute = 0xc5aa8 if helper else self.symbols[EXEC_NAME]
        self.parser = 0xbf388 if helper else self.symbols[PARSER_NAME]
        self.tls_function = None if helper else self.symbols['__emutls_get_address']
        high = max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
        u.mem_map(BASE, (high + 4095) & ~4095)
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                u.mem_write(BASE + seg['p_vaddr'], seg.data())
        dyn = elf.get_section_by_name('.dynsym')
        plt = elf.get_section_by_name('.plt')['sh_addr']
        self.imports = {BASE + plt + 32 + 16 * i: dyn.get_symbol(rel['r_info_sym']).name
                        for i, rel in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())
                        if dyn.get_symbol(rel['r_info_sym'])['st_shndx'] == 'SHN_UNDEF'}
        by_name = {name: at for at, name in self.imports.items()}
        for name in ('.rela.dyn', '.rela.plt'):
            section = elf.get_section_by_name(name)
            if section is None:
                continue
            for rel in section.iter_relocations():
                kind, symbol, add = rel['r_info_type'], dyn.get_symbol(rel['r_info_sym']), rel['r_addend']
                if kind == 1027:
                    value = BASE + add
                elif kind in (257, 1025, 1026):
                    value = (BASE + symbol['st_value'] if symbol['st_shndx'] != 'SHN_UNDEF'
                             else by_name.get(symbol.name, DATA + 0x8000)) + add
                else:
                    raise AssertionError(('relocation', kind))
                u.mem_write(BASE + rel['r_offset'], struct.pack('<Q', value & MASK))
        for at in (STACK, DATA, STOP):
            u.mem_map(at, 0x10000)
        u.mem_map(HEAP, 0x1000000)
        u.mem_write(DATA, struct.pack('<I', 22))
        u.mem_write(DATA + 16, b'fixture\0')
        u.hook_add(UC_HOOK_CODE, self.hook)
        u.hook_add(UC_HOOK_MEM_INVALID, self.invalid)

    def get(self, n):
        return self.u.reg_read(getattr(R, f'UC_ARM64_REG_X{n}'))

    def ret(self, value):
        link = self.get(30)
        for n in range(1, 18):
            self.u.reg_write(getattr(R, f'UC_ARM64_REG_X{n}'), 0xbad000 + n)
        self.u.reg_write(R.UC_ARM64_REG_X0, value & MASK)
        self.u.reg_write(R.UC_ARM64_REG_PC, link)

    def cstr(self, at):
        return bytes(self.u.mem_read(at, 4096)).split(b'\0', 1)[0]

    def alloc(self, size):
        at = self.state['heap']
        self.state['heap'] += (max(size, 1) + 31) & ~31
        assert self.state['heap'] < HEAP + 0x1000000
        self.state['allocations'][at] = size
        return at

    def invalid(self, uc, access, address, size, value, context):
        self.state['invalid'] = dict(address=hex(address), size=size, pc=hex(self.get_pc()))
        return False

    def get_pc(self):
        return self.u.reg_read(R.UC_ARM64_REG_PC)

    def hook(self, uc, address, size, context):
        at = address - BASE
        if address == STOP:
            uc.emu_stop()
            return
        if at == self.reader:
            source, length = self.get(0), self.get(2)
            if APPEND <= source < APPEND + 0x100:
                self.state['metadata'].append([source - APPEND, length])
            else:
                self.state['reads'].append([hex(source), length])
        if at == self.lookup:
            self.state['lookups'].append(self.cstr(self.get(0)).decode())
        if at == self.parser:
            self.state['parser'] += 1
            uc.mem_write(self.get(1), struct.pack('<i', 0x100))
            self.ret(0)
            return
        if at == self.tls_function or self.imports.get(address) == '__emutls_get_address':
            control = self.get(0)
            if control not in self.state['tls']:
                length, alignment, index, template = struct.unpack('<4Q', bytes(uc.mem_read(control, 32)))
                target = self.alloc(length)
                if template:
                    uc.mem_write(target, bytes(uc.mem_read(template, length)))
                self.state['tls'][control] = target
            self.ret(self.state['tls'][control])
            return
        if at == self.execute:
            pointer, length, output = self.get(0), self.get(1), self.get(2)
            code = bytes(uc.mem_read(pointer, length))
            callback = dict(bytes=length, sha256=SHA(code))
            self.state['callbacks'].append(callback)
            if self.config.get('transport_error'):
                self.ret(-19008)
                return
            value = self.kernel(code, callback)
            uc.mem_write(output, struct.pack('<Q', value & MASK))
            self.ret(0)
            return
        name = self.imports.get(address)
        if name is None:
            return
        self.state['imports'].add(name)
        if name in ('malloc', 'calloc', 'realloc', '_Znwm', '_Znam'):
            length = self.get(0) * self.get(1) if name == 'calloc' else self.get(1) if name == 'realloc' else self.get(0)
            target = self.alloc(length)
            if name == 'realloc' and self.get(0):
                uc.mem_write(target, bytes(uc.mem_read(self.get(0), min(length, self.state['allocations'][self.get(0)]))))
            self.ret(target)
        elif name in ('free', '_ZdlPv', '_ZdaPv'):
            self.ret(0)
        elif name in ('memset', 'memcpy', 'memmove', '__memcpy_chk'):
            target, source, length = self.get(0), self.get(1), self.get(2)
            uc.mem_write(target, bytes([source & 255]) * length if name == 'memset' else bytes(uc.mem_read(source, length)))
            self.ret(target)
        elif name == 'memcmp':
            x, y = bytes(uc.mem_read(self.get(0), self.get(2))), bytes(uc.mem_read(self.get(1), self.get(2)))
            self.ret((x > y) - (x < y))
        elif name == 'memchr':
            index = bytes(uc.mem_read(self.get(0), self.get(2))).find(bytes([self.get(1) & 255]))
            self.ret(self.get(0) + index if index >= 0 else 0)
        elif name in ('strncpy', 'strcpy'):
            value = self.cstr(self.get(1))
            value = (value[:self.get(2)] + bytes(max(0, self.get(2) - len(value)))) if name == 'strncpy' else value + b'\0'
            uc.mem_write(self.get(0), value)
            self.ret(self.get(0))
        elif name in ('strlen', '__strlen_chk'):
            self.ret(len(self.cstr(self.get(0))))
        elif name in ('strcmp', 'strncmp'):
            x, y = self.cstr(self.get(0)), self.cstr(self.get(1))
            if name == 'strncmp':
                x, y = x[:self.get(2)], y[:self.get(2)]
            self.ret((x > y) - (x < y))
        elif name == '__cxa_guard_acquire':
            self.ret(int(bytes(uc.mem_read(self.get(0), 1)) == b'\0'))
        elif name == '__cxa_guard_release':
            uc.mem_write(self.get(0), b'\1')
            self.ret(0)
        elif name in ('__cxa_atexit', '__register_atfork', 'pthread_mutex_lock', 'pthread_mutex_unlock',
                      'fprintf', 'printf', 'fflush', 'prctl'):
            self.ret(0)
        elif name == '__vsnprintf_chk':
            fmt = self.cstr(self.get(4)).decode()
            stack, gr, vr, go, vo = struct.unpack('<QQQii', bytes(uc.mem_read(self.get(5), 32)))
            def arg():
                nonlocal stack, go
                if go < 0:
                    at = gr + go
                    go += 8
                else:
                    at = stack
                    stack += 8
                return struct.unpack('<Q', bytes(uc.mem_read(at, 8)))[0]
            def field(match):
                flags, width, precision, length, kind = match.groups()
                if kind == '%':
                    return '%'
                value = arg()
                if kind == 's':
                    rendered = self.cstr(value).decode(errors='replace') if value else '(null)'
                elif kind == 'c':
                    rendered = chr(value & 255)
                elif kind == 'p':
                    rendered = hex(value)
                else:
                    if length not in ('l', 'll', 'z', 'j'):
                        value &= 0xffffffff
                    if kind in ('d', 'i'):
                        value = SIGNED(value) if length in ('l', 'll', 'z', 'j') else value - (1 << 32) if value & (1 << 31) else value
                        rendered = str(value)
                    elif kind == 'u':
                        rendered = str(value)
                    elif kind in ('x', 'X'):
                        rendered = format(value, kind)
                    else:
                        raise AssertionError(('format', kind))
                return rendered.rjust(int(width), '0' if '0' in flags else ' ') if width else rendered
            text = re.sub(r'%([-+#0 ]*)([0-9]*)(?:\.([0-9]+))?(ll|l|z|j|h|hh)?([a-zA-Z%])', field, fmt).encode()
            if self.get(1):
                uc.mem_write(self.get(0), text[:self.get(1) - 1] + b'\0')
            self.ret(len(text))
        elif name in ('getresuid', 'getresgid'):
            for n in range(3):
                if self.get(n):
                    uc.mem_write(self.get(n), bytes(4))
            self.ret(0)
        elif name == '__errno':
            self.ret(DATA)
        elif name == 'strerror':
            self.ret(DATA + 16)
        elif name == 'syscall':
            if self.get(0) in (172, 178):
                self.ret(37)
            else:
                raise AssertionError(('syscall', self.get(0), hex(self.get(30) - BASE)))
        else:
            raise AssertionError(('import', name, hex(self.get(30) - BASE)))

    def kernel(self, code, callback):
        instructions = [ins for offset in range(0, len(code) - 3, 4)
                        for ins in DECODER.disasm(code[offset:offset + 4], KCODE + offset)]
        # Existing SDK discovery callbacks are modeled at the kernel boundary;
        # actual userspace getters, resolver, AsmJit and all read callbacks run.
        has_at = any(i.mnemonic == 'at' for i in instructions)
        has_blr = any(i.mnemonic == 'blr' for i in instructions)
        if not has_at and not has_blr:
            self.state['coldDiscovery'] += 1
            assert self.state['coldDiscovery'] <= 2, ('unexpected discovery callback', len(code))
            callback['kind'] = 'existing-append-discovery'
            return APPEND
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for at in (KCODE, KSTACK, KREQ, KCRED, KSTOP):
            u.mem_map(at, 0x10000)
        for at in (APPEND, SOURCE & ~4095, LOOKUP, NOFAULT):
            u.mem_map(at, 0x2000)
        u.mem_write(KCODE, code)
        meta = bytearray(0x34)
        struct.pack_into('<II', meta, 0, APPEND - KBASE, LOOKUP - KBASE)
        struct.pack_into('<IH', meta, 0x2a, 0x130000, 4)
        struct.pack_into('<I', meta, 0x30, 0x120000)
        u.mem_write(APPEND, bytes(meta))
        u.mem_write(SOURCE, bytes((i * 37 + 11) & 255 for i in range(600)))
        u.reg_write(R.UC_ARM64_REG_SP, KSTACK + 0x8000)
        u.reg_write(R.UC_ARM64_REG_X11, KREQ)
        u.reg_write(R.UC_ARM64_REG_X17, KCRED + 0x10)
        u.reg_write(R.UC_ARM64_REG_X30, KSTOP)
        original = {i: 0xabc000 + i for i in range(19, 30)}
        for i, value in original.items():
            u.reg_write(getattr(R, f'UC_ARM64_REG_X{i}'), value)
        u.reg_write(R.UC_ARM64_REG_PAR_EL1, 0x12345000)
        state = dict(daif=0x80, nativeReads=0, userCopies=0)
        def get(n):
            return u.reg_read(getattr(R, f'UC_ARM64_REG_X{n}'))
        def returned(value):
            link = get(30)
            for n in range(1, 18):
                u.reg_write(getattr(R, f'UC_ARM64_REG_X{n}'), 0xbad000 + n)
            u.reg_write(R.UC_ARM64_REG_X0, value & MASK)
            u.reg_write(R.UC_ARM64_REG_PC, link)
        def hook(uc, pc, size, context):
            if pc == KSTOP:
                uc.emu_stop()
                return
            if pc == LOOKUP:
                name = bytes(uc.mem_read(get(0), 256)).split(b'\0', 1)[0].decode()
                self.state['kernelLookups'].append(name)
                symbols = {'copy_from_kernel_nofault': NOFAULT, 'probe_kernel_read': NOFAULT,
                           '__probe_kernel_read': NOFAULT, 'copy_to_user_nofault': COPY_USER}
                if self.config.get('missing') or (self.config.get('older') and name == 'copy_from_kernel_nofault'):
                    symbols.pop(name, None)
                if self.config.get('raw_only') and name == 'copy_to_user_nofault':
                    symbols.pop(name, None)
                returned(symbols.get(name, 0))
                callback['kind'] = 'kernel-symbol-lookup'
                return
            if pc == NOFAULT:
                state['nativeReads'] += 1
                target, source, length = get(0), get(1), get(2)
                assert 0 < length <= 256
                if self.config.get('fault'):
                    returned(-14)
                elif self.config.get('cross_page') and source == SOURCE:
                    uc.mem_write(target, bytes(uc.mem_read(source, 8)))
                    returned(-14)
                else:
                    uc.mem_write(target, bytes(uc.mem_read(source, length)))
                    returned(0)
                callback['kind'] = 'nofault-read'
                return
            if pc == COPY_USER:
                state['userCopies'] += 1
                target, source, length = get(0), get(1), get(2)
                value = bytes(uc.mem_read(source, length))
                if self.config.get('copy_fault'):
                    self.u.mem_write(target, value[:-1])
                    returned(length - 1)
                else:
                    self.u.mem_write(target, value)
                    returned(0)
                return
            ins = next(DECODER.disasm(bytes(uc.mem_read(pc, 4)), pc))
            if ins.mnemonic == 'mrs' and ins.op_str.endswith(', daif'):
                n = int(ins.op_str.split(',')[0][1:])
                uc.reg_write(getattr(R, f'UC_ARM64_REG_X{n}'), state['daif'])
                uc.reg_write(R.UC_ARM64_REG_PC, pc + 4)
            elif ins.mnemonic == 'msr' and ins.op_str.startswith('daifset,'):
                state['daif'] |= int(ins.op_str.split('#')[1], 0) << 6
                uc.reg_write(R.UC_ARM64_REG_PC, pc + 4)
            elif ins.mnemonic == 'msr' and ins.op_str.startswith('daif,'):
                state['daif'] = get(int(ins.op_str.split('x')[1]))
                uc.reg_write(R.UC_ARM64_REG_PC, pc + 4)
            elif ins.mnemonic == 'at':
                source = get(int(ins.op_str.split('x')[1]))
                assert APPEND <= source < APPEND + 0x34
                allowed = source - APPEND < 8 or source - APPEND >= 0x2a
                assert allowed, 'metadata whitelist widened into path/gap'
                uc.reg_write(R.UC_ARM64_REG_PAR_EL1, int(self.config.get('metadata_fault', False)))
                uc.reg_write(R.UC_ARM64_REG_PC, pc + 4)
                callback['kind'] = 'metadata-bootstrap'
        u.hook_add(UC_HOOK_CODE, hook)
        try:
            u.emu_start(KCODE, KSTOP + 4, count=10000)
        except UcError as error:
            raise AssertionError(('kernel callback', callback, hex(u.reg_read(R.UC_ARM64_REG_PC)))) from error
        assert u.reg_read(R.UC_ARM64_REG_PC) == KSTOP
        assert u.reg_read(R.UC_ARM64_REG_SP) == KSTACK + 0x8000
        assert all(get(i) == value for i, value in original.items())
        assert state['daif'] == 0x80
        assert u.reg_read(R.UC_ARM64_REG_PAR_EL1) == 0x12345000
        callback.update(state)
        return int.from_bytes(u.mem_read(KCRED + 0x11, 6), 'little') | (int.from_bytes(u.mem_read(KCRED + 0x28, 2), 'little') << 48)

    def call(self, source=SOURCE, length=600):
        before = {key: len(self.state[key]) for key in ('callbacks', 'metadata', 'lookups', 'kernelLookups')}
        sp = STACK + 0xf000
        for n, value in ((0, source), (1, DATA + 0x1000), (2, length), (30, STOP)):
            self.u.reg_write(getattr(R, f'UC_ARM64_REG_X{n}'), value)
        self.u.reg_write(R.UC_ARM64_REG_SP, sp)
        for n in range(19, 30):
            self.u.reg_write(getattr(R, f'UC_ARM64_REG_X{n}'), 0x9900 + n)
        try:
            self.u.emu_start(BASE + self.reader, STOP + 4, count=5000000)
        except Exception as error:
            raise AssertionError(('userspace', hex(self.get_pc() - BASE), hex(self.get(30) - BASE), self.state.get('invalid'), str(error))) from error
        assert self.get_pc() == STOP, 'instruction budget exceeded'
        assert self.u.reg_read(R.UC_ARM64_REG_SP) == sp
        assert all(self.get(n) == 0x9900 + n for n in range(19, 30))
        result = SIGNED(self.get(0))
        diff = {key: self.state[key][before[key]:] for key in before}
        if not result and source == SOURCE:
            assert bytes(self.u.mem_read(DATA + 0x1000, length)) == bytes((i * 37 + 11) & 255 for i in range(length))
        return dict(result=result, transportCount=len(diff['callbacks']), metadataRequests=diff['metadata'],
                    lookupCount=len(diff['lookups']), queriedSymbols=diff['lookups'],
                    kernelLookupCount=len(diff['kernelLookups']), kernelSymbols=diff['kernelLookups'],
                    callbacks=diff['callbacks'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--baseline-sdk', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--trace', action='store_true')
    args = parser.parse_args()
    assert bool(args.helper) != bool(args.sdk)
    blob = (args.helper or args.sdk).read_bytes()
    cases = {}
    for name, config in dict(good={}, older={'older': True}, missing={'missing': True},
                             raw_only={'raw_only': True}, fault={'fault': True},
                             cross_page={'cross_page': True}, copy_fault={'copy_fault': True},
                             transport_error={'transport_error': True}, metadata_fault={'metadata_fault': True}).items():
        replay = Replay(blob, bool(args.helper), config)
        first = replay.call()
        expected = 0 if name in ('good', 'older') else -19978 if name in ('missing', 'raw_only') else -19008 if name == 'transport_error' else -19987
        assert first['result'] == expected, (name, first)
        result = dict(passed=True, first=first)
        if name == 'good':
            result['second'] = replay.call()
            assert result['second']['result'] == 0
            assert first['metadataRequests'] == [[0x30, 4], [0, 4], [0x2a, 6], [4, 4]], first
            assert result['second']['metadataRequests'] == []
        cases[name] = result
        print('PASS', name, first['result'], 'transport', first['transportCount'])
        if args.trace:
            print(json.dumps(first, indent=2))
    report = dict(passed=True, actualColdResolver=True, resolverBoundaryMocked=False,
                  kernelDiscoveryBoundaryModeled=True, deviceRequests=False, cases=cases,
                  sources={p.relative_to(ROOT).as_posix(): SHA(p.read_bytes()) for p in
                           (ROOT / 'runtime/ultra/authorization/helper_kernel_read.cpp',
                            ROOT / 'runtime/ultra/authorization/helper_kernel_read.S',
                            ROOT / 'runtime/ultra/authorization/kernel_read_metadata.h', Path(__file__).resolve())})
    report['helperSha256' if args.helper else 'sdkSha256'] = SHA(blob)
    if args.helper:
        report['baselineHelperSha256'] = SHA((ROOT / 'runtime/maplesu-sdk/helper/autorun_bootstrap').read_bytes())
    if args.baseline_sdk:
        old = Replay(args.baseline_sdk.read_bytes(), False, {}).call()
        # The earlier guarded candidate rejects two metadata fields, but the
        # resolver recovers through its remaining descriptor path. It is a
        # compatibility comparison, not the original unsafe command2 baseline.
        assert old['result'] == 0, old
        assert old['metadataRequests'] == [[0x30, 4], [0x2a, 6], [4, 4], [0, 4]], old
        assert sum(item.get('kind') == 'metadata-bootstrap' for item in old['callbacks']) == 2
        report['baseline'] = dict(sha256=SHA(args.baseline_sdk.read_bytes()), cold=old,
                                 guardedMetadataFallback=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
