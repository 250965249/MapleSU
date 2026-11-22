"""Preserve compiler objects and losslessly expand their debug sections."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys

import struct


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def semantics(path):
    data = path.read_bytes()
    if data.startswith(b'!<thin>\n'):
        if path.name != 'msu_manager_claim.o':
            raise ValueError('Unexpected thin archive name')
        at, names, members, symbols, headers = 8, None, [], [], set()
        while at < len(data):
            headers.add(at)
            header = data[at:at + 60]
            if len(header) != 60 or header[58:60] != b'`\n':
                raise ValueError('Invalid actual thin archive member header')
            label = header[:16].decode('ascii').strip()
            size = int(header[48:58].decode('ascii').strip())
            if size < 0:
                raise ValueError('Invalid actual thin archive member size')
            at += 60
            if label in ('/', '//'):
                body = data[at:at + size]
                if len(body) != size:
                    raise ValueError('Truncated actual thin archive table')
                if label == '//':
                    names = body
                else:
                    if size < 4:
                        raise ValueError('Truncated actual thin archive symbol count')
                    count = int.from_bytes(body[:4], 'big')
                    if count > (size - 4) // 4:
                        raise ValueError('Invalid actual thin archive symbol count')
                    symbols.extend(int.from_bytes(body[pos:pos + 4], 'big') for pos in range(4, 4 + count * 4, 4))
                at += size + size % 2
            else:
                if not label.startswith('/') or not label[1:].isdigit() or names is None:
                    raise ValueError('Invalid actual thin archive member reference')
                offset = int(label[1:])
                end = names.find(b'/\n', offset)
                if offset >= len(names) or end < 0:
                    raise ValueError('Thin archive member name outside actual table')
                member = Path(names[offset:end].decode())
                if member.parent != path.parent or member.suffix != '.o' or member.name == path.name or member.name in members:
                    raise ValueError('Thin archive member outside exact aggregate object set')
                members.append(member.name)
        if at != len(data) or not members or any(position not in headers for position in symbols):
            raise ValueError('Invalid actual thin archive extent or symbol index')
        return hashlib.sha256(b'thin-archive-container\0' + data).hexdigest()

    def raw(offset, size):
        if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
            raise ValueError('ELF byte range outside actual object: ' + str(path))
        return data[offset:offset + size]

    def unpack(layout, offset):
        return struct.unpack(layout, raw(offset, struct.calcsize(layout)))

    header = unpack('<16sHHIQQQIHHHHHH', 0)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, names = header
    if ident[:6] != b'\x7fELF\x02\x01' or kind != 1 or machine != 183 or ehsize != 64 or shsize != 64 or not shnum:
        raise ValueError('Expected actual ELF64 little-endian AArch64 compiler object: ' + str(path))
    headers = [unpack('<IIQQQQIIQQ', shoff + index * shsize) for index in range(shnum)]
    if names >= shnum:
        raise ValueError('ELF section names index outside actual table')

    def section_data(index):
        section = headers[index]
        return bytes(section[5]) if section[1] == 8 else raw(section[4], section[5])

    def string(table, offset):
        end = table.find(b'\0', offset)
        if offset < 0 or end < 0:
            raise ValueError('ELF name outside actual string table')
        return table[offset:end].decode('utf-8', 'surrogateescape')

    name_table = section_data(names)
    section_names = [string(name_table, section[0]) for section in headers]
    tables, symbols, allocated, relocations, loads = {}, [], [], [], []
    for index, section in enumerate(headers):
        _, stype, sflags, address, offset, size, link, info, alignment, entsize = section
        if sflags & 2:
            allocated.append((section_names[index], stype, sflags, address, size, alignment,
                entsize, hashlib.sha256(section_data(index)).hexdigest()))
        if stype not in (2, 11):
            continue
        if entsize != 24 or size % entsize or link >= shnum:
            raise ValueError('Invalid actual ELF symbol table')
        strings, rows = section_data(link), []
        for position in range(offset, offset + size, entsize):
            name, sinfo, other, destination, value, width = unpack('<IBBHQQ', position)
            label = string(strings, name)
            if 0 < destination < shnum:
                destination = section_names[destination]
            row = (label, value, width, sinfo, other, destination)
            rows.append(row)
            symbols.append((section_names[index], *row))
        tables[index] = rows
    for index, section in enumerate(headers):
        _, stype, _, _, offset, size, link, info, _, entsize = section
        if stype not in (4, 9):
            continue
        width = 24 if stype == 4 else 16
        if entsize != width or size % width or link not in tables or info >= shnum:
            raise ValueError('Invalid actual ELF relocation table')
        for position in range(offset, offset + size, width):
            row = unpack('<QQq' if stype == 4 else '<QQ', position)
            target, combined, addend = (*row, None) if stype == 9 else row
            symbol, relocation_type = combined >> 32, combined & 0xffffffff
            if symbol >= len(tables[link]):
                raise ValueError('ELF relocation symbol outside actual table')
            relocations.append((section_names[index], section_names[info], target,
                relocation_type, tables[link][symbol][0], addend))
    if phnum and phsize != 56:
        raise ValueError('Invalid actual ELF program header width')
    for position in range(phoff, phoff + phnum * phsize, phsize or 1):
        ptype, pflags, offset, virtual, physical, size, memory, alignment = unpack('<IIQQQQQQ', position)
        if ptype == 1:
            loads.append((ptype, virtual, physical, size, memory, pflags, alignment,
                hashlib.sha256(raw(offset, size)).hexdigest()))
    record = dict(header=(kind, machine, version, entry, flags), allocated=allocated,
        symbols=symbols, relocations=relocations, loadSegments=loads)
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


def main():
    target = Path(sys.argv[1])
    archive = target / 'compiler-objects'
    archive.mkdir(exist_ok=True)
    executable = Path(shutil.which('llvm-objcopy')).resolve()
    records = []
    for path in sorted(target.glob('*.o')):
        command = target / ('.' + path.name + '.cmd')
        if not command.is_file():
            continue
        saved = archive / path.name
        if saved.exists():
            raise ValueError('Compiler object archive already exists: ' + str(saved))
        before, expected = identity(path), semantics(path)
        shutil.copyfile(path, saved)
        if identity(saved)['sha256'] != before['sha256']:
            raise ValueError('Compiler object changed during preservation: ' + str(path))
        thin = path.read_bytes().startswith(b'!<thin>\n')
        argv = [] if thin else [str(executable), '--decompress-debug-sections', str(path)]
        if argv:
            subprocess.run(argv, check=True)
        actual = semantics(path)
        if actual != expected:
            raise ValueError('Debug decompression changed allocated, load, symbol, relocation or CFI bytes: ' + str(path))
        records.append(dict(object=path.stem, compilerOutput=before, archivedCompilerOutput=identity(saved),
            output=identity(path), compilerCommand=identity(command), transformCommand=argv,
            semanticsBeforeSha256=expected, semanticsAfterSha256=actual,
            allocatedLoadSymbolRelocationCfiUnchanged=True))
    receipt = dict(schema='maplesu-object-debug-transformation/1',
        tool=identity(executable), transformer=identity(Path(__file__)), objects=records)
    (target / 'debug-transformations.json').write_text(json.dumps(receipt, indent=2)+'\n')


if __name__ == '__main__':
    main()
