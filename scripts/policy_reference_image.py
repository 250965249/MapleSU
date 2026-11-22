"""Read an actual SHA-bound arm64 Image as reference ABI input.

This adapter preserves the original raw format. Kallsyms intervals are upper
bounds, never represented as original ELF symbol sizes or section headers.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from policy_payload_image_target import capture_image
from policy_btf_abi import Btf


def sha(data):
    return hashlib.sha256(data).hexdigest()


def config_symbols(data):
    values = {}
    for line in data.decode().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        else:
            item = re.fullmatch(r'# (CONFIG_[A-Za-z0-9_]+) is not set', line)
            if not item:
                continue
            key, value = item[1], 'n'
        if key in values and values[key] != value:
            raise ValueError('Conflicting actual config symbol: ' + key)
        values[key] = value
    enabled = {key: value for key, value in values.items() if value != 'n'}
    return sha(json.dumps(enabled, sort_keys=True, separators=(',', ':')).encode())


def extract(contract_path, selection, output, source):
    # Reuse the existing exact-Image decoder, which verifies original bytes,
    # release, all persisted TSV entries, embedded BTF/config and GNU notes.
    capture_image(contract_path, output, source)
    contract = json.loads(contract_path.read_text())
    root = Path(__file__).resolve().parents[1]
    image_path = root / contract['imagePath']
    image = image_path.read_bytes()
    if len(image) != contract['imageBytes'] or sha(image) != contract['imageSha256']:
        raise ValueError('Raw reference Image changed during extraction')
    wanted = set(json.loads(selection.read_text()))
    mapping = output / 'raw-image-metadata'
    map_data = (mapping / 'System.map').read_bytes()
    btf_data = (output / 'vmlinux.btf').read_bytes()
    btf = Btf(btf_data)
    rows, by_name = [], {}
    for ordinal, line in enumerate(map_data.decode().splitlines()):
        address, code, name = line.split()
        row = dict(address=int(address, 16), code=code, name=name, ordinal=ordinal)
        rows.append(row)
        by_name.setdefault(name, []).append(row)

    def address(name):
        values = {item['address'] for item in by_name.get(name, [])}
        if len(values) != 1:
            raise ValueError('Missing/ambiguous actual raw linker boundary: ' + name)
        return values.pop()

    base = address('_text')
    end = address('_end')
    if end < base + len(image):
        raise ValueError('Actual raw allocation boundary truncates Image')
    ordered = sorted({item['address'] for item in rows} | {end})
    region_data = json.dumps(dict(base=base, fileEnd=base + len(image), allocationEnd=end), sort_keys=True).encode()
    config = (mapping / '.config').read_bytes()
    source_identity = dict(sourceFormat='raw-arm64-image', vmlinuxPath=None, imagePath=str(image_path),
        imageSha256=sha(image), sourceFileBytes=len(image), contractPath=str(contract_path),
        contractSha256=sha(contract_path.read_bytes()), btfSha256=sha(btf_data), btfBytes=len(btf_data),
        symtabFormat='actual-image-full-kallsyms-text', symtabSha256=sha(map_data),
        symstrSha256=sha(map_data), sectionHeadersFormat='actual-linker-allocation-boundaries',
        sectionHeadersSha256=sha(region_data), rawAllocation=dict(base=base, end=end),
        configPath=str(mapping / '.config'), configBytes=len(config), configSha256=sha(config),
        configSymbolsSha256=config_symbols(config), moduleSymversAvailable=False)
    extents, selected, markers, core, objects = {}, [], {}, {}, {}
    for row in rows:
        name, start, code = row['name'], row['address'], row['code']
        if name not in wanted:
            continue
        kind = 'FUNC' if code in 'tTwW' else 'OBJECT' if code in 'rRdDbBsSvV' else None
        if kind is None or not base <= start < end:
            continue
        stop_at = bisect.bisect_right(ordered, start)
        stop = ordered[stop_at] if stop_at < len(ordered) else end
        upper = stop - start
        if upper <= 0 or kind == 'FUNC' and (start % 4 or start - base + 4 > len(image)):
            raise ValueError('Invalid actual raw symbol boundary: ' + name)
        size = upper
        exact, declaration = False, None
        if kind == 'OBJECT' and btf.variables.get(name):
            sizes = {btf.type_size(btf.types[index][3]) for index in btf.variables[name]}
            if len(sizes) != 1 or not 0 < next(iter(sizes)) <= upper:
                raise ValueError('Actual raw BTF object exceeds kallsyms interval: ' + name)
            size, exact, declaration = sizes.pop(), True, 'actual-image-BTF-VAR'
        extent = dict(kind=kind, address=start, bytes=size, symbolIndex=row['ordinal'],
            sectionIndex=1, section='raw.Image.text' if kind == 'FUNC' else 'raw.Image.data',
            sectionAddress=base, sectionBytes=end-base, sectionFlags=6 if kind == 'FUNC' else 2,
            sectionType=8 if start-base >= len(image) else 1, sourceFormat='raw-arm64-image',
            kallsymsType=code, extentExact=exact, boundaryUpperBoundBytes=upper,
            extentProvenance=declaration or 'next-distinct-actual-kallsyms-address-upper-bound',
            flagsProvenance='actual-kallsyms-symbol-kind; not original ELF section flags')
        offset = start-base
        if kind == 'FUNC' and offset >= 4:
            prefix = image[offset-4:offset]
            extent.update(prefixWord=struct.unpack('<I', prefix)[0], prefixBytesSha256=sha(prefix))
        extents.setdefault(name, []).append(extent)
        selected.append('%d: %016x %d %s 0 0 1 %s' % (row['ordinal'], start, size, kind, name))
        if kind == 'FUNC':
            marker = dict(available=True, function=name, address=start, symbolIndex=row['ordinal'],
                functionBytes=size, section=extent['section'], sectionAddress=base,
                sectionBytes=end-base, sectionFlags=6, fileOffset=offset,
                extentExact=False, extentProvenance=extent['extentProvenance'], sourceFormat='raw-arm64-image')
            if offset >= 4:
                marker.update(prefixAddress=start-4, prefixFileOffset=offset-4,
                    prefixWord=extent['prefixWord'], prefixBytesSha256=extent['prefixBytesSha256'])
            core[name] = marker
            if name == 'proc_pid_attr_write':
                markers[name] = marker
        else:
            objects[name] = dict(available=exact, name=name, address=start, bytes=size,
                symbolIndex=row['ordinal'], section=extent['section'], sectionAddress=base,
                sectionBytes=end-base, sectionFlags=2, sectionType=extent['sectionType'],
                fileOffset=None if extent['sectionType'] == 8 else offset,
                extentExact=exact, boundaryUpperBoundBytes=upper,
                extentProvenance=extent['extentProvenance'], sourceFormat='raw-arm64-image',
                reason=None if exact else 'Requires actual same-target declaration type size')
    source_identity['selectedSymbolRows'] = len(selected)
    (output / 'reference.btf').write_bytes(btf_data)
    (output / 'reference.symbols').write_text('\n'.join(selected) + '\n')
    (output / 'reference-source.json').write_text(json.dumps(source_identity, indent=2) + '\n')
    (output / 'reference-symbol-extents.json').write_text(json.dumps(extents, indent=2) + '\n')
    (output / 'reference-function-markers.json').write_text(json.dumps(dict(schemaVersion=1,
        sourceBinding={key: source_identity[key] for key in
            ('sourceFileBytes', 'btfSha256', 'symtabSha256', 'sectionHeadersSha256')},
        markers=markers, coreMarkers=core, suDataMarkers=objects), indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kernel-source', type=Path, required=True)
    args = parser.parse_args()
    extract(args.contract, args.selection, args.output, args.kernel_source)
