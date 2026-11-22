"""Verify the actual packaged ARM64 ELF load segments on 16 KB Android pages."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile

from elftools.elf.elffile import ELFFile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    with zipfile.ZipFile(args.apk) as package:
        for name in package.namelist():
            if not name.startswith('lib/arm64-v8a/') or not name.endswith('.so'):
                continue
            data = package.read(name)
            elf = ELFFile(io.BytesIO(data))
            segments = [dict(offset=s['p_offset'], address=s['p_vaddr'], alignment=s['p_align'])
                        for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
            passed = bool(segments) and elf['e_machine'] == 'EM_AARCH64' and all(
                s['alignment'] >= 16384 and (s['address'] - s['offset']) % 16384 == 0
                for s in segments)
            rows.append(dict(path=name, sha256=hashlib.sha256(data).hexdigest(),
                             passed=passed, segments=segments))
    report = dict(apk=str(args.apk.resolve()), apkSha256=hashlib.sha256(args.apk.read_bytes()).hexdigest(),
                  pageBytes=16384, passed=bool(rows) and all(r['passed'] for r in rows), results=rows,
                  scope='Packaged ARM64 ELF files; embedded SDK executables require separate verification')
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checked=len(rows),
                         failed=[r['path'] for r in rows if not r['passed']])))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
