"""Read bounded AVB evidence from the three frozen r2 footer failures; never modify images."""
from pathlib import Path
import argparse
import hashlib
import json
import mmap
import re
import struct

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'docs/dual-mode/impl/_work/2026-11-15-p2/evidence'
LIFECYCLE = EVIDENCE / 'embedded-real-lifecycle-r2/lifecycle/LIFECYCLE.json'
UPSTREAM = EVIDENCE / 'ramdisk-codecs-avb-r1/red-avb/upstream-reference/avbtool.py'


def identity(path):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, offset, endian='>'):
    return struct.unpack_from(endian + 'I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('>Q', data, offset)[0]


def align(value, page=4096):
    return (value + page - 1) // page * page


def parse_vbmeta(image, offset, limit):
    errors = []
    record = {'offset': offset}
    if offset < 0 or offset + 256 > limit:
        return record | {'complete': False, 'errors': ['HEADER_RANGE']}
    header = image[offset:offset + 256]
    if header[:4] != b'AVB0':
        return record | {'complete': False, 'errors': ['MAGIC']}
    auth, aux, algorithm = u64(header, 12), u64(header, 20), u32(header, 28)
    size = 256 + auth + aux
    record.update(bytes=size, algorithm=algorithm, authBytes=auth, auxBytes=aux,
                  requiredVersion=[u32(header, 4), u32(header, 8)], flags=u32(header, 120),
                  rollbackIndex=u64(header, 112), rollbackIndexLocation=u32(header, 124),
                  release=header[128:176].split(b'\0')[0].decode('ascii', 'replace'))
    if auth % 64 or aux % 64:
        errors.append('BLOCK_ALIGNMENT')
    if size > limit - offset or size > 1024 * 1024:
        return record | {'complete': False, 'errors': errors + ['TOTAL_RANGE_OR_AUDIT_CAP']}
    blob = image[offset:offset + size]
    record['sha256'] = sha(blob)
    record['reservedZero'] = not any(header[176:256])
    for field, block in ((32, auth), (48, auth), (64, aux), (80, aux), (96, aux)):
        start, length = u64(header, field), u64(header, field + 8)
        if start > block or length > block - start:
            errors.append('REGION_' + str(field))
    if errors:
        return record | {'complete': False, 'errors': errors}
    aux_start = 256 + auth
    cursor = aux_start + u64(header, 96)
    end = cursor + u64(header, 104)
    descriptors = []
    while cursor < end:
        if end - cursor < 16:
            errors.append('DESCRIPTOR_HEADER_RANGE')
            break
        tag, following = u64(blob, cursor), u64(blob, cursor + 8)
        length = 16 + following
        if following % 8 or length > end - cursor:
            errors.append('DESCRIPTOR_LENGTH')
            break
        desc = blob[cursor:cursor + length]
        item = {'tag': tag, 'offset': offset + cursor, 'bytes': length, 'sha256': sha(desc)}
        if tag == 2:
            if length < 132:
                errors.append('HASH_DESCRIPTOR_FIXED_RANGE')
            else:
                image_size, hash_name = u64(desc, 16), desc[24:56].split(b'\0')[0].decode('ascii', 'replace')
                name_len, salt_len, digest_len = (u32(desc, field) for field in (56, 60, 64))
                required = 132 + name_len + salt_len + digest_len
                if align(required, 8) != length:
                    errors.append('HASH_DESCRIPTOR_VARIABLE_RANGE')
                else:
                    name = desc[132:132 + name_len].decode('utf-8', 'replace')
                    salt = desc[132 + name_len:132 + name_len + salt_len]
                    digest = desc[132 + name_len + salt_len:required]
                    item.update(imageSize=image_size, hashAlgorithm=hash_name, partitionName=name,
                                saltHex=salt.hex(), digestHex=digest.hex(), flags=u32(desc, 68))
                    if hash_name in ('sha256', 'sha512') and image_size <= len(image):
                        check = hashlib.new(hash_name, salt)
                        check.update(memoryview(image)[:image_size])
                        item['coveredImageDigestMatches'] = check.digest() == digest
        descriptors.append(item)
        cursor += length
    record['descriptors'] = descriptors
    record['descriptorBoundaryExact'] = cursor == end
    record['complete'] = not errors
    record['errors'] = errors
    if algorithm in range(1, 7):
        hash_name = 'sha256' if algorithm <= 3 else 'sha512'
        digest = hashlib.new(hash_name, header + blob[aux_start:]).digest()
        saved = blob[256 + u64(header, 32):256 + u64(header, 32) + u64(header, 40)]
        record['authenticationHashMatches'] = saved == digest
        sig = blob[256 + u64(header, 48):256 + u64(header, 48) + u64(header, 56)]
        key = blob[aux_start + u64(header, 64):aux_start + u64(header, 64) + u64(header, 72)]
        if len(key) >= 8:
            bits = u32(key, 0)
            width = bits // 8
            record['rsaKeyBits'] = bits
            record['signatureBytes'] = len(sig)
            record['publicKeyBytes'] = len(key)
            if bits in (2048, 4096, 8192) and len(key) == 8 + 2 * width and len(sig) == width:
                modulus = int.from_bytes(key[8:8 + width], 'big')
                encoded = pow(int.from_bytes(sig, 'big'), 65537, modulus).to_bytes(width, 'big')
                prefix = bytes.fromhex('3031300d060960864801650304020105000420' if hash_name == 'sha256'
                                       else '3051300d060960864801650304020305000440')
                expected = b'\x00\x01' + b'\xff' * (width - len(prefix) - len(digest) - 3) + b'\x00' + prefix + digest
                record['rsaSignatureMatchesHeaderAndAuxiliary'] = encoded == expected
    return record


def audit(case, out, role):
    source = Path(case['input']['path'])
    stat = source.stat()
    record = {'role': role, 'expectedInput': case['input'], 'rangesRead': [], 'candidates': []}
    with source.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as image:
        actual = {'path': str(source), 'bytes': len(image), 'sha256': sha(image)}
        assert actual == case['input'], 'input differs from frozen r2'
        record['input'] = actual
        header, footer = image[:1584], image[-64:]
        assert header[:8] == b'ANDROID!' and u32(header, 40, '<') == 4
        kernel_size, ramdisk_size = u32(header, 8, '<'), u32(header, 12, '<')
        ramdisk_at = 4096 + align(kernel_size)
        signature_at = ramdisk_at + align(ramdisk_size)
        signature_size = u32(header, 1580, '<')
        body_end = align(signature_at + signature_size)
        record['header'] = {'headerVersion': 4, 'kernelOffset': 4096, 'kernelSize': kernel_size,
            'ramdiskOffset': ramdisk_at, 'ramdiskSize': ramdisk_size, 'signatureOffset': signature_at,
            'signatureSize': signature_size, 'bodyEnd': body_end, 'sha256': sha(header)}
        assert footer[:4] == b'AVBf'
        original, vbmeta_at, vbmeta_size = (u64(footer, field) for field in (12, 20, 28))
        record['footer'] = {'offset': len(image) - 64, 'hex': footer.hex(), 'version': [u32(footer, 4), u32(footer, 8)],
            'originalImageSize': original, 'vbmetaOffset': vbmeta_at, 'vbmetaSize': vbmeta_size,
            'reservedZero': not any(footer[36:]), 'originalSizeBeforeBodyEnd': original < body_end,
            'vbmetaInsideKernel': 4096 <= vbmeta_at < 4096 + kernel_size}
        (out / (role + '-header.bin')).write_bytes(header)
        (out / (role + '-footer.bin')).write_bytes(footer)
        windows = [('footer-declared-vbmeta', vbmeta_at, min(vbmeta_size, 4096)),
                   ('bodyEnd', body_end, 256)]
        record['windows'] = []
        for label, start, length in windows:
            if 0 <= start <= len(image) - length:
                raw = image[start:start + length]
                path = out / (role + '-' + label + '.bin')
                path.write_bytes(raw)
                record['windows'].append({'label': label, 'offset': start, 'bytes': length,
                    'sha256': sha(raw), 'head64Hex': raw[:64].hex(), 'file': path.name})
        record['declaredVbmeta'] = parse_vbmeta(image, vbmeta_at, len(image) - 64)
        tail_end = len(image) - 64
        record['tail'] = {'start': body_end, 'end': tail_end,
            'bytes': tail_end - body_end, 'sha256': sha(memoryview(image)[body_end:tail_end]),
            'magicSearchRange': [body_end, tail_end], 'fullImageSearchPerformed': False}
        runs = list(re.compile(b'[^\x00]+').finditer(image, body_end, tail_end))
        record['tail']['nonzeroBytes'] = sum(match.end() - match.start() for match in runs)
        record['tail']['nonzeroRuns'] = [{'start': match.start(), 'end': match.end()} for match in runs[:256]]
        record['tail']['allNonzeroRunsRecorded'] = len(runs) <= 256
        position = body_end
        while True:
            position = image.find(b'AVB0', position, tail_end)
            if position < 0:
                break
            candidate = parse_vbmeta(image, position, tail_end)
            if candidate['complete']:
                path = out / (role + '-vbmeta-' + str(position) + '.bin')
                path.write_bytes(image[position:position + candidate['bytes']])
                candidate['file'] = path.name
            record['candidates'].append(candidate)
            position += 4
        record['rangesRead'] = [{'purpose': 'boot header', 'start': 0, 'end': 1584},
            {'purpose': 'partition footer', 'start': tail_end, 'end': len(image)},
            {'purpose': 'original footer position', 'start': vbmeta_at, 'end': vbmeta_at + min(vbmeta_size, 4096)},
            {'purpose': 'current post-component tail only', 'start': body_end, 'end': tail_end}]
        record['identityHashRange'] = [0, len(image)]
    after = source.stat()
    record['statUnchanged'] = (stat.st_size, stat.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cases', type=int, nargs='+', default=[2, 8, 9],
                        help='Explicit indices in the frozen r2 inventory; no directory discovery.')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    frozen = json.loads(LIFECYCLE.read_text('utf-8-sig'))
    receipt = {'schema': 'maplesu-invalid-avb-tail-audit/1', 'runner': identity(__file__),
        'frozenLifecycle': identity(LIFECYCLE), 'formatReference': identity(UPSTREAM),
        'productionModified': False, 'deviceTest': False, 'partitionWrites': False,
        'decompressionPerformed': False, 'rawKernelFilesCreated': False, 'cases': []}
    for number in args.cases:
        assert 1 <= number <= len(frozen['cases'])
        receipt['cases'].append(audit(frozen['cases'][number - 1], args.out, f'case-{number:02}'))
    (args.out / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps([{'role': case['role'], 'bodyEnd': case['header']['bodyEnd'],
        'footerOriginalImageSize': case['footer']['originalImageSize'],
        'footerVbmetaOffset': case['footer']['vbmetaOffset'], 'footerVbmetaSize': case['footer']['vbmetaSize'],
        'tailNonzeroBytes': case['tail']['nonzeroBytes'], 'vbmetaCandidates': len(case['candidates']),
        'completeVbmetaCandidates': sum(item['complete'] for item in case['candidates'])}
        for case in receipt['cases']], indent=2))


if __name__ == '__main__':
    main()
