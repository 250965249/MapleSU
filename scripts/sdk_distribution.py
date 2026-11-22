import hashlib
import io
import json
from pathlib import Path
import re

from ar_archive import parse_ar
from elftools.elf.elffile import ELFFile
from policy_backend_identity import describe_backend
from source_sdk_delivery import source_helper_identity


def checked(root, item):
    root = Path(root).resolve()
    name = item['path']
    path = root / name
    if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError('Invalid SDK distribution path: ' + name)
    if path.stat().st_size != item['size'] or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
        raise ValueError('SDK distribution input changed: ' + name)
    return path


def verify_distribution(manifest, root):
    distribution = manifest['distribution']
    assert distribution['schemaVersion'] == 1
    assert re.fullmatch(r'[0-9a-f]{64}', distribution['producerReleaseSha256'])
    source = json.loads(checked(root, distribution['sourceManifest']).read_bytes())
    assert source['schemaVersion'] == 1 and source['sdkBuildId'] == manifest['sdkBuildId']
    names = [item['path'] for item in source['files']]
    assert len(names) == len(set(names)) == distribution['sourceFiles'] and names
    for item in source['files']:
        checked(root, item)
    for item in distribution['toolchainSources']:
        checked(root, item)
    archive = checked(root, manifest['archive'])
    helper = checked(root, manifest['helper'])
    members = parse_ar(str(archive))['members']
    assert [{key: item[key] for key in ('ord', 'name', 'size', 'sha256')} for item in members] == source['archiveMembers']
    assert len(members) == 260
    entries = [item for item in members if item['name'] == 'maplesu_autorun_bootstrap_install.o']
    assert len(entries) == 1
    entry = entries[0]
    data = archive.read_bytes()
    embedded = ELFFile(io.BytesIO(data[entry['body_offset']:entry['body_offset'] + entry['size']]))
    symbols = [symbol for symbol in embedded.get_section_by_name('.symtab').iter_symbols()
               if symbol.name.endswith('autorun_bootstrap_file_dataE')]
    assert len(symbols) == 1
    symbol = symbols[0]
    section = embedded.get_section(symbol['st_shndx'])
    start = symbol['st_value'] - section['sh_addr']
    assert symbol['st_size'] == helper.stat().st_size
    assert section.data()[start:start + symbol['st_size']] == helper.read_bytes()
    identity = source_helper_identity(helper, {'keySlot': {
        'offset': manifest['helper']['keySlotOffset'], 'capacity': 4096,
        'tokenBytes': 128, 'keyLength': 48,
    }})
    assert all(manifest['helper'][key] == value for key, value in identity.items())
    policy = manifest['environmentPolicyBoot']
    backend = checked(root, policy['backend'])
    actual = describe_backend(backend)
    assert actual == {key: value for key, value in policy['backend'].items() if key != 'path'}
    raw = helper.read_bytes()
    assert actual['fileName'].encode() + b'\0' in raw and bytes.fromhex(actual['noteHex']) in raw
    bundle = checked(root, policy['delivery']['bundleManifest'])
    generated = json.loads(bundle.read_bytes())
    assert hashlib.sha256(bundle.with_suffix('.cpp').read_bytes()).hexdigest() == generated['generatedSourceSha256']
    assert policy['entryHelperSha256'] == identity['sha256']
    return {'sourceFiles': len(names), 'archiveMembers': len(members), 'sdkBuildId': manifest['sdkBuildId']}
