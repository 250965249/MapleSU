"""Check the production manifest rejects modified reference native member inputs."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'runtime/maplesu-sdk/sdk/tools'))
import gen_manifest as G
sys.path.insert(0, str(ROOT / 'runtime/maplesu-sdk/sdk'))
import build as B

source = ROOT / 'runtime/maplesu-sdk/sdk/manifest/0073_patch_avc_denied.o.json'
record = json.loads(source.read_text(encoding='utf-8'))
assert record['kind'] == 'FROM_IR' and record['sources'] == ['reference/native/patch_avc_denied.bc']
reference = G.RefIndex.build({73: dict(idx=73, name=record['name'], **record['original'], layout='bitcode')})


def errors(value):
    _, issues = G.validate_record(value, str(source), reference)
    return [issue.code for issue in issues if issue.level == 'error']


assert not errors(record), errors(record)
for field, value, expected in (
    ('sha256', '0' * 64, 'reference-input-mismatch'),
    ('bytes', record['referenceInput']['bytes'] + 1, 'reference-input-mismatch'),
    ('sha256', 'malformed', 'bad-reference-input'),
):
    changed = copy.deepcopy(record)
    changed['referenceInput'][field] = value
    assert expected in errors(changed), errors(changed)
changed = copy.deepcopy(record)
changed['sources'].append('src/patch/patch_avc_denied.cpp')
assert 'bad-reference-input' in errors(changed), errors(changed)
changed = copy.deepcopy(record)
changed['sources'] = ['src/patch/patch_avc_denied.cpp']
assert 'reference-input-mismatch' in errors(changed), errors(changed)

normalized, issues = G.validate_record(record, str(source), reference)
assert not [issue for issue in issues if issue.level == 'error']
assert normalized.to_jsonl()['referenceInput'] == record['referenceInput']
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    manifest = root / 'manifest.jsonl'
    manifest.write_text(json.dumps(normalized.to_jsonl()) + '\n', encoding='utf-8')
    entries, _ = B.load_manifest(manifest, allow_partial=True)
    assert len(entries) == 1 and entries[0].reference_input == record['referenceInput']
    assert G.reference_input_error(entries[0].reference_input, entries[0].sources) is None
    copied = root / 'reference.bc'
    copied.write_bytes(entries[0].sources[0].read_bytes())
    entries[0].sources = [copied]
    assert G.reference_input_error(entries[0].reference_input, entries[0].sources) is None
    # Modify after loading; direct compilation must reject before invoking clang.
    for payload in (b'X' + copied.read_bytes()[1:], b'truncated'):
        copied.write_bytes(payload)
        with patch.object(B, 'OBJ_DIR', root / 'obj'), patch.object(B, 'TU_DIR', root / 'tu'), \
                patch.object(B.S, 'run') as run:
            try:
                B.stage_compile(entries, None, SimpleNamespace(jobs=1), {}, None)
            except B.StageError as exc:
                assert exc.code == B.EXIT_COMPILE and 'reference-input-mismatch' in str(exc)
            else:
                raise AssertionError('changed reference reached the compiler')
            run.assert_not_called()
for value in (0, -1, True, '593776'):
    assert G.reference_input_error(dict(record['referenceInput'], bytes=value),
                                   [G.resolve_source(record['sources'][0])])[0] == 'bad-reference-input'
print('PASS native reference pin: original accepted; metadata round-trip retained; hash/size/schema/source changes rejected before compile')
