"""Install the additive extension only on its exact captured SDK baseline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

from verify_sdk_member_diff import parse_ar

parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
sdk = root / 'runtime/maplesu-sdk'
build = args.build
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text(encoding='utf-8-sig'))
meta = read(build / 'build.json')
candidate = build / 'libkernel_module_kit_static.a'
archive = sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a'
manifest = read(sdk / 'SDK-RELEASE.json')
assert sha(candidate) == meta['archiveSha256']
assert sha(archive) == manifest['archive']['sha256'], 'SDK manifest changed: inspect before install'
before, after = parse_ar(str(archive)), parse_ar(str(candidate))
baseline_members = before['members']
if sha(archive) != meta['baselineArchiveSha256']:
    assert manifest.get('parasiteExtension', {}).get('baselineArchiveSha256') == meta['baselineArchiveSha256'], 'SDK changed: rebase before install'
    assert baseline_members[-1]['name'] == meta['addedMember']
    baseline_members = baseline_members[:-1]
assert [(m['name'], m['sha256']) for m in after['members'][:-1]] == [
    (m['name'], m['sha256']) for m in baseline_members]
assert after['members'][-1]['name'] == meta['addedMember']
for path, digest in meta['sources'].items():
    assert sha(root / path) == digest, 'Rebuild changed source: ' + path
diff_path = sdk / 'SU-AUTH-MEMBER-DIFF.json'
diff = read(diff_path)
member = after['members'][-1]
diff['archiveSha256'] = meta['archiveSha256']
diff['totalMembers'] = after['member_count']
diff['added'] = [row for row in diff.get('added', []) if row['name'] != meta['addedMember']]
diff['added'].append({'ord': member['ord'], 'name': member['name'], 'candidateSha256': member['sha256']})
diff_path.write_text(json.dumps(diff, indent=2) + '\n')
manifest['sdkBuildId'] = 'maplesu-ultra-5.1.0-parasite-r7-20261105'
manifest['parasiteExtension'] = meta
manifest['archive'].update(sha256=meta['archiveSha256'], size=candidate.stat().st_size)
manifest['memberDiff'].update(sha256=sha(diff_path), added=len(diff['added']))
manifest['statement'] = 'SDK 5.1.0: existing Panic/module-control/su repairs retained byte-for-byte; additive parasite extension, device acceptance pending.'
(sdk / 'SDK-RELEASE.json').write_text(json.dumps(manifest, indent=2) + '\n')
identity = sdk / 'SDK-IDENTITY.cmake'
text = identity.read_text()
for name, value in [('MAPLESU_ULTRA_SDK_BUILD_ID', manifest['sdkBuildId']), ('MAPLESU_ULTRA_SDK_SHA256', meta['archiveSha256'])]:
    text = re.sub(r'set\(' + name + r' "[^"]*"\)', f'set({name} "{value}")', text)
identity.write_text(text)
shutil.copy2(candidate, archive)
print('Installed additive SDK:', meta['archiveSha256'])
