"""Install a verified module-control candidate without dropping parallel SDK repairs."""
import argparse,hashlib,json,re,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_sdk_member_diff import parse_ar,compare_members
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[1];sdk=root/'runtime/maplesu-sdk';build=a.build
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
meta=read(build/'build.json');archive=sdk/'lib/arm64-v8a/libkernel_module_kit_static.a';manifest=read(sdk/'SDK-RELEASE.json')
assert sha(build/'libkernel_module_kit_static.a')==meta['archiveSha256']
assert sha(archive)==manifest['archive']['sha256']
assert sha(archive)==meta['baselineArchiveSha256'] or (
 manifest.get('moduleControl',{}).get('baselineArchiveSha256')==meta['baselineArchiveSha256'] and
 manifest['sdkBuildId'].startswith('maplesu-ultra-5.1.0-module-control-')),'SDK baseline changed; rebase first'
old=parse_ar(str(root/'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'));new=parse_ar(str(build/'libkernel_module_kit_static.a'))
assert len(new['members'])==old['member_count']+1 and new['members'][-1]['name']=='maplesu_module_control.o'
common={**new,'members':new['members'][:-1],'member_count':old['member_count']};diff=compare_members(old,common);assert not diff['removed'] and not diff['orderErrors']
last=new['members'][-1];diff['added']=[{'ord':last['ord'],'name':last['name'],'candidateSha256':last['sha256']}]
doc={'schemaVersion':1,'baselineArchiveSha256':old['file_sha256'],'archiveSha256':meta['archiveSha256'],'totalMembers':new['member_count'],**diff}
(sdk/'SU-AUTH-MEMBER-DIFF.json').write_text(json.dumps(doc,indent=2)+'\n')
manifest['sdkBuildId']='maplesu-ultra-5.1.0-module-control-r6-20261105';manifest['moduleControl']=meta
manifest['moduleControl']['semantics']='Atomic desired boot state; installed-helper gate verified; legacy ABI retained; immediate stop unsupported.'
manifest['archive'].update(sha256=meta['archiveSha256'],size=(build/'libkernel_module_kit_static.a').stat().st_size)
for k in ['bootstrap','helper']:manifest[k].update(sha256=meta['helperSha256'],buildId=meta['helperBuildId'],size=meta['helperBytes'],changed=True)
manifest['helper']['normalizedSha256']=meta['helperNormalizedSha256']
manifest['statement']='SDK 5.1.0 Panic and native module-control candidate; offline validation and device acceptance are separate gates.'
manifest['memberDiff'].update(sha256=sha(sdk/'SU-AUTH-MEMBER-DIFF.json'),changed=len(diff['changed']),added=1,removed=0)
for row in diff['changed']:
 entry=next((x for x in manifest['repairs'] if x['memberOrdinal']==row['ord']),None)
 if entry is None:
  entry={'id':'m%03d'%row['ord'],'memberOrdinal':row['ord'],'memberName':row['name']};manifest['repairs'].append(entry)
 entry['sha256']=row['candidateSha256']
(sdk/'SDK-RELEASE.json').write_text(json.dumps(manifest,indent=2)+'\n')
p=sdk/'SDK-IDENTITY.cmake';text=p.read_text();values={'MAPLESU_ULTRA_SDK_BUILD_ID':manifest['sdkBuildId'],'MAPLESU_ULTRA_SDK_SHA256':meta['archiveSha256'],'MAPLESU_ULTRA_HELPER_SHA256':meta['helperNormalizedSha256'],'MAPLESU_ULTRA_HELPER_BUILD_ID':meta['helperBuildId']}
for key,value in values.items():text=re.sub(r'set\('+key+r' "[^"]*"\)',f'set({key} "{value}")',text)
p.write_text(text);shutil.copy2(build/'libkernel_module_kit_static.a',archive)
print('Installed SDK candidate',meta['archiveSha256'])
