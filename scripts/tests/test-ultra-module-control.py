import argparse,hashlib,io,json,subprocess
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[2];build=a.build.resolve();build.mkdir(parents=True,exist_ok=True)
# Derive the generated gate identity from the delivered SDK, so a clean source
# checkout does not depend on a previous repair script's private build directory.
sdk=root/'runtime/maplesu-sdk'
release=json.loads((sdk/'SDK-RELEASE.json').read_text())
archive=sdk/'lib/arm64-v8a/libkernel_module_kit_static.a'
raw=archive.read_bytes()
assert hashlib.sha256(raw).hexdigest()==release['archive']['sha256']
member=next(row for row in parse_ar(str(archive))['members'] if row['name']=='maplesu_autorun_bootstrap_install.o')
obj=ELFFile(io.BytesIO(raw[member['body_offset']:member['body_offset']+member['size']]))
helper=obj.get_section_by_name('.data').data()
assert hashlib.sha256(helper).hexdigest()==release['helper']['sha256']
elf=ELFFile(io.BytesIO(helper));gate=release['moduleControl']
at,size=gate['gateFileOffset'],gate['gateBytes'];branch=0xa6d68
segment=next(i for i,row in enumerate(elf.iter_segments()) if row['p_type']=='PT_LOAD' and row['p_offset']==at)
phdr=elf['e_phoff']+segment*elf['e_phentsize']
header=f'#pragma once\n#define MAPLESU_GATE_FILE_OFFSET {at}\n#define MAPLESU_GATE_BRANCH_OFFSET {branch}\n#define MAPLESU_GATE_PHDR_OFFSET {phdr}\n'
for name,blob in [('bytes',helper[at:at+size]),('branch',helper[branch:branch+4]),('phdr',helper[phdr:phdr+56])]:
 header+='static constexpr unsigned char maplesu_gate_'+name+'[] = {'+','.join(map(str,blob))+'};\n'
(build/'module_gate_identity.h').write_text(header,encoding='utf-8')
(build/'embedded-bootstrap.elf').write_bytes(helper)
script=f'''set -eu
cd /case
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -std=c++17 -stdlib=libc++ -Wall -Wextra -Werror -Wno-unused-variable -Wno-packed-non-pod -I. -I/repo/runtime/maplesu-sdk/include -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu /repo/runtime/tests/pro_module_control_test.cpp /repo/runtime/ultra/modules/module_control.cpp -o module-control.test
./module-control.test embedded-bootstrap.elf
'''
r=subprocess.run(['docker','run','--rm','--network','none','--mount',f'type=bind,source={root},target=/repo,readonly','--mount',f'type=bind,source={build},target=/case','--entrypoint','sh','ghcr.io/ylarod/ddk-min:android15-6.6-20260828','-c',script],capture_output=True,text=True)
(a.build/'module-control-regression.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr);raise SystemExit(r.returncode)
