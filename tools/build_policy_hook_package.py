"""Build and package measured temporary policy sidecars using retained local inputs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
BUILDER=ROOT/'jailbreak-providers/root-loader/build_policy_hook.py'

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def stage(reports,assets):
    images=[];seen=set()
    for path in reports:
        report=json.loads(path.read_text())
        if report.get('passed') is not True or report.get('controlAbi')!=2:
            raise ValueError('unqualified policy sidecar: '+str(path))
        for name,expected in report['sourceSha256'].items():
            if digest(ROOT/name)!=expected:raise ValueError('sidecar source drift: '+name)
        record=report['module'];module=Path(record['path'])
        if module.stat().st_size!=record['bytes'] or digest(module)!=record['sha256']:
            raise ValueError('sidecar artifact drift: '+str(module))
        identity=report['buildId'];page=report['facts']['MSU_PH_PAGE_BYTES']
        if (identity,page) in seen:raise ValueError('duplicate sidecar image')
        seen.add((identity,page))
        relative=Path('maplesu/policy-hook')/(identity+'.ko')
        target=assets/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(module,target)
        if digest(target)!=record['sha256']:raise ValueError('sidecar copy drift')
        images.append(dict(asset=relative.as_posix(),sha256=record['sha256'],bytes=record['bytes'],buildId=identity,
                           kernelRelease=report['kernelRelease'],pageSize=page))
    document=dict(schemaVersion=1,controlAbi=2,generatedAt=datetime.now(timezone.utc).isoformat(),images=images)
    assets.mkdir(parents=True,exist_ok=True)
    (assets/'maplesu-policy-hook.json').write_text(json.dumps(document,indent=2)+'\n')
    return document

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundles',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--assets',type=Path,required=True)
    p.add_argument('--ndk',type=Path,required=True)
    p.add_argument('--contract',type=Path,action='append',required=True)
    a=p.parse_args();reports=[]
    for index,contract in enumerate(a.contract):
        directory=a.output/str(index)
        subprocess.run([sys.executable,BUILDER,'--contract',contract,'--bundles',a.bundles,'--ndk',a.ndk,'--out',directory],check=True,cwd=ROOT)
        reports.append(directory/'build.json')
    print(json.dumps(stage(reports,a.assets),indent=2))
if __name__=='__main__':main()
