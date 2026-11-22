"""Run the file transaction suite against the built JAR and bind the actual inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs():
    paths = [ROOT / 'installer-core/build.gradle.kts']
    paths += sorted((ROOT / 'installer-core/src').rglob('*.java'))
    paths += sorted((ROOT / 'installer-core/build/classes/java/test').rglob('*.class'))
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java', default='java')
    args = parser.parse_args()
    jar = ROOT / 'installer-core/build/libs/installer-core.jar'
    record = {'schemaVersion': 1, 'passed': False, 'jarSha256': sha256(jar), 'inputs': inputs(),
              'testScriptSha256': sha256(Path(__file__)),
              'scope': 'Regular-file backup, write, readback, restart recovery and fault injection; no device partitions.'}
    destination = ROOT / '.analysis/file-installer-validation.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    classpath = os.pathsep.join((str(jar), str(ROOT / 'installer-core/build/classes/java/test')))
    result = subprocess.run([args.java, '-cp', classpath, 'dev.maplesu.installer.FileInstallTransactionTest'],
                            capture_output=True, text=True, timeout=60)
    output = result.stdout + result.stderr
    (ROOT / '.analysis/file-installer-validation.log').write_text(output, encoding='utf-8')
    match = re.fullmatch(r'PASS (\d+) file installation transaction checks\s*', output)
    if result.returncode != 0 or not match:
        raise SystemExit('File installer validation failed; see .analysis/file-installer-validation.log')
    if record['jarSha256'] != sha256(jar) or record['inputs'] != inputs():
        raise SystemExit('File installer validation inputs changed while tests were running')
    record.update({'passed': True, 'checks': int(match[1])})
    destination.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(output.strip())


if __name__ == '__main__':
    main()
