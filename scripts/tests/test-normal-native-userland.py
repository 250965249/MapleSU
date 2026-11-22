"""Run the production native install sequence, including Normal userland failure rollback."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/specgen'))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java, javac = shutil.which('java'), shutil.which('javac')
    if not java or not javac:
        parser.error('Java JDK is required')
    deps = [cached_jar(*item) for item in [
        ('org.jetbrains.kotlin', 'kotlin-stdlib', '2.4.20'),
        ('org.jetbrains', 'annotations', '13.0'),
        ('junit', 'junit', '4.13.2'), ('org.hamcrest', 'hamcrest-core', '1.3')]]
    compiler = cached_jar('org.jetbrains.kotlin', 'kotlin-compiler-embeddable', '2.4.20')
    coroutines = cached_jar('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm', '1.11.0')
    # Use the actual Java transaction closure; no partition device is accessed by the tests.
    sources = sorted((ROOT / 'installer-core/src/main/java/dev/maplesu/installer').glob('*.java'))
    kotlin = [ROOT / 'manager' / name for name in [
        'src/main/java/dev/maplesu/manager/installer/NativeInstallSequence.kt',
        'src/test/java/dev/maplesu/manager/installer/NativeInstallSequenceTest.kt',
        'src/test/java/dev/maplesu/manager/ksu/KsuSourceIsolationTest.kt',
        'src/test/java/dev/maplesu/manager/ksu/KsuTestPaths.kt']]
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources + kotlin}
    classes = out / 'classes'
    classes.mkdir(exist_ok=True)
    jar = out / 'tests.jar'
    cp = os.pathsep.join(map(str, [classes] + deps))
    selected = out / 'NormalNativeChecks.java'
    selected.write_text('''import org.junit.internal.TextListener;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
public class NormalNativeChecks {
    public static void main(String[] args) throws Exception {
        JUnitCore runner = new JUnitCore();
        runner.addListener(new TextListener(System.out));
        boolean passed = runner.run(Class.forName("dev.maplesu.manager.installer.NativeInstallSequenceTest")).wasSuccessful();
        Class<?> boundary = Class.forName("dev.maplesu.manager.ksu.KsuSourceIsolationTest");
        for (String method : new String[]{"bootInstallerExceptionAllowsOnlyTheTwoDeploymentSymbols",
                "rebootTransportExceptionAllowsOnlyTheExactGlueSymbol"}) {
            passed &= runner.run(Request.method(boundary, method)).wasSuccessful();
        }
        if (!passed) System.exit(1);
    }
}
''', encoding='utf-8')
    commands = [
        [javac, '-encoding', 'UTF-8', '-d', str(classes), *map(str, sources)],
        [java, '-Xmx768m', '-cp', os.pathsep.join(map(str, [compiler, coroutines] + deps)),
         'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '21',
         '-classpath', cp, '-d', str(jar), *map(str, kotlin)],
        [javac, '-encoding', 'UTF-8', '-classpath', cp, '-d', str(classes), str(selected)],
        [java, '-cp', str(jar) + os.pathsep + cp, 'NormalNativeChecks']]
    for name, command in zip(['java-compile', 'compile', 'selection-compile', 'tests'], commands):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=120)
        log = result.stdout + result.stderr
        (out / (name + '.log')).write_text(log, encoding='utf-8')
        print(log)
        if result.returncode:
            break
    unchanged = hashes == {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sources + kotlin}
    (out / 'verification.json').write_text(json.dumps({
        'passed': result.returncode == 0 and unchanged, 'sourcesUnchanged': unchanged,
        'sourceSha256': hashes, 'deviceTested': False, 'partitionWrites': False,
        'tests': ['NativeInstallSequenceTest',
                  'KsuSourceIsolationTest.bootInstallerExceptionAllowsOnlyTheTwoDeploymentSymbols',
                  'KsuSourceIsolationTest.rebootTransportExceptionAllowsOnlyTheExactGlueSymbol'],
        'fullSourceIsolationSuite': False,
        'platformSubstitutes': ['in-memory partition devices; production sequence and transaction code'],
    }, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(result.returncode if unchanged else 1)


if __name__ == '__main__':
    main()
