"""Run one real prepareTarget per frozen old invalid-AVB sample; never writes partitions."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
import zipfile
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'docs/dual-mode/impl/_work'
BASELINE = EVIDENCE / '2026-11-15-p2/evidence/embedded-real-lifecycle-r2/lifecycle/LIFECYCLE.json'
RUNTIME = EVIDENCE / '2026-11-16/evidence/owned-removal-current-core-r1/signed-fix/final-runtime/receipt.json'
WRITER = EVIDENCE / '2026-11-16/evidence/invalid-avb-candidate-green-r2/writer-overlay.jar'
LIMIT = 450 * 1024 * 1024
CLASSES = ['dev.maplesu.manager.ultrakernel.' + name for name in (
    'UltraKernelFlow', 'UltraKernelBuilder', 'UltraKernelOriginalRecovery', 'UltraKernelSpecGenerator',
    'UltraKernelRecipe', 'UltraKernelStructOffsets', 'UltraKernelBodies', 'UltraKernelAsm', 'UltraKernelA64Verify', 'UltraKernelOwnerSizes', 'UltraKernelPlan',
    'UltraKernelSpec', 'UltraKernelBtf', 'UltraKernelFileAssets', 'UltraKernelCredential')]
CLASSES += ['dev.maplesu.image.' + name for name in (
    'BootImageRebuilder', 'BootImageInspector', 'KernelCompression', 'BootImageEquivalence')]

HARNESS = r'''
import dev.maplesu.manager.ultrakernel.*;
import dev.maplesu.image.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.json.*;
import kotlin.Unit;

class InvalidAvbPrepareTargetMain {
    static String sha(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }
    static String sha(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var in = new FileInputStream(file)) {
            byte[] block = new byte[65536]; int n;
            while ((n = in.read(block)) >= 0) if (n != 0) digest.update(block, 0, n);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    static JSONObject identity(File file) throws Exception {
        return new JSONObject().put("path", file.getCanonicalPath()).put("bytes", file.length()).put("sha256", sha(file));
    }
    static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    static JSONArray origins(String[] names) throws Exception {
        JSONArray rows = new JSONArray();
        for (String name : names) {
            Class<?> type = Class.forName(name, false, ClassLoader.getSystemClassLoader());
            String member = "/" + name.replace('.', '/') + ".class";
            try (var in = type.getResourceAsStream(member)) {
                byte[] bytes = in.readAllBytes();
                rows.put(new JSONObject().put("class", name).put("codeSource", type.getProtectionDomain().getCodeSource().getLocation())
                    .put("resource", type.getResource(member)).put("bytes", bytes.length).put("sha256", sha(bytes)));
            }
        }
        return rows;
    }
    static JSONObject replay(File base, File candidate, File spec) throws Exception {
        byte[] raw = UltraKernelPlan.Companion.readKernel(base);
        byte[] actual = UltraKernelPlan.Companion.readKernel(candidate);
        byte[] expected = raw.clone(); BitSet covered = new BitSet(raw.length); int records = 0;
        for (String line : Files.readAllLines(spec.toPath())) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] fields = line.split("\\|", -1); check(fields.length == 3, "REPLAY_SPEC_FIELDS");
            long offset = Long.parseLong(fields[0]); byte[] before = HexFormat.of().parseHex(fields[1]);
            byte[] after = HexFormat.of().parseHex(fields[2]);
            check(before.length == after.length && offset >= 0 && offset <= (long)raw.length - before.length, "REPLAY_RANGE");
            int start = Math.toIntExact(offset);
            check(Arrays.equals(raw, start, start + before.length, before, 0, before.length), "REPLAY_PREIMAGE");
            System.arraycopy(after, 0, expected, start, after.length); covered.set(start, start + after.length); records++;
        }
        check(Arrays.equals(actual, expected), "REPLAY_COMPLETE_KERNEL_MISMATCH");
        int outside = 0;
        for (int i = 0; i < raw.length; i++) if (!covered.get(i) && actual[i] != raw[i]) outside++;
        check(outside == 0, "REPLAY_OUTSIDE_CHANGE");
        return new JSONObject().put("passed", true).put("records", records).put("allPreimagesMatched", true)
            .put("completeKernelEqual", true).put("outsideRecordsChanged", outside)
            .put("baseKernelSha256", sha(raw)).put("actualKernelSha256", sha(actual));
    }
    static long[][] parts(BootImageInspector.Report r) {
        return new long[][]{{r.ramdiskOffset,r.ramdiskSize},{r.secondOffset,r.secondSize},
            {r.recoveryDtboOffset,r.recoveryDtboSize},{r.dtbOffset,r.dtbSize},{r.signatureOffset,r.signatureSize}};
    }
    static JSONArray unchangedComponents(File base, File output) throws Exception {
        BootImageInspector.Report before = BootImageInspector.inspect(base), after = BootImageInspector.inspect(output);
        check(before.headerVersion == after.headerVersion, "HEADER_VERSION_CHANGED");
        String[] names = {"ramdisk","second","recoveryDtbo","dtb","signature"};
        long[][] a=parts(before), b=parts(after); JSONArray rows=new JSONArray();
        try (RandomAccessFile left=new RandomAccessFile(base,"r");RandomAccessFile right=new RandomAccessFile(output,"r")) {
            for (int i=0;i<names.length;i++) {
                check(a[i][1]==b[i][1],"NON_KERNEL_COMPONENT_SIZE:"+names[i]);
                MessageDigest da=MessageDigest.getInstance("SHA-256"),db=MessageDigest.getInstance("SHA-256");
                byte[] ba=new byte[65536],bb=new byte[65536];long remaining=a[i][1];left.seek(a[i][0]);right.seek(b[i][0]);
                while(remaining>0) {int n=(int)Math.min(remaining,ba.length);left.readFully(ba,0,n);right.readFully(bb,0,n);
                    check(Arrays.equals(ba,0,n,bb,0,n),"NON_KERNEL_COMPONENT_CHANGED:"+names[i]);da.update(ba,0,n);db.update(bb,0,n);remaining-=n;}
                rows.put(new JSONObject().put("name",names[i]).put("bytes",a[i][1]).put("sourceSha256",HexFormat.of().formatHex(da.digest()))
                    .put("outputSha256",HexFormat.of().formatHex(db.digest())).put("fullBytesEqual",true));
            }
        }
        return rows;
    }
    public static void main(String[] args) throws Exception {
        if (args[0].equals("origins")) {System.out.println(origins(Arrays.copyOfRange(args,1,args.length)).toString(2));return;}
        File input=new File(args[0]),work=new File(args[1]),evidence=new File(args[2]),assets=new File(args[3]);
        check(!work.exists()&&work.mkdirs(),"SCRATCH_CREATE");evidence.mkdirs();
        JSONObject result=new JSONObject().put("schema","maplesu-invalid-avb-prepare-target/1")
            .put("deviceTest",false).put("partitionWrites",false).put("metadataFabricated",false).put("receiptSupplied",false)
            .put("input",identity(input)).put("prepareCalls",0);
        JSONArray notices=new JSONArray();long start=System.nanoTime();
        try {
            UltraKernelFlow flow=new UltraKernelFlow(work,new UltraKernelFileAssets(assets),false,null);
            result.put("prepareCalls",1);
            UltraKernelFlow.Preparation prepared=flow.prepareTarget(input,UltraKernelCredential.Companion.of("Aa1".repeat(16)),null,
                text->{notices.put(text);return Unit.INSTANCE;});
            JSONObject prep=new JSONObject().put("planOrigin",prepared.getPlanOrigin()).put("supportLevel",prepared.getSupportLevel())
                .put("alreadyInstalled",prepared.getAlreadyInstalled());result.put("preparation",prep).put("prepareReturned",true);
            UltraKernelBuilder.Candidate candidate=prepared.getCandidate();
            if(candidate!=null) {
                prep.put("candidate",identity(candidate.getImage())).put("kernelSha256",candidate.getKernelSha256())
                    .put("records",candidate.getPatches()).put("changedBytes",candidate.getDifferingBytes());
                File base=input;
                if(!sha(base).equals(candidate.getBaseBootSha256())) {
                    try(var paths=Files.walk(work.toPath())) {
                        base=paths.filter(Files::isRegularFile).map(Path::toFile).filter(f->{try{return sha(f).equals(candidate.getBaseBootSha256());}catch(Exception e){return false;}}).findFirst().orElseThrow();
                    }
                }
                result.put("replayBase",identity(base));
                File[] specs=work.listFiles(f->f.isFile()&&f.getName().endsWith(".spec"));check(specs!=null&&specs.length==1,"SPEC_SINGLE_REQUIRED");
                result.put("independentReplay",replay(base,candidate.getImage(),specs[0]));
                result.put("components",unchangedComponents(base,candidate.getImage()));
                BootImageInspector.Report image=BootImageInspector.inspect(candidate.getImage());
                check(image.sha256.equals(candidate.getBootSha256()),"CANDIDATE_HASH_DIFFERS");
                byte[] record=BootImageRebuilder.readRecoveryRecord(candidate.getImage());check(record!=null,"CANDIDATE_RECOVERY_RECORD_MISSING");
                result.put("writerReadback",new JSONObject(image.toJson())).put("recoveryRecordBytes",record.length)
                    .put("footerPresent",AvbFooter.parse(candidate.getImage()).present);
                for(File f:work.listFiles()) if(f.isFile()&&(f.getName().endsWith(".spec")||f.getName().endsWith(".json")))
                    Files.copy(f.toPath(),new File(evidence,f.getName()).toPath());
                result.put("candidateVerified",true);
            } else result.put("candidateVerified",false);
            result.put("passed",candidate!=null);
        } catch(Exception error) {
            String code=error instanceof UltraKernelGenerateException?((UltraKernelGenerateException)error).getCode():error.getMessage();
            String detail=error instanceof UltraKernelGenerateException?((UltraKernelGenerateException)error).getDetail():error.getMessage();
            StringWriter trace=new StringWriter();error.printStackTrace(new PrintWriter(trace));
            result.put("passed",false).put("errorType",error.getClass().getName()).put("code",code).put("detail",detail)
                .put("stackTrace",trace.toString());
        } finally {
            result.put("notices",notices).put("elapsedSeconds",(System.nanoTime()-start)/1e9)
                .put("inputAfter",identity(input)).put("inputUnchanged",sha(input).equals(result.getJSONObject("input").getString("sha256")));
            Files.writeString(new File(evidence,"result.json").toPath(),result.toString(2)+"\n");
            System.out.println("prepareTarget passed=" + result.getBoolean("passed"));
        }
    }
}
'''


def identity(path):
    path = Path(path).resolve()
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': h.hexdigest()}


def first_definition(classpath, name):
    member = name.replace('.', '/') + '.class'
    for entry in classpath:
        path = Path(entry)
        if path.is_dir() and (path / member).is_file():
            data = (path / member).read_bytes()
        elif path.is_file():
            with zipfile.ZipFile(path) as jar:
                if member not in jar.namelist():
                    continue
                data = jar.read(member)
        else:
            continue
        return {'class': name, 'codeSource': str(path.resolve()), 'member': member,
                'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    raise RuntimeError('CLASS_MISSING:' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.drive.upper() == 'C:' and not out.exists()
    out.mkdir(parents=True)
    runtime = json.loads(RUNTIME.read_text(encoding='utf-8-sig'))
    argv = runtime['commands'][0]['argv']
    java = Path(argv[0]); javac = java.with_name('javac.exe')
    classpath = argv[argv.index('-cp') + 1].split(os.pathsep)
    classpath = [str(WRITER) if Path(p).name == 'writer-overlay.jar' else p for p in classpath]
    assert identity(WRITER)['sha256'] == '94d44e14e31c7bb5304cd779fdd6dbb669fda24464ee574270c6f57f2318b440'
    assert identity(Path(runtime['recoveryOverlay']['path'])) == runtime['recoveryOverlay']
    source = out / 'InvalidAvbPrepareTargetMain.java'; source.write_text(HARNESS, encoding='utf-8')
    classes = out / 'classes'; classes.mkdir()
    receipt = {'schema': 'maplesu-invalid-avb-prepare-target-receipt/1', 'runtimeReceipt': identity(RUNTIME),
               'baseline': identity(BASELINE), 'java': identity(java), 'javac': identity(javac),
               'writer': identity(WRITER), 'recoveryOverlay': runtime['recoveryOverlay'],
               'runner': identity(__file__), 'harness': identity(source), 'classpath': classpath,
               'firstDefinitions': [first_definition(classpath, name) for name in CLASSES],
               'scratchLimitBytes': LIMIT, 'cases': [], 'SDKOrAPKBuild': False,
               'productionModified': False, 'partitionWrites': False, 'deviceOperations': False}
    def save():
        (out / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    save()
    compile_argv = [str(javac), '--release', '17', '-encoding', 'UTF-8', '-cp', os.pathsep.join(classpath), '-d', str(classes), str(source)]
    done = subprocess.run(compile_argv, capture_output=True)
    (out / 'compile.stdout.log').write_bytes(done.stdout); (out / 'compile.stderr.log').write_bytes(done.stderr)
    receipt['compile'] = {'argv': compile_argv, 'exitCode': done.returncode}; save()
    if done.returncode:
        return done.returncode
    execute_cp = os.pathsep.join([str(classes), *classpath])
    origin_argv = [str(java), '-Xmx128m', '-cp', execute_cp, 'InvalidAvbPrepareTargetMain', 'origins', *CLASSES]
    done = subprocess.run(origin_argv, capture_output=True)
    (out / 'origins.stdout.json').write_bytes(done.stdout); (out / 'origins.stderr.log').write_bytes(done.stderr)
    receipt['origins'] = {'argv': origin_argv, 'exitCode': done.returncode}
    if done.returncode:
        save();return done.returncode
    actual = json.loads(done.stdout)
    for expected, row in zip(receipt['firstDefinitions'], actual, strict=True):
        assert row['class'] == expected['class'] and row['bytes'] == expected['bytes'] and row['sha256'] == expected['sha256']
        assert urllib.parse.unquote(urllib.parse.urlparse(Path(expected['codeSource']).as_uri()).path).rstrip('/') == urllib.parse.unquote(urllib.parse.urlparse(row['codeSource']).path).rstrip('/')
    receipt['actualOriginsMatched'] = True; save()
    cases = json.loads(BASELINE.read_text(encoding='utf-8-sig'))['cases']
    for index in [2, 8, 9]:
        expected = cases[index - 1]['input']; source_image = Path(expected['path'])
        assert identity(source_image) == expected
        estimated_peak = expected['bytes'] * 6 + 16 * 1024 * 1024
        assert estimated_peak <= LIMIT and shutil.disk_usage(out).free >= estimated_peak + 128 * 1024 * 1024
        evidence = out / f'case-{index:02}'; evidence.mkdir()
        scratch = out / f'scratch-{index:02}'
        case = {'id': index, 'input': expected, 'estimatedPeakLogicalBytes': estimated_peak,
                'diskBefore': shutil.disk_usage(out)._asdict()}
        command = [str(java), '-Xmx1024m', '-cp', execute_cp, 'InvalidAvbPrepareTargetMain',
                   str(source_image), str(scratch), str(evidence), str(ROOT / 'manager/src/main/assets')]
        started = time.monotonic()
        with (evidence / 'stdout.log').open('wb') as stdout, (evidence / 'stderr.log').open('wb') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            peak = 0
            while process.poll() is None:
                peak = max(peak, sum(p.stat().st_size for p in scratch.rglob('*') if p.is_file()) if scratch.exists() else 0)
                if peak > LIMIT:
                    process.kill(); process.wait()
                    raise RuntimeError('SCRATCH_LIMIT_EXCEEDED')
                time.sleep(0.1)
            process.wait()
        case.update(argv=command, exitCode=process.returncode, elapsedSeconds=time.monotonic()-started,
                    observedPeakLogicalBytes=peak, inputAfter=identity(source_image))
        case['inputUnchanged'] = case['inputAfter'] == expected
        if (evidence / 'result.json').exists():
            case['result'] = json.loads((evidence / 'result.json').read_text(encoding='utf-8-sig'))
        if scratch.exists():
            assert scratch.resolve().parent == out and scratch.name == f'scratch-{index:02}'
            shutil.rmtree(scratch)
        case['scratchRemoved'] = not scratch.exists(); case['diskAfter'] = shutil.disk_usage(out)._asdict()
        receipt['cases'].append(case); save()
        print(json.dumps({'case': index, 'exitCode': process.returncode,
                          'passed': case.get('result', {}).get('passed'), 'code': case.get('result', {}).get('code'),
                          'peakMiB': round(peak / 1024 / 1024, 2)}), flush=True)
    receipt['executionComplete'] = len(receipt['cases']) == 3
    receipt['inputsUnchanged'] = all(c['inputUnchanged'] for c in receipt['cases'])
    receipt['passed'] = all(c['exitCode'] == 0 and c['inputUnchanged'] and c['scratchRemoved'] and c.get('result', {}).get('passed') for c in receipt['cases'])
    save()
    return 0 if receipt['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
