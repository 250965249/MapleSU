// No Android/Kotlin build: execute the production shell template and check its wiring.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const repo = path.resolve(__dirname, '..', '..');
const baseline = process.argv[2] && path.resolve(process.argv[2]);
const read = relative => {
  const file = baseline ? path.join(baseline, relative) : path.join(repo, relative);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n') : '';
};
const runtime = 'manager/src/main/java/dev/maplesu/manager/runtime/';
const installer = 'manager/src/main/java/dev/maplesu/manager/installer/';
const bootstrap = read(runtime + 'RootServiceBootstrap.kt');
const checks = [];
function check(name, run) { checks.push([name, run]); }
function quote(value) { return "'" + value.replace(/'/g, "'\\''") + "'"; }

const bash = process.env.BASH_EXE || (process.platform === 'win32'
  ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash');
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'maplesu-bootstrap-'));
try {
  const toybox = path.join(fixture, 'toybox.sh').replace(/\\/g, '/');
  fs.writeFileSync(toybox, `
    [ "$1" = runcon ] || exit 2
    [ "$FAIL_RUNCON" != 1 ] || exit 77
    shift; export TEST_DOMAIN="$1"; shift
    exec "$@"
  `);
  // The only substitutions are Android executables/proc files supplied by this fixture.
  // The branching, quoting, exec and exit handling come directly from production source.
  const template = bootstrap.match(/fun command\(script: String\): String = """\n([\s\S]*?)\n\s*"""\.trimIndent\(\)/)?.[1];
  function command(script) {
    if (!template) return script; // Pre-fix ROOT_EXEC passed the script through unchanged.
    return template.replace(/\$\{'\$'\}/g, '$').replace(/\$\{quote\(script\)\}/g, quote(script));
  }
  const prefix = `
    id() { printf '%s\\n' "$TEST_UID"; }
    context() { printf '%s\\n' "$TEST_DOMAIN"; }
    service() { [ "$TEST_DOMAIN" != u:r:kernel:s0 ] && printf 'Service activity: found\\n'; }
    export -f id context service
  `;
  function execute(script, uid = '0', domain = 'u:r:kernel:s0', failRuncon = '0') {
    const body = command(script)
      .replaceAll('/system/bin/id', 'id')
      .replace(/(?:\/system\/bin\/)?cat \/proc\/self\/attr\/current/g, 'context')
      .replaceAll('/system/bin/toybox', quote(bash) + ' ' + quote(toybox))
      .replaceAll('/system/bin/service', 'service')
      .replaceAll('/system/bin/sh', quote(bash.replace(/\\/g, '/')));
    const result = spawnSync(bash, ['--noprofile', '--norc', '-c', prefix + '\n' + body], {
      encoding: 'utf8', timeout: 4000,
      env: { ...process.env, TEST_UID: uid, TEST_DOMAIN: domain, FAIL_RUNCON: failRuncon },
    });
    if (result.error) throw result.error;
    return result;
  }
  check('UID 0 in kernel domain can reach framework Binder before launch', () => {
    const result = execute('/system/bin/service check activity');
    assert.equal(result.status, 0, `uid=0/domain=kernel service failed: ${result.stderr}`);
    assert.match(result.stdout, /activity: found/);
  });
  check('ordinary root domains are preserved', () => {
    const result = execute('printf "%s" "$TEST_DOMAIN"', '0', 'u:r:magisk:s0');
    assert.equal(result.status, 0);
    assert.equal(result.stdout, 'u:r:magisk:s0');
  });
  check('nonroot cannot dispatch a service command', () => {
    const result = execute('printf DISPATCHED', '10080');
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, /DISPATCHED/);
  });
  check('failed domain transition never dispatches', () => {
    const result = execute('printf DISPATCHED', '0', 'u:r:kernel:s0', '1');
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, /DISPATCHED/);
  });
  check('multiline quoted payload is dispatched once without expansion', () => {
    const payload = "a'b\n$(printf injected) `printf injected` $TOKEN";
    const result = execute('printf %s ' + quote(payload));
    assert.equal(result.status, 0);
    assert.equal(result.stdout, payload);
  });
  check('both libsu launch callers normalize the domain', () => {
    assert.match(read(runtime + 'RootExecutionRouter.kt'), /RootServiceBootstrap\.command\(script\)/);
    assert.match(read(installer + 'InstallerServiceClient.kt'), /RootServiceBootstrap\.launch\(/);
    assert.doesNotMatch(read(installer + 'InstallerServiceClient.kt'), /toybox runcon/);
  });
  check('installation tries explicit SU candidates before the cached route', () => {
    const source = read(installer + 'InstallerServiceClient.kt');
    const start = source.indexOf('val candidates = buildList');
    const selection = source.slice(start, source.indexOf('RootServiceBootstrap.launch(', start));
    assert.ok(selection.indexOf('SuRootCandidates') >= 0);
    assert.ok(selection.indexOf('SuRootCandidates') < selection.indexOf('InstallerServiceLaunchRoute.ROOT_EXEC'));
    assert.match(selection, /ProcessSuExec\.exec/);
    assert.match(bootstrap, /for \(candidate in candidates\)/);
    assert.match(bootstrap, /probe\.output\.lineSequence\(\).*!= READY/);
  });
  check('SU discovery is independent of runtime pairing and budgets each candidate', () => {
    const inventory = read(runtime + 'SuRootCandidates.kt');
    assert.ok(inventory.includes('/system/bin/su'));
    assert.doesNotMatch(inventory, /usesProBackend|ModeRuntime|canProvision/);
    assert.doesNotMatch(inventory, /File\(path\)\.(?:exists|canExecute)\(/);
    const probe = read('manager/src/main/java/dev/maplesu/manager/workmode/detect/probes/SuReadinessProbeAdapter.kt');
    assert.match(probe, /SuRootCandidates\.all/);
    assert.match(probe, /candidates\.size - index/);
  });
  check('all read-back candidates are archived before pending/live handoff', () => {
    const source = read(runtime + 'pro/ProInstallCredentials.kt');
    const retain = source.slice(source.indexOf('fun retainCandidate('), source.indexOf('fun retainSignedIdentity('));
    assert.ok(retain.indexOf('archiveCandidate(') >= 0);
    assert.ok(retain.indexOf('archiveCandidate(') < retain.indexOf('operationId == IMAGE_EXPORT_OPERATION'));
    assert.match(retain, /putString\(sha256, key\)/);
    assert.match(source, /createDevice = \{ requireNotNull\(imageSeed\(app, create = true\)\) \}/);
  });
  check('key recovery attempts every distinct saved image without an eight-key cutoff', () => {
    const source = read(runtime + 'pro/ProIdentityResolution.kt');
    assert.doesNotMatch(source, /MAX_INSTALL_CANDIDATES|\.take\(8\)/);
    assert.match(source, /for \(key in .*port\.installKeys/);
    assert.match(source, /\.filter\(::valid\)\.distinct\(\)/);
    assert.match(read(runtime + 'pro/ProInstallCredentials.kt'), /recoveryCredentials\(\)/);
  });
  let failed = 0;
  for (const [name, run] of checks) {
    try { run(); console.log('PASS ' + name); }
    catch (error) { failed++; console.log('FAIL ' + name + '\n  ' + error.message.split('\n')[0]); }
  }
  console.log(`${checks.length - failed}/${checks.length} checks passed; Android build/device tests not run`);
  process.exitCode = failed ? 1 : 0;
} finally {
  fs.rmSync(fixture, { recursive: true, force: true });
}
