const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = process.argv[2] || '.';
const source = fs.readFileSync(path.join(root, 'manager/src/main/assets/liteweb/a/app.js'), 'utf8');
const code = source.slice(source.indexOf('var STEP_NAMES ='), source.indexOf('function copyRecoveryLink('));
function fixture() {
  const timers = new Map();
  let nextTimer = 0;
  const c = vm.createContext({
    console, state: { busy: false, tab: 'hidden' }, restoreState: { completed: null },
    homeState: {}, homeReadId: 0,
    apiGetSafe: async () => ({ ok: true, status: 200, data: { ok: true, awaitingConfirmation: true } }),
    apiPostSafe: async () => ({ ok: true, status: 200, data: { ok: true, awaitingConfirmation: true } }),
    validData: r => r && r.ok && r.data && r.data.ok !== false ? r.data : null,
    dataOf: r => r && r.ok ? r.data : null,
    pick: (o, keys, fallback) => { for (const k of keys) if (o[k] != null) return o[k]; return fallback; },
    boolOf: v => typeof v === 'boolean' ? v : null,
    setMsg() {}, toast() {}, unsupportedText: () => '请求失败',
    normalizeHidden: () => ({ managerUninstalled: false }),
    setTimeout: (fn, ms) => { timers.set(++nextTimer, { fn, ms }); return nextTimer; },
    clearTimeout: id => timers.delete(id),
    document: { hidden: false, documentElement: { classList: { toggle() {} } }, querySelectorAll: () => [] },
    window: { scrollTo() {} }, $: () => ({}),
  });
  vm.runInContext(code, c);
  vm.runInContext('renderRestoreSteps = function() {}; renderHome = function() {}; renderRestoreCenter = function() {};', c);
  return { c, timers, tick: async () => {
    const [id, timer] = timers.entries().next().value || [];
    assert.ok(timer, 'pending restore must schedule a status query');
    timers.delete(id); await timer.fn();
  }};
}
const tests = [
  ['confirmed receipt completes a waiting page and clears pending state', async () => {
    const {c} = fixture(); c.restoreState.awaitingConfirmation = true;
    c.apiGetSafe = async () => ({ ok: true, status: 200, data: { ok: true, completed: true, awaitingConfirmation: false } });
    await c.refreshRestoreHandover();
    assert.equal(c.restoreState.completed, 'full');
    assert.equal(c.restoreState.awaitingConfirmation, false);
  }],
  ['pending restoration polls until the confirmed receipt arrives', async () => {
    const {c, tick, timers} = fixture(); await c.runFullRestore(null);
    assert.equal(c.restoreState.completed, null);
    c.apiGetSafe = async () => ({ ok: true, status: 200, data: { ok: true, completed: true } });
    await tick(); assert.equal(c.restoreState.completed, 'full'); assert.equal(timers.size, 0);
  }],
  ['lost install reply is resolved using server progress', async () => {
    const {c, tick} = fixture();
    c.apiPostSafe = async () => ({ ok: false, status: 0, data: null });
    c.apiGetSafe = async () => ({ ok: true, status: 200, data: { ok: true, restoring: true } });
    await c.runFullRestore(null); await tick();
    assert.equal(c.restoreState.checking, true);
    c.apiGetSafe = async () => ({ ok: true, status: 200, data: { ok: true, awaitingConfirmation: true } });
    await tick(); assert.equal(c.restoreState.awaitingConfirmation, true);
  }],
  ['idle status and disconnect never forge successful restoration', async () => {
    const {c} = fixture(); c.restoreState.awaitingConfirmation = true;
    c.apiGetSafe = async () => ({ ok: true, status: 200, data: { ok: true, awaitingConfirmation: false } });
    await c.refreshRestoreHandover(); assert.equal(c.restoreState.completed, null);
    c.apiGetSafe = async () => ({ ok: false, status: 0, data: null });
    await c.refreshRestoreHandover();
    assert.equal(c.restoreState.completed, null); assert.equal(c.restoreState.connectionLost, true);
  }],
  ['failed install status clears the waiting banner and preserves the reason', async () => {
    const {c} = fixture(); c.restoreState.awaitingConfirmation = true;
    c.apiGetSafe = async () => ({ ok: true, status: 200, data: { ok: false,
      code: 'RECOVERY_DATA_VERIFY_FAILED', steps: ['data:failed(DATA_UID_MISMATCH)'] } });
    await c.refreshRestoreHandover();
    assert.equal(c.restoreState.awaitingConfirmation, false);
    assert.equal(c.restoreState.completed, null);
    assert.equal(c.restoreState.result.data.code, 'RECOVERY_DATA_VERIFY_FAILED');
  }],
  ['old status replies cannot complete a newly started installation', async () => {
    const {c} = fixture(); let reply;
    c.apiGetSafe = () => new Promise(resolve => { reply = resolve; });
    const old = c.refreshRestoreHandover();
    await c.runFullRestore(null);
    reply({ ok: true, status: 200, data: { ok: true, completed: true } });
    await old;
    assert.equal(c.restoreState.completed, null);
    assert.equal(c.restoreState.awaitingConfirmation, true);
  }],
  ['UID reassignment reaches manager confirmation and then the completion page', async () => {
    const {c, tick} = fixture();
    const steps = ['pm_install:ok', 'data_backup:ok', 'data_uid:ok', 'data:ok', 'await_manager_confirmation:pending'];
    c.apiPostSafe = async () => ({ ok: true, status: 200, data: { ok: true, awaitingConfirmation: true, steps } });
    await c.runFullRestore(null);
    assert.equal(c.restoreState.awaitingConfirmation, true);
    assert.equal(c.restoreState.completed, null);
    c.apiGetSafe = async () => ({ ok: true, status: 200, data: { ok: true, completed: true, steps } });
    await tick();
    assert.equal(c.restoreState.completed, 'full');
    assert.equal(c.restoreState.awaitingConfirmation, false);
  }],
  ['failed UID migration keeps retry enabled and does not poll forever', async () => {
    const {c, timers} = fixture();
    c.apiPostSafe = async () => ({ ok: true, status: 200, data: { ok: false,
      code: 'RECOVERY_DATA_VERIFY_FAILED', steps: ['data_backup:ok', 'data:failed(DATA_MIGRATION_FAILED)'] } });
    await c.runFullRestore(null);
    assert.equal(c.restoreState.pending, false);
    assert.equal(c.restoreState.checking, false);
    assert.equal(c.restoreState.completed, null);
    assert.equal(timers.size, 0);
    assert.equal(c.state.busy, false);
  }],
  ['legacy unhide handles an installation already running on the server', async () => {
    const {c, timers} = fixture();
    c.apiPostSafe = async () => ({ ok: true, status: 200, data: { ok: true, restoring: true } });
    await c.cancelHidden(null);
    assert.equal(c.restoreState.completed, null);
    assert.equal(c.restoreState.checking, true);
    assert.equal(timers.size, 1);
  }],
];
(async () => {
  let failed = 0;
  for (const [name, test] of tests) {
    try { await test(); console.log('PASS: ' + name); }
    catch (e) { failed++; console.error('FAIL: ' + name + '\n' + e.message); }
  }
  console.log(`${tests.length - failed}/${tests.length} web status regressions passed`);
  process.exitCode = failed ? 1 : 0;
})();
