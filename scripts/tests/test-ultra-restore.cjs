const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('manager/src/main/assets/liteweb/a/app.js', 'utf8');
const code = source.slice(source.indexOf('var STEP_NAMES ='), source.indexOf('function copyRecoveryLink('));

async function run() {
  const context = vm.createContext({
    console, state: { busy: false, tab: 'hidden' }, restoreState: { completed: null },
    apiPostSafe: async () => ({ ok: true, data: { ok: true, awaitingConfirmation: true,
      steps: ['pm_install:ok', 'await_manager_confirmation:pending'] } }),
    validData: r => r && r.ok ? r.data : null,
    dataOf: r => r && r.ok ? r.data : null,
    pick: (o, keys, fallback) => { for (const k of keys) if (o[k] != null) return o[k]; return fallback; },
    boolOf: v => typeof v === 'boolean' ? v : null,
    setMsg() {}, toast() {}, setTimeout() {}, clearTimeout() {}, homeReadId: 0,
    normalizeHidden: () => ({ managerUninstalled: false }),
    document: { documentElement: { classList: { toggle() {} } }, querySelectorAll: () => [] },
  });
  vm.runInContext(code, context);
  vm.runInContext('renderRestoreSteps = function() {}; renderHome = function() {}; renderRestoreCenter = function() {};', context);
  context.finishRecovery = () => { context.restoreState.completed = 'full'; };
  await context.runFullRestore(null);
  assert.equal(context.restoreState.completed, null, 'APK installation must not be displayed as completed handover');
  assert.equal(context.restoreState.awaitingConfirmation, true, 'web recovery must wait for explicit in-app confirmation');
  assert.equal(context.restoreState.pending, false, 'a pending handover must allow retry and refresh');
  context.restoreState.awaitingConfirmation = false;
  await context.cancelHidden(null);
  assert.equal(context.restoreState.completed, null, 'the legacy unhide button must use the same pending handover');
  assert.equal(context.restoreState.awaitingConfirmation, true);
  context.restoreState.awaitingConfirmation = false;
  context.apiGetSafe = context.apiPostSafe;
  await context.refreshRestoreHandover();
  assert.equal(context.restoreState.awaitingConfirmation, true, 'reloading the web page must rediscover the durable handover');
  context.apiPostSafe = async () => ({ ok: true, data: { ok: false, code: 'PM_FAILED' } });
  context.unsupportedText = () => 'PM_FAILED';
  context.restoreState.awaitingConfirmation = false;
  await context.runFullRestore(null);
  assert.equal(context.restoreState.completed, null);
  assert.equal(context.restoreState.pending, false);
  context.apiPostSafe = async () => ({ ok: true, data: { ok: true } });
  await context.runFullRestore(null);
  assert.equal(context.restoreState.completed, 'full', 'completed Normal restores retain their current UI behavior');
  console.log('PASS: real web restore handler preserves recovery until manager confirmation');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
