// Real page, real DOM and fetch against a loopback fixture. No device changes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const assets = path.resolve('manager/src/main/assets/liteweb');
const evidence = path.resolve(process.argv[2] || 'work/web-restore-data-20261108/browser');
fs.mkdirSync(evidence, { recursive: true });
const prefix = '/x7k9f/' + 'a'.repeat(64);
let status = { ok: true };
let installReply = () => (status = { ok: true, awaitingConfirmation: true,
  steps: ['pm_install:ok', 'data_backup:ok', 'data_uid:ok', 'data:ok', 'await_manager_confirmation:pending'] });
const server = http.createServer((req, res) => {
  const route = req.url.split('?')[0].slice(prefix.length);
  res.setHeader('Cache-Control', 'no-store');
  if (route.startsWith('/api/')) {
    let body = { ok: true };
    if (route === '/api/restore/status') body = status;
    else if (route === '/api/restore') body = installReply();
    else if (route === '/api/status') body = { ok: true, root: true, mode: 'LITE', moduleCount: 0 };
    else if (route === '/api/hidden') body = { ok: true, hidden: true, managerUninstalled: true };
    else if (route === '/api/port') body = { ok: true, port: 18427 };
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
    return;
  }
  const file = path.resolve(assets, route === '/' ? 'index.html' : '.' + route);
  if (!file.startsWith(assets + path.sep) || !fs.existsSync(file)) { res.writeHead(404).end(); return; }
  const mime = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
  res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
  res.end(fs.readFileSync(file));
});
async function waitText(page, value) {
  await page.locator('#t-hidden').getByText(value, { exact: true }).first().waitFor({ state: 'visible', timeout: 12000 });
}
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch({ headless: true,
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined });
  try {
    const page = await browser.newPage({ viewport: { width: 392, height: 873 } });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${server.address().port}${prefix}/`);
    await page.evaluate(() => show('hidden'));
    async function restore() {
      await page.getByRole('button', { name: '恢复管理器', exact: true }).click();
      await page.getByRole('button', { name: '恢复', exact: true }).click();
    }
    await restore();
    await waitText(page, '等待管理器确认恢复');
    await waitText(page, '适配管理器新 UID');
    status = { ok: true, completed: true, awaitingConfirmation: false, steps: ['data:ok'] };
    await waitText(page, '恢复完成');
    await page.screenshot({ path: path.join(evidence, 'completed.png'), fullPage: true });
    console.log('PASS: rendered waiting page automatically reaches the completed page');

    status = { ok: true };
    installReply = () => (status = { ok: false, code: 'RECOVERY_DATA_VERIFY_FAILED',
      detail: 'DATA_UID_MISMATCH', steps: ['pm_install:ok', 'data:failed(DATA_UID_MISMATCH)'] });
    await page.reload(); await page.evaluate(() => show('hidden'));
    await restore();
    await waitText(page, '保留数据的 UID 与卸载记录不一致，恢复入口已保留');
    assert.equal(await page.getByRole('button', { name: '恢复管理器', exact: true }).isEnabled(), true);
    await page.screenshot({ path: path.join(evidence, 'data-error.png'), fullPage: true });
    console.log('PASS: data mismatch is actionable and leaves retry enabled');

    status = { ok: true };
    installReply = () => (status = { ok: false, code: 'RECOVERY_DATA_VERIFY_FAILED',
      detail: 'DATA_MIGRATION_FAILED', steps: ['pm_install:ok', 'data_backup:ok', 'data:failed(DATA_MIGRATION_FAILED)'] });
    await restore();
    await waitText(page, '数据属主迁移未完成，原数据备份和恢复入口已保留，请重试');
    assert.equal(await page.getByRole('button', { name: '恢复管理器', exact: true }).isEnabled(), true);
    assert.equal(await page.getByText('恢复完成', { exact: true }).count(), 0);
    console.log('PASS: interrupted UID migration reports the retained backup and enables retry');

    status = { ok: true, restoring: true };
    await page.route('**/api/restore', route => route.abort());
    await restore();
    await waitText(page, '恢复状态待确认');
    // The aborted POST must not freeze the controls or be reported as a data failure.
    assert.equal(await page.getByRole('button', { name: '恢复管理器', exact: true }).isEnabled(), true);
    status = { ok: true, awaitingConfirmation: true };
    await page.evaluate(() => window.dispatchEvent(new Event('pageshow')));
    await waitText(page, '等待管理器确认恢复');
    console.log('PASS: lost request reply reconnects to the server result on foreground entry');

    await page.route('**/api/restore/status', route => route.abort());
    await page.evaluate(() => window.dispatchEvent(new Event('pageshow')));
    await waitText(page, '恢复状态待确认');
    assert.equal(await page.getByText('恢复完成', { exact: true }).count(), 0);
    await page.screenshot({ path: path.join(evidence, 'connection-lost.png'), fullPage: true });
    assert.deepEqual(errors, []);
    console.log('PASS: disconnected page explains how to continue without claiming success');
  } finally {
    await browser.close();
    server.closeAllConnections(); server.close();
  }
})().catch(e => { console.error(e); process.exitCode = 1; server.closeAllConnections(); server.close(); });
