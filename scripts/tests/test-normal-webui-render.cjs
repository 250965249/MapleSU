// Render the actual production path-handler responses in Chromium, without a module HTTP server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require('playwright');

async function main() {
  const root = path.resolve(__dirname, '../..');
  const args = process.argv.slice(2);
  const callbacksOnly = args.includes('--callbacks-only');
  const paths = args.filter(value => value !== '--callbacks-only');
  const input = path.resolve(paths[0] || path.join(root, '.tmp/normal-webui-static-permanent/handler/responses.json'));
  const output = path.resolve(paths[1] || path.join(root, '.tmp/normal-webui-render'));
  const compatibilityInput = path.resolve(paths[2] || path.join(root, '.tmp/normal-webui-compatibility/compatibility.json'));
  const compatibility = JSON.parse(fs.readFileSync(compatibilityInput, 'utf8'));
  const policyVerification = JSON.parse(fs.readFileSync(path.join(path.dirname(compatibilityInput), 'verification.json'), 'utf8'));
  assert.equal(policyVerification.passed, true, 'Production policy export was not verified');
  for (const [source, hash] of Object.entries(policyVerification.sourceSha256)) {
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(root, source))).digest('hex'), hash,
      `Production callback/policy source changed: ${source}`);
  }
  fs.mkdirSync(output, { recursive: true });
  const responses = callbacksOnly ? new Map() :
    new Map(JSON.parse(fs.readFileSync(input, 'utf8')).map(item => [item.url, item]));
  const requested = [];
  const errors = [];
  let passed = false;
  const browser = await chromium.launch({ headless: true,
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined });
  try {
    const page = await browser.newPage({ viewport: { width: 392, height: 873 } });
    page.on('pageerror', error => errors.push(error.message));
    if (callbacksOnly) {
      await page.setContent('<!doctype html><html><body></body></html>');
    } else {
      await page.route('**/*', async route => {
        const url = route.request().url();
        requested.push(url);
        const response = responses.get(url);
        assert.ok(response, `Unexpected network request: ${url}`);
        await route.fulfill({ status: response.status, contentType: response.mimeType || 'text/plain',
          headers: {
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': compatibility.normalCsp,
          },
          body: response.bodyBase64 ? Buffer.from(response.bodyBase64, 'base64') : Buffer.alloc(0) });
      });
      const first = await page.goto('https://mui.kernelsu.org/index.html');
      assert.equal(first.status(), 200);
      await page.waitForFunction(() => document.documentElement.dataset.staticReady === 'yes');
      assert.equal(await page.locator('#fixture').textContent(), 'Normal static WebUI loaded');
      assert.equal(await page.locator('#fixture').evaluate(element => getComputedStyle(element).color), 'rgb(19, 37, 73)');
      assert.equal(await page.evaluate(() => window.isSecureContext), true);
      assert.equal(await page.evaluate(async () => {
        const result = await WebAssembly.instantiateStreaming(fetch('/assets/fixture.wasm'));
        return result.instance instanceof WebAssembly.Instance;
      }), true);
      assert.equal(await page.evaluate(async () => (await (await fetch('/assets/icon.svgz')).text()).startsWith('<svg')), true);
      assert.equal(await page.evaluate(async () => (await fetch('/missing.html')).status), 404);
      assert.deepEqual(await page.evaluate(async () => {
        const echo = (worker, value) => new Promise((resolve, reject) => {
          const timer = setTimeout(() => { worker.terminate(); reject(new Error('Worker response timed out')); }, 5000);
          worker.onmessage = event => { clearTimeout(timer); worker.terminate(); resolve(event.data); };
          worker.onerror = event => { clearTimeout(timer); worker.terminate(); reject(new Error(event.message)); };
          worker.postMessage(value);
        });
        const sameOrigin = await echo(new Worker('/assets/worker.js'), 'normal');
        const url = URL.createObjectURL(new Blob(["self.onmessage=e=>self.postMessage({kind:'blob',value:e.data});"],
          { type: 'application/javascript' }));
        try { return [sameOrigin, await echo(new Worker(url), 'blob')]; }
        finally { URL.revokeObjectURL(url); }
      }), [{ kind: 'same-origin', value: 'normal' }, { kind: 'blob', value: 'blob' }]);
    }
    assert.deepEqual(await page.evaluate(fixture => {
      const events = [];
      const execute = source => (0, eval)(source.replace(/^javascript:\s*/, ''));
      window.done = (...args) => events.push(['simple', ...args]);
      window.app = {
        done(...args) { events.push(['dotted', this === window.app, ...args]); },
        child: {
          stdout: { emit: (name, value) => events.push(['stdout', name, value]) },
          stderr: { emit: (name, value) => events.push(['stderr', name, value]) },
          emit(name, value) {
            events.push([name, name === 'error' ? value.exitCode : value]);
            if (name === 'exit') delete window.app.child;
          },
        },
      };
      execute(fixture.simpleExec);
      execute(fixture.dottedExec);
      execute(fixture.windowExec);
      fixture.spawn.forEach(execute);
      window['app.done'] = function (...args) { events.push(['ultra-literal', this === window, ...args]); };
      execute(fixture.ultraExec);
      delete window['app.done'];
      execute(fixture.ultraExec);
      execute(fixture.ultraWindowExec);
      const child = (kind, remove) => {
        const value = {
          stdout: { emit(name, line) { events.push([kind, 'stdout', this === value.stdout, name, line]); } },
          stderr: { emit(name, line) { events.push([kind, 'stderr', this === value.stderr, name, line]); } },
          emit(name, result) {
            events.push([kind, name, this === value, name === 'error' ? result.exitCode : result]);
            if (name === 'exit') remove();
          },
        };
        return value;
      };
      window.app.child = child('ultra-nested-child', () => { delete window.app.child; });
      window['app.child'] = child('ultra-literal-child', () => { delete window['app.child']; });
      fixture.ultraSpawn.forEach(execute);
      fixture.ultraSpawn.forEach(execute);
      window.__callbackInjected = 0;
      window.app.constructor = () => { ++window.__callbackInjected; };
      window.app.prototype = { done() { ++window.__callbackInjected; } };
      Object.setPrototypeOf(window.app, { done() { ++window.__callbackInjected; } });
      for (const entry of fixture.ultraUnsafeNames) {
        execute(entry.script);
        window[entry.name] = function (...args) { events.push(['ultra-literal-name', entry.name, this === window, ...args]); };
        execute(entry.script);
        delete window[entry.name];
      }
      events.push(['unsafe-expression-counter', window.__callbackInjected]);
      return events;
    }, compatibility), [
      ['simple', 0, 'stdout', 'stderr'], ['dotted', true, 7, 'out', 'err'],
      ['dotted', true, 8, 'window', ''], ['stdout', 'data', 'line'], ['stderr', 'data', 'warning'],
      ['exit', 9], ['error', 9], ['ultra-literal', true, 0, 'literal', ''],
      ['dotted', true, 0, 'literal', ''], ['dotted', true, 8, 'window', ''],
      ['ultra-literal-child', 'stdout', true, 'data', 'ultra-line'],
      ['ultra-literal-child', 'stderr', true, 'data', 'ultra-warning'],
      ['ultra-literal-child', 'exit', true, 13], ['ultra-literal-child', 'error', true, 13],
      ['ultra-nested-child', 'stdout', true, 'data', 'ultra-line'],
      ['ultra-nested-child', 'stderr', true, 'data', 'ultra-warning'],
      ['ultra-nested-child', 'exit', true, 13], ['ultra-nested-child', 'error', true, 13],
      ['ultra-literal-name', 'done();window.__callbackInjected=1', true, 0, 'legacy', ''],
      ['ultra-literal-name', 'app.constructor', true, 0, 'legacy', ''],
      ['ultra-literal-name', 'app.__proto__.done', true, 0, 'legacy', ''],
      ['ultra-literal-name', 'app.prototype.done', true, 0, 'legacy', ''],
      ['unsafe-expression-counter', 0],
    ]);
    if (!callbacksOnly) {
      await page.evaluate(() => new Promise(resolve => {
        const frame = document.createElement('iframe');
        frame.src = 'https://outside.invalid/frame';
        document.body.append(frame);
        setTimeout(() => { frame.remove(); resolve(); }, 100);
      }));
      assert.equal(requested.some(url => url.startsWith('https://outside.invalid/')), false);
      await page.screenshot({ path: path.join(output, 'static-html.png') });
      for (const url of ['https://mui.kernelsu.org/assets/style.css?rev=1',
        'https://mui.kernelsu.org/assets/main.js?rev=1',
        'https://mui.kernelsu.org/data/status.json?revision=1']) assert.ok(requested.includes(url), url);
    }
    assert.deepEqual(errors, []);
    passed = true;
    console.log(callbacksOnly ? 'PASS: production Normal and Ultra callback scripts, literal priority, nested receivers, spawn order and literal-only invalid names' :
      'PASS: production handler HTML/CSS/module JS/JSON/WASM/SVGZ, Normal same-origin/blob workers and Normal/Ultra callback scripts; missing file returns 404');
  } finally {
    await browser.close();
    fs.writeFileSync(path.join(output, 'verification.json'), JSON.stringify({
      passed, callbacksOnly, scope: callbacksOnly ? 'Chromium execution of production-generated callback scripts on an empty page' :
        'Chromium rendering of real production path-handler responses; Android/root I/O was fixture-backed',
      input: callbacksOnly ? null : input,
      inputSha256: callbacksOnly ? null : crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'),
      compatibilityInput, compatibilitySha256: crypto.createHash('sha256').update(fs.readFileSync(compatibilityInput)).digest('hex'),
      productionPolicySourceSha256: policyVerification.sourceSha256,
      requested, pageErrors: errors, moduleHttpServerStarted: false,
      androidWebViewTested: false, deviceTestsPerformed: false,
    }, null, 2) + '\n');
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
