// Extended interaction coverage — the paths the main smoke test skips.
// Run `npm run preview` first. PREVIEW_URL overrides the default port.
import { chromium } from 'playwright';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/* Own the server this suite tests.
 *
 * The default was http://localhost:4705/, with a preview assumed to be serving
 * it already and no check of whose server answered. The fleet registry
 * (crypto-lab/tools/playwright-ports.json) assigns 4705 to no lab; this lab's
 * port is 4661. A port held by another project answers the goto, and every
 * check after it then describes someone else's page.
 *
 * PREVIEW_URL still points this at an already-running server; CI does that.
 * With it unset this builds if needed, starts its own preview on 4661 with
 * --strictPort -- which refuses to move, so a collision fails loudly here --
 * and stops it by its own pid, never by pattern.
 */
const OWN_PORT = 4661;
const BASE = process.env.PREVIEW_URL ?? `http://localhost:${OWN_PORT}/crypto-lab-kyberslash/`;
let ownServer = null;

async function reachable(u) {
  try {
    return (await fetch(u, { redirect: 'follow' })).ok;
  } catch {
    return false;
  }
}

async function startOwnServer() {
  if (!existsSync(join(REPO_ROOT, 'dist', 'index.html'))) {
    const built = spawnSync('npm', ['run', 'build'], { cwd: REPO_ROOT, encoding: 'utf8' });
    if (built.status !== 0) {
      console.error('FAIL: could not build before starting the preview server');
      console.error((built.stdout ?? '') + (built.stderr ?? ''));
      process.exit(1);
    }
  }
  /* `detached` makes the child a process-GROUP leader, which is the whole
     point: `npm run preview` is a wrapper that execs vite, so signalling the
     npm pid alone leaves vite holding the port. See stopOwnServer. */
  const child = spawn('npm', ['run', 'preview', '--', '--port', String(OWN_PORT), '--strictPort'], {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  /* Published BEFORE the readiness wait, not on return.
     `ownServer = await startOwnServer()` only assigns once this function
     returns, and it does not return until the server answers or 30s pass -- so
     a SIGTERM inside that window found `ownServer` still null and the handler
     had nothing to kill. Measured: one such run left `vite preview --port 4661
     --strictPort` reparented to launchd, and the next run could not bind. */
  ownServer = child;
  let log = '';
  child.stdout.on('data', (d) => (log += d));
  child.stderr.on('data', (d) => (log += d));
  for (let i = 0; i < 60; i++) {
    if (await reachable(BASE)) return child;
    if (child.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  console.error(`FAIL: preview did not come up on port ${OWN_PORT} within 30s.`);
  console.error('      --strictPort does not move, so this is a port collision or a build fault:');
  console.error(log.trim() || '      (the server printed nothing)');
  try {
    if (child.exitCode === null) process.kill(-child.pid, 'SIGTERM');
  } catch {
    /* already gone */
  }
  process.exit(1);
}

/* By pid, and only the child this process started -- never by pattern.
 *
 * The GROUP, not the pid alone. `npm run preview` is a wrapper around vite, so
 * `process.kill(pid)` reaps npm and leaves vite listening on 4661. That is how
 * this lab's gate broke: the a11y step that runs next starts Playwright's own
 * webServer on the same port with --strictPort and reuseExistingServer false
 * in CI, so it refused with "is already used" in half a second, and the runner
 * reported "Terminate orphan process: pid (...) (node)" at job cleanup --
 * naming the leftover server after the step that should have stopped it.
 *
 * Registered on exit and on both signals, and the caller also runs it in a
 * `finally`, because every one of those is a path the old code did not cover:
 * the kill sat after the last check, so a failing check skipped it. */
function stopOwnServer() {
  if (!ownServer || ownServer.exitCode !== null) return;
  try {
    process.kill(-ownServer.pid, 'SIGTERM');
  } catch {
    try {
      process.kill(ownServer.pid, 'SIGTERM');
    } catch {
      /* already gone */
    }
  }
}

process.on('exit', stopOwnServer);
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    stopOwnServer();
    process.exit(sig === 'SIGINT' ? 130 : 143);
  });
}

if (!process.env.PREVIEW_URL) ownServer = await startOwnServer();
/* Everything after this point runs with a server this process owns, so it
   runs inside a try/finally: the stop must not depend on reaching the end. */
try {


const results = [];
const ok = (label, cond, detail = '') => {
  results.push({ label, pass: !!cond, detail });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
};

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const page = await ctx.newPage();
const consoleErrors = [];
const pageErrors = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
page.on('pageerror', (e) => pageErrors.push(String(e)));
await page.goto(BASE, { waitUntil: 'networkidle' });

// --- Single measurement + distribution toggle ---
await page.locator('[data-action="next-measurement"]').click();
await page.waitForTimeout(150);
await page.locator('[data-action="toggle-distribution"]').click();
ok('distribution histogram toggles on', await page.locator('.histogram').count() === 1);
await page.locator('[data-action="toggle-distribution"]').click();
ok('distribution histogram toggles off', await page.locator('.histogram').count() === 0);

// --- Platform toggle to Cortex-M4 ---
await page.locator('[data-action="set-platform-m4"]').click();
await page.waitForTimeout(150);
const m4active = await page.getAttribute('[data-action="set-platform-m4"]', 'aria-pressed');
ok('platform switches to Cortex-M4', m4active === 'true', `aria-pressed=${m4active}`);
const platLabel = await page.locator('.attack-line strong').nth(2).innerText().catch(() => '');
ok('attack panel reflects M4 platform', /M4/.test(platLabel), platLabel);
await page.locator('[data-action="set-platform-a7"]').click();
await page.waitForTimeout(100);

// --- Patched-mode attack: no leak, neutral banner, zero recovered ---
await page.locator('[data-action="mode-patched"]').click();
await page.locator('[data-action="speed-16"]').click();
await page.locator('[data-action="launch-attack"]').click();
// Patched run exhausts the query budget without advancing; wait for it to finish.
await page.waitForFunction(() => {
  const btn = document.querySelector('[data-action="launch-attack"]');
  return btn && !btn.hasAttribute('disabled');
}, { timeout: 30000 });
ok('patched run shows neutral banner', await page.locator('.match-pill--neutral').count() === 1);
ok('patched run leaks zero coefficients', await page.locator('.recovery-grid .recovery-cell--pos, .recovery-grid .recovery-cell--neg').count() === 0);
const bitsText = await page.locator('.meter-block:nth-of-type(2) small').innerText().catch(() => '');
ok('patched recovered-bits stays 0', /^0\s*\//.test(bitsText.trim()), bitsText.trim());

// --- Stop mid-run (vulnerable, slow) ---
await page.locator('[data-action="mode-vulnerable"]').click();
await page.locator('[data-action="speed-1"]').click();
await page.locator('[data-action="launch-attack"]').click();
await page.waitForTimeout(500); // let it get going
// Real pointer click mid-run: the control buttons must keep stable DOM nodes
// through the ~60fps repaint, or this click would be dropped.
await page.locator('[data-action="stop-attack"]').click({ timeout: 5000 });
await page.waitForFunction(() => {
  const btn = document.querySelector('[data-action="launch-attack"]');
  return btn && !btn.hasAttribute('disabled');
}, { timeout: 10000 });
const stopped = await page.locator('[data-action="launch-attack"]').isEnabled();
ok('stop halts the run (launch re-enabled)', stopped);
const halted = await page.locator('.attack-log-entry--warning').count();
ok('stop logs a halt warning', halted >= 1, `warnings=${halted}`);

// --- Regenerate key resets the grid ---
await page.locator('[data-action="regenerate-key"]').click();
await page.waitForTimeout(150);
const unknownAfterReset = await page.locator('.recovery-grid .recovery-cell--unknown').count();
ok('regenerate key resets grid to all-unknown', unknownAfterReset === 768, `unknown=${unknownAfterReset}`);

// --- Switch implementation control ---
await page.locator('[data-action="switch-implementation"]').click();
await page.waitForTimeout(100);
const patchedNow = await page.getAttribute('[data-action="mode-patched"]', 'aria-pressed');
ok('switch-implementation flips mode', patchedNow === 'true', `patched aria-pressed=${patchedNow}`);

// --- Export timing samples triggers a real download ---
const [download] = await Promise.all([
  page.waitForEvent('download', { timeout: 5000 }).catch(() => null),
  page.locator('[data-action="export-samples"]').click(),
]);
ok('export produces a JSON download', !!download && /kyberslash-.*\.json$/.test(download?.suggestedFilename() ?? ''), download?.suggestedFilename() ?? 'no download');

// --- Auto-tour starts and can be stopped cleanly ---
await page.evaluate(() => window.scrollTo(0, 0));
await page.locator('[data-action="start-tour"]').click();
await page.waitForSelector('[data-action="stop-tour"]', { timeout: 5000 });
ok('auto-tour enters running state', await page.locator('[data-action="stop-tour"]').count() === 1);
await page.waitForTimeout(1500);
await page.locator('[data-action="stop-tour"]').click();
await page.waitForSelector('[data-action="start-tour"]', { timeout: 8000 });
ok('auto-tour stops cleanly', await page.locator('[data-action="start-tour"]').count() === 1);

ok('no console errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));
ok('no uncaught page errors', pageErrors.length === 0, pageErrors.slice(0, 3).join(' | '));

await browser.close();
const failed = results.filter((r) => !r.pass);
stopOwnServer();

console.log(`\n${results.length - failed.length}/${results.length} interaction checks passed`);
  process.exitCode = failed.length === 0 ? 0 : 1;
} finally {
  stopOwnServer();
}
