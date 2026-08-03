// Extended interaction coverage — the paths the main smoke test skips.
// Run `npm run preview` first. PREVIEW_URL overrides the default port.
import { chromium } from 'playwright';

const BASE = process.env.PREVIEW_URL ?? 'http://localhost:4705/crypto-lab-kyberslash/';
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
console.log(`\n${results.length - failed.length}/${results.length} interaction checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
