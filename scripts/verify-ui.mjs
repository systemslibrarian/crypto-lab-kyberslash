// Headless smoke test for the built lab. Run `npm run preview` first, then:
//   npm run verify:ui            (defaults to the standard preview URL)
//   PREVIEW_URL=http://localhost:4661/crypto-lab-kyberslash/ npm run verify:ui
// Requires playwright + chromium (npx playwright install chromium).
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

// 1. Single banner: exactly one shared topbar, zero in-app cl-header
const topbars = await page.locator('.cl-topbar').count();
const inAppHeaders = await page.locator('header.cl-header').count();
ok('exactly one shared brand bar', topbars === 1, `cl-topbar=${topbars}`);
ok('no duplicate in-app header', inAppHeaders === 0, `cl-header=${inAppHeaders}`);

// 2. Title preserved (richer HTML title, not the old override)
const title = await page.title();
ok('rich page title preserved', /Crypto Lab/.test(title), JSON.stringify(title));

// 3. Field-note present
ok('verified field-note rendered', await page.locator('.attack-fieldnote').count() === 1);

// 4. Measurements -> leak verdict
await page.locator('[data-action="run-hundred"]').click();
await page.waitForSelector('.verdict--leak', { timeout: 15000 });
const verdictText = (await page.locator('.verdict-headline').innerText()).trim();
ok('oscilloscope reports a leak', /leak/i.test(verdictText), verdictText);

// 5. Flip overlay works (data-flip flips to patched)
await page.locator('[data-action="flip-after"]').click();
const flipState = await page.getAttribute('.flip-chart', 'data-flip');
ok('flip-to-patched switches overlay', flipState === 'patched', `data-flip=${flipState}`);

// 6. Full attack run -> verified 768/768 gold pill
await page.locator('[data-action="speed-16"]').click();
await page.locator('[data-action="launch-attack"]').click();
await page.waitForSelector('.match-pill--total', { timeout: 45000 });
const pill = (await page.locator('.match-pill--total').innerText()).trim();
ok('attack recovers full key (gold pill)', /768\s*\/\s*768/.test(pill), pill);
ok('no missing coefficients after run', (await page.locator('.recovery-grid .recovery-cell--unknown').count()) === 0);

// 7. Sticky rail sits below the header (not occluded). Scroll and compare rects.
await page.evaluate(() => window.scrollTo(0, 1200));
await page.waitForTimeout(300);
const rects = await page.evaluate(() => {
  const bar = document.querySelector('.cl-topbar')?.getBoundingClientRect();
  const rail = document.querySelector('.exhibit-rail')?.getBoundingClientRect();
  return { barBottom: bar?.bottom, railTop: rail?.top, railVisible: rail ? rail.top >= 0 && rail.height > 0 : false };
});
ok('exhibit rail not hidden behind header', rects.railTop >= (rects.barBottom - 2), `railTop=${Math.round(rects.railTop)} barBottom=${Math.round(rects.barBottom)}`);

await page.screenshot({ path: 'scripts/shot-desktop-dark.png', fullPage: false });

// 8. Dark is the only theme, and the shared header carries no toggle
await page.evaluate(() => window.scrollTo(0, 0));
const theme = await page.getAttribute('html', 'data-theme');
ok('page is pinned to the dark theme', theme === 'dark', `data-theme=${theme}`);
ok('shared header ships no theme toggle', (await page.locator('#cl-theme-toggle').count()) === 0);

// 9. Mobile viewport renders (375px)
const mobile = await ctx.newPage();
await mobile.goto(BASE, { waitUntil: 'networkidle' });
await mobile.setViewportSize({ width: 375, height: 800 });
await mobile.waitForTimeout(300);
const heroVisible = await mobile.locator('.hero-copy h1').isVisible();
ok('mobile hero renders', heroVisible);
await mobile.screenshot({ path: 'scripts/shot-mobile.png', fullPage: false });

// 10. No console / page errors
ok('no console errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));
ok('no uncaught page errors', pageErrors.length === 0, pageErrors.slice(0, 3).join(' | '));

await browser.close();

const failed = results.filter((r) => !r.pass);
stopOwnServer();

console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exitCode = failed.length === 0 ? 0 : 1;
} finally {
  stopOwnServer();
}
