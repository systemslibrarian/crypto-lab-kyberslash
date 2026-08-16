// Headless smoke test for the built lab. Run `npm run preview` first, then:
//   npm run verify:ui            (defaults to the standard preview URL)
//   PREVIEW_URL=http://localhost:4174/crypto-lab-kyberslash/ npm run verify:ui
// Requires playwright + chromium (npx playwright install chromium).
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
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
