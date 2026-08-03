/**
 * Claims spec — the page's headline verdicts, counters and failure paths,
 * asserted against values the page itself computed.
 *
 * The a11y gate scans this page but never drives it, so nothing here was
 * previously checked: not the "Leak detected" verdict, not the 768/768 verified
 * key recovery, not the patched path's refusal to leak, not the two-probe truth
 * table, and not the per-target retargeting the README makes its centrepiece.
 */
import { expect, test, type Locator, type Page } from '@playwright/test';

/** "1,234" / "1,234.5" -> number. */
function n(text: string): number {
  const m = text.replace(/,/g, '').match(/-?\d+(?:\.\d+)?/);
  expect(m, `no number in: ${text}`).not.toBeNull();
  return Number(m![0]);
}

/**
 * Raw DOM text, NOT innerText: several of these labels are `text-transform:
 * uppercase` in CSS, and innerText applies that transform, so comparing
 * rendered casing would be comparing the stylesheet rather than the page's
 * computed content.
 */
async function textOf(loc: Locator): Promise<string> {
  const t = await loc.evaluate((el) => el.textContent ?? '');
  return t.replace(/\s+/g, ' ').trim();
}

async function allTextOf(loc: Locator): Promise<string[]> {
  const t = await loc.evaluateAll((els) => els.map((el) => el.textContent ?? ''));
  return t.map((s) => s.replace(/\s+/g, ' ').trim());
}

/** The four `<dd>` values of the flip overlay readout, by their `<dt>` label. */
async function readout(page: Page, label: string): Promise<number> {
  return n(await textOf(page.locator('.flip-readout div', { hasText: label }).locator('dd')));
}

// ------------------------------------------------------- Exhibit 2: the leak

test('exhibit 2 — the leak verdict is what the page’s own numbers imply', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('button', { name: 'Run 100 measurements' }).click();
  await expect(page.locator('#exhibit-2')).toHaveAttribute('aria-busy', 'false');

  // The two trace cards each publish their own mean and variance span.
  const vulnFooter = await textOf(page.locator('.trace-card--danger footer'));
  const safeFooter = await textOf(page.locator('.trace-card--safe footer'));
  const vulnMean = n(vulnFooter.split('Variance')[0]);
  const safeMean = n(safeFooter.split('Variance')[0]);
  const vulnSpan = n(vulnFooter.split('Variance span:')[1]);
  const safeSpan = n(safeFooter.split('Variance span:')[1]);

  // The patched path is constant-time: its spread is exactly zero, and the
  // page must say so rather than quietly reading 0x.
  expect(safeSpan).toBe(0);
  expect(vulnSpan).toBeGreaterThan(0);

  const verdict = page.locator('#exhibit-2 .verdict');
  const rows = await allTextOf(verdict.locator('.verdict-row'));
  const varianceRatio = rows.find((r) => r.includes('Variance ratio'))!;
  const meanDelta = rows.find((r) => r.includes('Mean delta'))!;
  const meanRatio = rows.find((r) => r.includes('Mean ratio'))!;

  // Infinite spread ratio, because the denominator really is zero.
  expect(varianceRatio).toContain('∞× wider');
  // Mean delta must equal the difference of the two published means.
  expect(Math.abs(n(meanDelta.split('Mean delta')[1]) - (vulnMean - safeMean))).toBeLessThanOrEqual(1);
  // Mean ratio must equal their quotient.
  expect(Math.abs(n(meanRatio.split('Mean ratio')[1]) - vulnMean / safeMean)).toBeLessThan(0.01);

  await expect(verdict).toHaveClass(/verdict--leak/);
  expect(await textOf(verdict.locator('.verdict-headline'))).toBe(
    'Leak detected — vulnerable path swings, patched path is flat.',
  );
});

test('exhibit 2 — the flip overlay’s spread-collapse figure is derived from its own spreads', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('button', { name: 'Run 100 measurements' }).click();
  await expect(page.locator('#exhibit-2')).toHaveAttribute('aria-busy', 'false');

  await expect(page.locator('.flip-chart')).toHaveAttribute('data-flip', 'vulnerable');
  await expect(page.locator('.flip-sub')).toContainText('Now flip the implementation.');

  const vulnSpread = await readout(page, 'Vulnerable spread');
  const patchedSpread = await readout(page, 'Patched spread');
  const collapse = await readout(page, 'Spread collapse');
  const meanShift = await readout(page, 'Mean shift');

  expect(vulnSpread).toBeGreaterThan(0);
  expect(patchedSpread).toBe(0);
  // collapse = 1 - patched/vulnerable, as a percentage.
  expect(collapse).toBeCloseTo((1 - patchedSpread / vulnSpread) * 100, 1);
  expect(meanShift).toBeGreaterThan(0);

  // The signature moment: flipping changes the rendered state and says so.
  await page.getByRole('button', { name: 'Flip to patched' }).click();
  await expect(page.locator('.flip-chart')).toHaveAttribute('data-flip', 'patched');
  await expect(page.locator('.flip-sub')).toContainText('The signal vanished.');
  // Same dataset — the numbers must not move when only the view flips.
  expect(await readout(page, 'Vulnerable spread')).toBe(vulnSpread);
  expect(await readout(page, 'Patched spread')).toBe(patchedSpread);
});

// -------------------------------------------- Exhibit 3: the two-probe logic

/** The walkthrough's three states, and the fast/slow pair each must produce. */
const WALKTHROUGH = [
  { action: 'walk-neg', sign: '−1', low: 'FAST', high: 'FAST' },
  { action: 'walk-zero', sign: '0', low: 'FAST', high: 'SLOW' },
  { action: 'walk-pos', sign: '+1', low: 'SLOW', high: 'SLOW' },
] as const;

test('exhibit 3 — every secret value produces its own timing pair, and the arithmetic checks out', async ({
  page,
}) => {
  await page.goto('.');

  const seenPairs = new Set<string>();
  for (const row of WALKTHROUGH) {
    await page.locator(`[data-action="${row.action}"]`).click();
    await expect(page.locator(`[data-action="${row.action}"]`)).toHaveAttribute('aria-pressed', 'true');

    const cards = page.locator('.probe-card');
    await expect(cards).toHaveCount(2);

    const verdicts = await allTextOf(cards.locator('.probe-verdict'));
    expect(verdicts).toEqual([row.low, row.high]);
    seenPairs.add(verdicts.join('/'));

    // Re-derive the device-side arithmetic the card prints:
    //   w = s + probe,  numerator = 2*w + 1664.
    for (let i = 0; i < 2; i++) {
      const maths = await allTextOf(cards.nth(i).locator('.probe-math'));
      // "device adds secret: w = +1 + 833 = 834"
      const add = maths[0].replace(/,/g, '').match(/w = (−?\+?\d+) \+ (\d+) = (−?\d+)/);
      expect(add, `unexpected probe math: ${maths[0]}`).not.toBeNull();
      const secret = Number(add![1].replace('−', '-').replace('+', ''));
      const probe = Number(add![2]);
      const w = Number(add![3].replace('−', '-'));
      // "numerator handed to __divsi3: 2·834 + 1664 = 3332"
      const num = maths[1].replace(/,/g, '').match(/2·(\d+) \+ 1664 = (\d+)/);
      expect(num, `unexpected numerator math: ${maths[1]}`).not.toBeNull();
      expect(Number(num![1])).toBe(w);
      expect(Number(num![2])).toBe(2 * w + 1664);
      // The device really added the hidden secret to the attacker's offset.
      expect(secret).toBe(Number(row.sign.replace('−', '-')));
      expect(w - probe).toBe(secret);
    }

    // The truth table's conclusion must name the secret we selected.
    const result = await textOf(page.locator('.truth-result'));
    expect(result).toContain(`(${row.low.toLowerCase()}, ${row.high.toLowerCase()})`);
    expect(result).toContain(`unique to s = ${row.sign}`);

    // Exactly one truth-table row is marked active, and it is this one.
    await expect(page.locator('.truth-table tbody tr.is-active')).toHaveCount(1);
    expect(await textOf(page.locator('.truth-table tbody tr.is-active th'))).toBe(`s = ${row.sign}`);
  }

  // "unique" means unique: three secrets, three distinct timing pairs.
  expect(seenPairs.size).toBe(3);
});

// ------------------------------------ Exhibit 3: the attack, and its failure

test('exhibit 3 — the vulnerable run recovers all 768 coefficients and verifies them', async ({ page }) => {
  test.slow();
  await page.goto('.');
  await page.locator('[data-action="speed-16"]').click();
  await page.locator('[data-action="mode-vulnerable"]').click();
  await page.getByRole('button', { name: 'Launch KyberSlash attack' }).click();

  await expect(page.locator('#exhibit-3')).toHaveAttribute('aria-busy', 'false', { timeout: 120_000 });

  // The headline: a verified match against the real key, not just "done".
  const pill = page.locator('.match-pill');
  await expect(pill).toHaveClass(/match-pill--total/);
  const pillText = await textOf(pill);
  const [matched, total] = pillText.replace(/,/g, '').match(/(\d+) \/ (\d+)/)!.slice(1).map(Number);
  expect(matched).toBe(total);
  expect(total).toBe(768);
  expect(pillText).toContain('Recovered key matches secret');
  expect(pillText).toContain('(100%)');

  // The header's own count must agree with the pill.
  expect(n(await textOf(page.locator('.recovery-header strong')))).toBe(total);

  // Every grid cell is resolved — none left unknown — and the resolved values
  // partition into exactly the three the lab claims to distinguish.
  await expect(page.locator('.recovery-grid .recovery-cell--unknown')).toHaveCount(0);
  const pos = await page.locator('.recovery-grid .recovery-cell--pos').count();
  const neg = await page.locator('.recovery-grid .recovery-cell--neg').count();
  const zero = await page.locator('.recovery-grid .recovery-cell--zero').count();
  expect(pos + neg + zero).toBe(total);
  expect(pos).toBeGreaterThan(0);
  expect(neg).toBeGreaterThan(0);
  expect(zero).toBeGreaterThan(0);

  // Meters: two bits per coefficient, and the run stayed inside its budget.
  const meters = await allTextOf(page.locator('.meter-block'));
  const bits = meters.find((m) => m.includes('Bits recovered'))!.replace(/,/g, '').match(/(\d+) \/ (\d+)/)!;
  expect(Number(bits[1])).toBe(Number(bits[2]));
  expect(Number(bits[2])).toBe(2 * total);
  const queries = meters.find((m) => m.includes('Queries sent'))!.replace(/,/g, '').match(/(\d+) \/ (\d+)/)!;
  expect(Number(queries[1])).toBeLessThanOrEqual(Number(queries[2]));
  expect(Number(queries[1])).toBeGreaterThan(0);

  // The statistical test says the signal is real.
  expect(await textOf(page.locator('.analysis-box strong'))).toBe('Signal present');

  // Every milestone was crossed, and the log recorded the completion.
  await expect(page.locator('.milestone:not(.is-reached)')).toHaveCount(0);
  await expect(page.locator('.attack-log-list')).toContainText('key fully recovered');
});

test('exhibit 3 — the patched run is the failure path: nothing leaks, and it says why', async ({ page }) => {
  test.slow();
  await page.goto('.');
  await page.locator('[data-action="speed-16"]').click();
  await page.locator('[data-action="mode-patched"]').click();
  await expect(page.locator('[data-action="mode-patched"]')).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Launch KyberSlash attack' }).click();

  await expect(page.locator('#exhibit-3')).toHaveAttribute('aria-busy', 'false', { timeout: 120_000 });

  // Zero recovery, stated as a verdict rather than left blank.
  await expect(page.locator('.match-pill')).toHaveClass(/match-pill--neutral/);
  expect(await textOf(page.locator('.match-pill'))).toBe('Patched path · zero coefficients leaked');
  expect(n(await textOf(page.locator('.recovery-header strong')))).toBe(0);
  await expect(page.locator('.recovery-grid .recovery-cell--unknown')).toHaveCount(768);
  await expect(page.locator('.recovery-grid .recovery-cell--pos')).toHaveCount(0);
  await expect(page.locator('.recovery-grid .recovery-cell--neg')).toHaveCount(0);

  // Bits recovered is zero while the query budget was actually spent — i.e.
  // the attack ran and failed, rather than never running.
  const meters = await allTextOf(page.locator('.meter-block'));
  const bits = meters.find((m) => m.includes('Bits recovered'))!.replace(/,/g, '').match(/(\d+) \/ (\d+)/)!;
  expect(Number(bits[1])).toBe(0);
  const queries = meters.find((m) => m.includes('Queries sent'))!.replace(/,/g, '').match(/(\d+) \/ (\d+)/)!;
  expect(Number(queries[1])).toBe(Number(queries[2]));

  // And the reason is on screen.
  expect(await textOf(page.locator('.analysis-box strong'))).toBe('Noise floor only');
  await expect(page.locator('.attack-log-list')).toContainText('no statistical signal above noise floor');
  await expect(page.locator('.milestone.is-reached')).toHaveCount(0);
});

/**
 * REGRESSION for a bug this spec found: the correlation readout was recomputed
 * at paint time from `state.attackState.timingProfile`, which `attackIteration`
 * clears the instant a coefficient falls. The panel therefore reported
 * "Noise floor only" alongside "confidence = 0.999", and the "Signal present"
 * headline was unreachable on the very path where the signal exists.
 */
test('exhibit 3 — regression: the correlation readout never contradicts its own confidence', async ({
  page,
}) => {
  test.slow();
  await page.goto('.');
  await page.locator('[data-action="speed-1"]').click();
  await page.locator('[data-action="mode-vulnerable"]').click();
  await page.getByRole('button', { name: 'Launch KyberSlash attack' }).click();

  let sawSignal = false;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const text = await textOf(page.locator('.analysis-box'));
    const confidence = Number(text.match(/confidence = ([\d.]+)/)![1]);
    const present = text.includes('Signal present');
    // A high-confidence reading may never be labelled the noise floor.
    expect(confidence < 0.9 || present, `contradiction: ${text}`).toBe(true);
    if (present) sawSignal = true;
    if ((await page.locator('#exhibit-3').getAttribute('aria-busy')) === 'false') break;
  }
  expect(sawSignal, 'the vulnerable path never reported a detectable signal').toBe(true);
});

// ------------------------------------------- Per-target retargeting (README)

/** Every cost step the mechanism panel lists, as {numerator, jump, coefficient}. */
async function costSteps(page: Page): Promise<{ numerator: number; jump: number; coefficient: number }[]> {
  const items = await allTextOf(page.locator('.why-leak-steps li'));
  return items.map((raw) => {
    const t = raw.replace(/,/g, '').replace(/\s+/g, ' ');
    return {
      numerator: Number(t.match(/numerator ≥ (\d+)/)![1]),
      jump: Number(t.match(/\+(\d+) cycle/)![1]),
      coefficient: Number(t.match(/t ≥ (\d+)/)![1]),
    };
  });
}

const TARGETS = [
  {
    action: 'set-platform-a7',
    device: 'Raspberry Pi 2',
    op: '__divsi3',
    // Paper §5.1.1 / §5.1.2.
    steps: [
      { numerator: 3329, jump: 20, coefficient: 833 },
      { numerator: 4096, jump: 2, coefficient: 1216 },
      { numerator: 8192, jump: 1, coefficient: 3264 },
    ],
    probes: [832, 833],
  },
  {
    action: 'set-platform-m4',
    device: 'STM32F407VG',
    op: 'udiv',
    // Paper Table 4 — 2^11 is the only crossover inside 1664..8320.
    steps: [{ numerator: 2048, jump: 2, coefficient: 192 }],
    probes: [191, 192],
  },
] as const;

for (const target of TARGETS) {
  test(`retargeting — ${target.device} shows its own mechanism, steps and probes`, async ({ page }) => {
    await page.goto('.');
    await page.locator(`[data-action="${target.action}"]`).click();
    await expect(page.locator(`[data-action="${target.action}"]`)).toHaveAttribute('aria-pressed', 'true');

    expect(await textOf(page.locator('.why-leak-eyebrow'))).toBe(`Mechanism · ${target.device}`);
    await expect(page.locator('.why-leak-steps-label')).toContainText(`${target.op} on ${target.device}`);

    const steps = await costSteps(page);
    expect(steps).toEqual([...target.steps]);
    // Every listed coefficient must be the one its own numerator implies:
    // the smallest t with 2t + 1664 >= numerator.
    for (const s of steps) {
      expect(s.coefficient).toBe(Math.ceil((s.numerator - 1664) / 2));
      // ...and it must be reachable from this line at all.
      expect(2 * s.coefficient + 1664).toBeGreaterThanOrEqual(1664);
      expect(2 * s.coefficient + 1664).toBeLessThanOrEqual(8320);
    }

    // The walkthrough straddles the biggest of those steps.
    const biggest = steps.reduce((best, s) => (s.jump > best.jump ? s : best), steps[0]);
    const chips = await allTextOf(page.locator('.probe-card .probe-chip'));
    expect(chips.map((c) => Number(c.replace(/[^0-9]/g, '')))).toEqual([...target.probes]);
    expect(target.probes[1]).toBe(biggest.coefficient);
    await expect(page.locator('.walkthrough-lead')).toContainText(`+${biggest.jump}-cycle`);

    // Each probe card's numerator lands on the side of the step its verdict claims.
    for (let i = 0; i < 2; i++) {
      const card = page.locator('.probe-card').nth(i);
      const slow = (await textOf(card.locator('.probe-verdict'))) === 'SLOW';
      const dividend = Number(
        (await textOf(card.locator('.probe-math').nth(1))).replace(/,/g, '').match(/= (\d+)/)![1],
      );
      expect(dividend >= biggest.numerator).toBe(slow);
    }
  });
}

// ------------------------------------------------ Exhibit 1: the fix on show

test('exhibit 1 — the vulnerable line and the upstream fix are both shown, with the real constants', async ({
  page,
}) => {
  await page.goto('.');

  const code = page.locator('#exhibit-1 .code-card');
  await expect(code).toHaveClass(/is-danger/);
  await expect(code).toContainText('t = (((t << 1) + KYBER_Q/2) / KYBER_Q) & 1;');
  // The division is the highlighted danger line, not just present in the file.
  const dangerLine = page.locator('#exhibit-1 .code-line--hl-danger');
  await expect(dangerLine).toHaveCount(1);
  expect(await textOf(dangerLine)).toContain('/ KYBER_Q');

  await page.locator('[data-action="code-patched"]').click();
  await expect(code).toHaveClass(/is-safe/);
  // The upstream fix, verbatim: multiply by floor(2^28/3329) = 80635, shift 28.
  await expect(code).toContainText('80635');
  await expect(code).not.toContainText('/ KYBER_Q');
  await expect(page.locator('#exhibit-1 .evidence-list')).toContainText('dda29cc');

  // Barrett panel: the 32-bit constant the lab computes with is floor(2^32/q)+1.
  const expected = Math.floor(2 ** 32 / 3329) + 1;
  expect(expected).toBe(1290168);
  await expect(page.locator('.barrett-col--safe .barrett-instr')).toContainText(
    expected.toLocaleString('en-US'),
  );
  // ...and the patched band figure really is one flat cost across every band.
  const flatCosts = await allTextOf(page.locator('.bands-track--flat .band-cycles'));
  expect(flatCosts.length).toBeGreaterThan(1);
  expect(new Set(flatCosts.map((c) => c.trim())).size).toBe(1);
});

test('exhibit 5 — the KyberSlash2 figures show the patch removing cycles', async ({ page }) => {
  await page.goto('.');
  const copy = await textOf(page.locator('.callout', { hasText: 'KyberSlash2 in one line' }));
  const m = copy.replace(/,/g, '').match(/lands at (\d+) cycles before the patch and (\d+) after it/);
  expect(m, `unexpected KyberSlash2 copy: ${copy}`).not.toBeNull();
  expect(Number(m![1])).toBeGreaterThan(Number(m![2]));
});
