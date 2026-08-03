import './style.css';
import './_teaching.css';

import {
  activeProbes,
  attackIteration,
  createAttackState,
  generateSecretKey,
  getRecoveredCoeff,
  statisticalAnalysis,
  walkthroughCoefficient,
  type AttackState,
  type SecretKey,
  type TimingAnalysis,
} from './attack';
import {
  BARRETT_INV_Q,
  KYBER_PARAMS,
  polyCompressPatched,
  polyCompressVulnerable,
  polyTomsgPatched,
  polyTomsgVulnerable,
} from './implementations';
import {
  aggregateTimings,
  coefficientSteps,
  displayBandIndex,
  getDisplayBands,
  getPlatformProfile,
  kyberSlash1Dividend,
  KYBERSLASH1_NUMERATOR_MAX,
  KYBERSLASH1_NUMERATOR_MIN,
  patchedDivCycles,
  PLATFORM_LABELS,
  primaryCoefficientStep,
  setActivePlatform,
  type LatencyBand,
  type Platform,
} from './timing-model';

type ThemeMode = 'dark' | 'light';
type CodeMode = 'vulnerable' | 'patched';
type AttackMode = 'vulnerable' | 'patched';
type FlipMode = 'before' | 'after';
type AttackSpeed = 1 | 4 | 16;
type LogKind = 'info' | 'recovery' | 'milestone' | 'warning' | 'success';

interface RecoveryEvent {
  coefficient: number;
  confidence: number;
  value: number;
}

interface LogEntry {
  kind: LogKind;
  text: string;
  elapsedSeconds: number;
  query: number;
}

interface AppState {
  theme: ThemeMode;
  platform: Platform;
  codeMode: CodeMode;
  showDistribution: boolean;
  measuring: boolean;
  measurementIndex: number;
  vulnerableSamples: number[];
  patchedSamples: number[];
  flipMode: FlipMode;
  attackMode: AttackMode;
  attackSpeed: AttackSpeed;
  attackRunning: boolean;
  tourRunning: boolean;
  tourStopRequested: boolean;
  attackStopRequested: boolean;
  attackRunId: number;
  attackSecret: SecretKey;
  attackState: AttackState;
  attackQueryTimes: number[];
  attackEvents: RecoveryEvent[];
  attackLog: LogEntry[];
  attackStartedAt: number | null;
  /**
   * The correlation test behind the most recent recovery decision (or, before
   * any decision, the live one). Held in state rather than recomputed at paint
   * time because `attackIteration` clears the sample buckets the moment a
   * coefficient falls, so re-deriving it from the live profile reported the
   * noise floor at precisely the moment the signal was decisive — the readout
   * used to print "Noise floor only" beside "confidence = 0.999".
   */
  attackAnalysis: TimingAnalysis | null;
  milestonesReached: number[];
  statusMessage: string;
  walkthroughSecret: -1 | 0 | 1;
}

const QUOTE = '"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."';
const ATTACK_QUERY_BUDGET = 20000;
const TRACE_LIMIT = 28;

type CodeLine = { text: string; hl?: 'danger' | 'safe' };

const VULNERABLE_LINES: readonly CodeLine[] = [
  { text: '// Kyber reference implementation - poly_tomsg function' },
  { text: '// KyberSlash1, pre-patch reference C code' },
  { text: '' },
  { text: 'for (int j = 0; j < 8; j++) {' },
  { text: '    t = a->coeffs[8*i+j];' },
  { text: '    t += ((int16_t)t >> 15) & KYBER_Q;' },
  { text: '' },
  { text: '    // Secret-dependent division by q = 3329' },
  { text: '    t = (((t << 1) + KYBER_Q/2) / KYBER_Q) & 1;', hl: 'danger' },
  { text: '' },
  { text: '    msg[i] |= t << j;' },
  { text: '}' },
];

/**
 * The ACTUAL upstream fix, verbatim from pq-crystals/kyber commit dda29cc
 * ("Updated poly_tomsg to prevent a compiler from using DIV", 1 December 2023).
 * It is a multiply-and-shift — the same idea the Barrett panel below explains —
 * but with a 28-bit constant, `floor(2^28/3329) = 80635`, and `+1665` rather
 * than `+1664`. Verified exhaustively: it returns the same bit as the original
 * `(((t << 1) + KYBER_Q/2)/KYBER_Q) & 1` for every t in 0..3328.
 *
 * Showing an invented constant here would have been the easy thing to do, and
 * would have been a claim the repository could not back. This is what shipped.
 */
const PATCHED_LINES: readonly CodeLine[] = [
  { text: '// pq-crystals/kyber ref/poly.c, commit dda29cc (1 Dec 2023)' },
  { text: '// 80635 = floor(2^28 / 3329); multiply-and-shift, no DIV' },
  { text: '' },
  { text: 'for (int j = 0; j < 8; j++) {' },
  { text: '    t = a->coeffs[8*i+j];' },
  { text: '' },
  { text: '    // No division instruction on secret data' },
  { text: '    t <<= 1;', hl: 'safe' },
  { text: '    t += 1665;', hl: 'safe' },
  { text: '    t *= 80635;', hl: 'safe' },
  { text: '    t >>= 28;', hl: 'safe' },
  { text: '    t &= 1;', hl: 'safe' },
  { text: '' },
  { text: '    msg[i] |= t << j;' },
  { text: '}' },
];

/**
 * Every entry below is taken from the KyberSlash project's own History section
 * (https://kyberslash.cr.yp.to/papers.html) and its per-library patch table
 * (https://kyberslash.cr.yp.to/libraries.html), or from the pq-crystals commit
 * log. An earlier version of this array placed the whole story in 2024 and
 * asserted that the reference code was "patched before public disclosure" —
 * both wrong. The discovery, the reference patch and the public announcement
 * all happened in November-December 2023, and most downstream libraries were
 * patched *after* the issue was public.
 */
const TIMELINE = [
  ['2022 Jul', 'NIST selects Kyber for post-quantum standardization.'],
  ['2023 Nov', 'Goutam Tamvada, Karthikeyan Bhargavan and Franziskus Kiefer (Cryspen) notice the secret-dependent division while writing a formally verified Rust implementation of Kyber, and report it to the pq-crystals maintainer.'],
  ['2023 Dec 1', 'pq-crystals/kyber reference code patched for KyberSlash1 — commit dda29cc, "Updated poly_tomsg to prevent a compiler from using DIV". Still non-public.'],
  ['2023 Dec 15', 'Daniel J. Bernstein, who found the same divisions independently while auditing SUPERCOP, announces them on the NIST pqc-forum as a "possibly exploitable" issue. This is the public disclosure.'],
  ['2023 Dec 19', 'The kyberslash.cr.yp.to FAQ goes up. On exploitability it says only: "Maybe. Patch now; don’t wait to see whether an exploit is demonstrated."'],
  ['2023 Dec 30', 'Prasanna Ravi and Matthias J. Kannwischer report the further secret-dependent divisions in poly_compress / polyvec_compress — KyberSlash2; pq-crystals patches them. Bernstein posts a Raspberry Pi 2 demo recovering a complete Kyber512 key, succeeding twice in three experiments.'],
  ['2024', 'Downstream patching takes months, not days, and happens in the open: cloudflare/circl 1 Jan, liboqs 8 Jan (KyberSlash2), PQClean 25 Jan, pqm4 23 Feb (KyberSlash2), kyberlib 12 May, PQClean aarch64 19 Sep.'],
  ['2024 Jun', 'Improved KyberSlash1 and KyberSlash2 demos published alongside the first version of the paper.'],
  ['2024 Aug 13', 'ML-KEM published as FIPS 203 — eight months after the leak was public.'],
  ['2025', 'Final paper in IACR TCHES 2025(2):209–234; CHES 2025 Best Paper Award. As of the project’s August 2025 survey, two Kyber libraries still had divisions on secret inputs.'],
] as const;

const LESSONS = [
  'Standardization is a mathematical contract, not a side-channel guarantee.',
  'The vulnerable reference code had formal security context and years of review, yet a plain division still leaked secret information.',
  'Automated tooling matters: Bernstein et al. also contributed a Valgrind patch that tracks variable-time instructions on secret data.',
  'Compiler settings matter. Modern x86_64 often avoids the bug only because the compiler rewrites division into multiplication, but size-focused builds like -Os can reintroduce real division on some targets.',
  'Safe deployments need maintained libraries, target-platform timing analysis, and explicit constant-time review.',
] as const;

interface CrossLink {
  slug: string;
  title: string;
  description: string;
  href: string;
  tone: 'teal' | 'violet' | 'amber' | 'crimson';
}

const CROSSLINKS: readonly CrossLink[] = [
  {
    slug: 'crypto-lab-kyber-vault',
    title: 'Kyber Vault',
    description: 'ML-KEM-768 baseline demo — encapsulation and decapsulation with verified parameters.',
    href: 'https://crypto-lab.systemslibrarian.dev/',
    tone: 'teal',
  },
  {
    slug: 'crypto-lab-pq-tls-handshake',
    title: 'PQ TLS Handshake',
    description: 'Where ML-KEM lands inside TLS 1.3 — hybrid key agreement walked end-to-end.',
    href: 'https://crypto-lab.systemslibrarian.dev/',
    tone: 'violet',
  },
  {
    slug: 'crypto-lab-lattice-fault',
    title: 'Lattice Fault',
    description: 'Fault-injection attacks against lattice systems — bit flips that break decryption.',
    href: 'https://crypto-lab.systemslibrarian.dev/',
    tone: 'crimson',
  },
  {
    slug: 'crypto-lab-timing-oracle',
    title: 'Timing Oracle',
    description: 'Classical timing-oracle failures — the genealogy KyberSlash inherits from.',
    href: 'https://crypto-lab.systemslibrarian.dev/',
    tone: 'amber',
  },
  {
    slug: 'crypto-lab-padding-oracle',
    title: 'Padding Oracle',
    description: 'Implementation bugs defeating correct mathematics — the same shape, decades earlier.',
    href: 'https://crypto-lab.systemslibrarian.dev/',
    tone: 'amber',
  },
  {
    slug: 'crypto-lab-model-breach',
    title: 'Model Breach',
    description: 'Broader deployment failures across the post-quantum stack.',
    href: 'https://crypto-lab.systemslibrarian.dev/',
    tone: 'violet',
  },
];

interface ExhibitMeta {
  number: number;
  id: string;
  title: string;
  shortTitle: string;
}

const EXHIBITS: readonly ExhibitMeta[] = [
  { number: 1, id: 'exhibit-1', title: 'The vulnerable line of code', shortTitle: 'Smoking gun' },
  { number: 2, id: 'exhibit-2', title: 'The oscilloscope', shortTitle: 'Measure leak' },
  { number: 3, id: 'exhibit-3', title: 'Live attack progress', shortTitle: 'Recover key' },
  { number: 4, id: 'exhibit-4', title: 'The disclosure timeline', shortTitle: 'Disclosure' },
  { number: 5, id: 'exhibit-5', title: 'What this means for PQ deployment', shortTitle: 'Lessons' },
];

interface Bridge {
  proved: string;
  next: string;
}

const BRIDGES: readonly Bridge[] = [
  {
    proved: 'One division on a secret-dependent operand becomes the whole story.',
    next: 'Now measure exactly what that one line costs the attacker.',
  },
  {
    proved: 'Variable timing means the secret leaks one cycle at a time.',
    next: 'Time to put that leak to work and recover the key in your browser.',
  },
  {
    proved: '768 coefficients fall to a model that costs nothing to run.',
    next: 'Compare what the field already knew about the failure window.',
  },
  {
    proved: 'Industry patched in months because the fix is local and small.',
    next: 'So what does any of this mean for a team shipping ML-KEM today?',
  },
];

const MILESTONE_PCT: readonly number[] = [10, 25, 50, 75, 100];
const ATTACK_LOG_LIMIT = 24;

const TRY_THIS: readonly string[] = [
  'Toggle between <strong>Vulnerable reference C</strong> and <strong>Patched Barrett reduction</strong> below. The single highlighted line is the entire bug — and the entire fix. The vulnerable line divides by <code>q = 3329</code>; the patched line replaces division with multiplication and a shift.',
  'Press <strong>Run 100 measurements</strong>. Watch the verdict bar above turn red. The vulnerable mean drifts; the patched mean stays flat — that timing gap is the secret leaking. Then try <strong>Cortex-M4</strong> in the hero — same story, smaller spread.',
  'Press <strong>Launch KyberSlash attack</strong>. The 768 cells below light up coefficient by coefficient, and the gold pill confirms the recovered key matches the real one. When it finishes, switch to <strong>Patched path</strong> and launch again — nothing happens, because the leak is gone.',
  'Skim the dates. NIST <em>selected</em> Kyber in <strong>July 2022</strong>; the division leak was found and made public in <strong>November&ndash;December 2023</strong>; ML-KEM only became <strong>FIPS 203</strong> in <strong>August 2024</strong>, eight months after the leak was public. Note also what the patch dates say: most libraries were fixed <em>after</em> disclosure, over months. "Standardised" and "safe to deploy on your target" are not the same property.',
  'Read one lesson per scroll. The cards at the bottom point to neighbouring failure modes in the broader Crypto Lab — fault injection, classical timing oracles, padding oracles — so you can see how KyberSlash fits into the wider implementation-bug genealogy.',
];

function renderTryThis(index: number): string {
  const text = TRY_THIS[index];
  if (!text) {
    return '';
  }
  return `
    <aside class="try-this" aria-label="What to try in this exhibit">
      <span class="try-this-label">Try this</span>
      <p>${text}</p>
    </aside>`;
}

const appRoot = document.querySelector<HTMLDivElement>('#app');

if (!appRoot) {
  throw new Error('Application root not found');
}

const app = appRoot;

const initialTheme = (document.documentElement.getAttribute('data-theme') ?? 'dark') as ThemeMode;
const initialPlatform: Platform = (() => {
  const stored = localStorage.getItem('platform');
  return stored === 'cortex-m4' ? 'cortex-m4' : 'cortex-a7';
})();
setActivePlatform(initialPlatform);
const initialSecret = generateSecretKey();

const state: AppState = {
  theme: initialTheme,
  platform: initialPlatform,
  codeMode: 'vulnerable',
  showDistribution: false,
  measuring: false,
  measurementIndex: 0,
  vulnerableSamples: [],
  patchedSamples: [],
  flipMode: 'before',
  attackMode: 'vulnerable',
  attackSpeed: 1,
  attackRunning: false,
  tourRunning: false,
  tourStopRequested: false,
  attackStopRequested: false,
  attackRunId: 0,
  attackSecret: initialSecret,
  attackState: createAttackState(initialSecret),
  attackQueryTimes: [],
  attackEvents: [],
  attackLog: [],
  attackStartedAt: null,
  attackAnalysis: null,
  milestonesReached: [],
  statusMessage: 'KyberSlash lab ready. Initial timing traces loaded.',
  walkthroughSecret: 0,
};

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function setStatusMessage(message: string): void {
  state.statusMessage = message;
}

/**
 * Inline first-mention gloss. Renders the term with a dotted underline (a visible
 * affordance, not color-only) and a native tooltip; the definition is also
 * exposed to assistive tech via aria-label so it isn't hover-only. Keyboard
 * focusable so the tooltip is reachable without a mouse.
 */
function glossTerm(term: string, definition: string): string {
  const safeTerm = escapeHtml(term);
  const safeDef = escapeHtml(definition);
  return `<span class="gloss" tabindex="0" role="note" title="${safeTerm}: ${safeDef}" aria-label="${safeTerm}: ${safeDef}">${safeTerm}</span>`;
}

function formatInteger(value: number): string {
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(value);
}

function formatDecimal(value: number, digits: number = 1): string {
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(value);
}

function trimTrace(values: number[]): number[] {
  return values.slice(-TRACE_LIMIT);
}

function measurementCoefficients(seed: number): Int16Array {
  const coeffs = new Int16Array(KYBER_PARAMS.n);
  for (let index = 0; index < coeffs.length; index += 1) {
    const base = ((seed + 1) * 97 + index * 53 + (seed % 5) * 211) % KYBER_PARAMS.q;
    let centered = base - 1664;
    if ((seed + index) % 11 === 0) {
      centered = 1664;
    }
    if ((seed + index) % 19 === 0) {
      centered = -1664;
    }
    coeffs[index] = centered;
  }
  return coeffs;
}

function recordMeasurement(): void {
  const coeffs = measurementCoefficients(state.measurementIndex);
  const vulnerable = polyTomsgVulnerable(coeffs).totalCycles;
  const patched = polyTomsgPatched(coeffs).totalCycles;
  state.measurementIndex += 1;
  state.vulnerableSamples = trimTrace([...state.vulnerableSamples, vulnerable]);
  state.patchedSamples = trimTrace([...state.patchedSamples, patched]);
}

async function runMeasurementBatch(count: number, completionFocusTarget: string): Promise<void> {
  if (state.measuring) {
    return;
  }

  state.measuring = true;
  setStatusMessage(`Running ${count} simulated timing measurement${count === 1 ? '' : 's'}.`);
  render();

  for (let index = 0; index < count; index += 1) {
    recordMeasurement();
    if (index % 20 === 0) {
      render();
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    }
  }

  state.measuring = false;
  setStatusMessage(`Completed ${count} simulated timing measurement${count === 1 ? '' : 's'}.`);
  render(completionFocusTarget);
}

function createPolyline(values: number[], tone: 'danger' | 'safe'): string {
  const label = tone === 'danger' ? 'Vulnerable implementation timing trace' : 'Patched implementation timing trace';

  if (values.length === 0) {
    return `<svg viewBox="0 0 100 40" class="trace-svg" role="img" aria-label="${label}"><line x1="0" y1="20" x2="100" y2="20" class="trace-line trace-line--${tone}" /></svg>`;
  }

  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const range = Math.max(maximum - minimum, 1);
  const points = values
    .map((value, index) => {
      const x = values.length === 1 ? 50 : (index / (values.length - 1)) * 100;
      const y = 36 - ((value - minimum) / range) * 32;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(' ');

  return `<svg viewBox="0 0 100 40" class="trace-svg" role="img" aria-label="${label}"><polyline points="${points}" class="trace-line trace-line--${tone}" /></svg>`;
}

function histogram(values: number[], bins: number): number[] {
  if (values.length === 0) {
    return Array.from({ length: bins }, () => 0);
  }

  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const range = Math.max(maximum - minimum, 1);
  const counts = Array.from({ length: bins }, () => 0);

  for (const value of values) {
    const slot = Math.min(bins - 1, Math.floor(((value - minimum) / range) * bins));
    counts[slot] += 1;
  }

  return counts;
}

function buildSharedScalePolyline(values: number[], minimum: number, range: number): string {
  if (values.length === 0) {
    return '';
  }
  return values
    .map((value, index) => {
      const x = values.length === 1 ? 50 : (index / (values.length - 1)) * 100;
      const y = 36 - ((value - minimum) / range) * 32;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(' ');
}

function renderFlipOverlay(): string {
  const pairs = Math.min(state.vulnerableSamples.length, state.patchedSamples.length);
  const vulnerable = state.vulnerableSamples.slice(0, pairs);
  const patched = state.patchedSamples.slice(0, pairs);
  const ready = pairs >= 6;

  const unionMin = ready ? Math.min(...vulnerable, ...patched) : 0;
  const unionMax = ready ? Math.max(...vulnerable, ...patched) : 1;
  const unionRange = Math.max(unionMax - unionMin, 1);

  const vulnerableMean = ready ? vulnerable.reduce((sum, v) => sum + v, 0) / vulnerable.length : 0;
  const patchedMean = ready ? patched.reduce((sum, v) => sum + v, 0) / patched.length : 0;
  const vulnerableSpread = ready ? Math.max(...vulnerable) - Math.min(...vulnerable) : 0;
  const patchedSpread = ready ? Math.max(...patched) - Math.min(...patched) : 0;
  const spreadCollapse = vulnerableSpread > 0 ? 1 - patchedSpread / vulnerableSpread : 0;
  const meanDelta = Math.max(0, vulnerableMean - patchedMean);

  const vulnerablePoints = buildSharedScalePolyline(vulnerable, unionMin, unionRange);
  const patchedPoints = buildSharedScalePolyline(patched, unionMin, unionRange);

  const stage = `flip-stage--${state.flipMode}`;
  const flipState = state.flipMode === 'before' ? 'vulnerable' : 'patched';

  if (!ready) {
    return `
      <article class="flip-stage flip-stage--idle" aria-label="Flip-to-patched signature interaction">
        <header class="flip-header">
          <span class="flip-eyebrow">Signature moment</span>
          <h3>Flip to patched · same dataset, same axes</h3>
        </header>
        <p class="flip-hint">Run the 100-measurement batch above first, then flip below to see the signal disappear on the same chart.</p>
      </article>`;
  }

  return `
    <article class="flip-stage ${stage}" aria-label="Flip-to-patched signature interaction">
      <header class="flip-header">
        <span class="flip-eyebrow">Signature moment</span>
        <h3>Flip to patched · same dataset, same axes</h3>
        <p class="flip-sub">${pairs} matched decapsulations. Same coefficient vectors. One Y-axis. ${state.flipMode === 'after' ? 'The signal vanished.' : 'Now flip the implementation.'}</p>
      </header>
      <div class="flip-controls" role="group" aria-label="Toggle implementation on overlay">
        <button type="button" class="chip ${state.flipMode === 'before' ? 'is-active' : ''}" data-action="flip-before" aria-pressed="${state.flipMode === 'before'}">Vulnerable path</button>
        <button type="button" class="chip ${state.flipMode === 'after' ? 'is-active' : ''}" data-action="flip-after" aria-pressed="${state.flipMode === 'after'}">Flip to patched</button>
      </div>
      <div class="flip-chart" data-flip="${flipState}">
        <svg viewBox="0 0 100 40" class="flip-svg" role="img" aria-label="Overlay of vulnerable and patched timing on a shared scale">
          <line x1="0" y1="36" x2="100" y2="36" class="flip-axis" />
          <polyline points="${vulnerablePoints}" class="flip-line flip-line--vulnerable" />
          <polyline points="${patchedPoints}" class="flip-line flip-line--patched" />
        </svg>
        <div class="flip-legend" aria-hidden="true">
          <span class="flip-swatch flip-swatch--vulnerable"></span> vulnerable
          <span class="flip-swatch flip-swatch--patched"></span> patched
        </div>
      </div>
      <dl class="flip-readout">
        <div>
          <dt>Vulnerable spread</dt>
          <dd>${formatInteger(vulnerableSpread)} cycles</dd>
        </div>
        <div>
          <dt>Patched spread</dt>
          <dd>${formatInteger(patchedSpread)} cycles</dd>
        </div>
        <div>
          <dt>Spread collapse</dt>
          <dd>${formatDecimal(Math.max(0, spreadCollapse) * 100, 1)}%</dd>
        </div>
        <div>
          <dt>Mean shift</dt>
          <dd>${formatInteger(meanDelta)} cycles</dd>
        </div>
      </dl>
    </article>`;
}

function createHistogram(): string {
  const vulnerable = histogram(state.vulnerableSamples, 10);
  const patched = histogram(state.patchedSamples, 10);
  const peak = Math.max(1, ...vulnerable, ...patched);

  return vulnerable
    .map((value, index) => {
      const patchedValue = patched[index] ?? 0;
      return `
        <div class="hist-bin">
          <span class="hist-bar hist-bar--danger" style="height:${(value / peak) * 100}%"></span>
          <span class="hist-bar hist-bar--safe" style="height:${(patchedValue / peak) * 100}%"></span>
        </div>`;
    })
    .join('');
}

function latestMeasurements(values: number[]): string {
  return values
    .slice(-5)
    .reverse()
    .map((value, index) => `<li>Decapsulation ${index + 1}: <strong>${formatInteger(value)}</strong> cycles</li>`)
    .join('');
}

function elapsedSeconds(): number {
  if (state.attackStartedAt === null) {
    return 0;
  }
  return (performance.now() - state.attackStartedAt) / 1000;
}

function pushLog(kind: LogKind, text: string): void {
  state.attackLog = [
    {
      kind,
      text,
      elapsedSeconds: elapsedSeconds(),
      query: state.attackState.queries,
    },
    ...state.attackLog,
  ].slice(0, ATTACK_LOG_LIMIT);
}

function checkMilestone(): void {
  const total = state.attackSecret.coeffs.length;
  const recovered = state.attackState.currentCoefficient;
  const pct = (recovered / total) * 100;
  for (const threshold of MILESTONE_PCT) {
    if (pct >= threshold && !state.milestonesReached.includes(threshold)) {
      state.milestonesReached = [...state.milestonesReached, threshold];
      const verb = threshold === 100 ? 'recovered' : 'crossed';
      pushLog(
        threshold === 100 ? 'success' : 'milestone',
        `${threshold}% ${verb} — ${recovered}/${total} coefficients`,
      );
    }
  }
}

function resetAttack(mode: AttackMode = state.attackMode): void {
  state.attackMode = mode;
  state.attackRunning = false;
  state.attackStopRequested = false;
  state.attackRunId += 1;
  state.attackState = createAttackState(state.attackSecret);
  state.attackQueryTimes = [];
  state.attackEvents = [];
  state.attackLog = [];
  state.attackStartedAt = null;
  state.attackAnalysis = null;
  state.milestonesReached = [];
  setStatusMessage(`Attack mode set to ${mode === 'vulnerable' ? 'vulnerable implementation' : 'patched implementation'}.`);
}

function pushAttackEvent(coefficient: number, value: number): void {
  const confidence = Math.min(0.98, 0.72 + ((coefficient % 7) * 0.035));
  state.attackEvents = [
    {
      coefficient,
      confidence: Number(confidence.toFixed(2)),
      value,
    },
    ...state.attackEvents,
  ].slice(0, 4);
}

/**
 * Repaint only the dynamic display regions of Exhibit 3 on each animation frame —
 * the milestone strip, recovery grid, meters, trace, correlation box, and log.
 *
 * Deliberately does NOT rebuild the whole page (wasteful) or even the whole
 * exhibit subtree: the control buttons (Stop, speed, mode, export…) keep their
 * DOM nodes, so a mouse click is never dropped by a repaint that lands between
 * pointerdown and pointerup. Their disabled state only changes at run start/end,
 * which the full render() at those boundaries handles.
 */
function paintAttackExhibit(): void {
  const exhibit = document.getElementById('exhibit-3');
  if (!exhibit) {
    render();
    return;
  }

  const milestones = exhibit.querySelector('.milestone-strip');
  if (milestones) {
    milestones.innerHTML = renderMilestoneStripInner();
  }

  // The recovery section holds no controls, so replacing it wholesale is safe.
  const recovery = exhibit.querySelector('.recovery-section');
  if (recovery) {
    recovery.outerHTML = renderRecoveryGrid();
  }

  const meters = exhibit.querySelector('.meter-stack');
  if (meters) {
    meters.innerHTML = renderMeterStackInner();
  }

  const trace = exhibit.querySelector('.attack-trace-host');
  if (trace) {
    trace.innerHTML = renderAttackTraceInner();
  }

  const analysis = exhibit.querySelector('.analysis-box');
  if (analysis) {
    analysis.innerHTML = renderAnalysisBoxInner();
  }

  const log = exhibit.querySelector('.attack-log');
  if (log) {
    log.innerHTML = renderAttackLogInner();
  }

  exhibit.setAttribute('aria-busy', String(state.attackRunning));
}

async function startAttack(): Promise<void> {
  if (state.attackRunning) {
    return;
  }

  resetAttack(state.attackMode);
  state.attackRunning = true;
  state.attackStopRequested = false;
  state.attackStartedAt = performance.now();
  const runId = state.attackRunId;
  pushLog(
    'info',
    `Launching ${state.attackMode} run · ${PLATFORM_LABELS[state.platform]} · budget ${formatInteger(ATTACK_QUERY_BUDGET)} queries`,
  );
  setStatusMessage(`Launching ${state.attackMode === 'vulnerable' ? 'vulnerable' : 'patched'} attack simulation.`);
  render('stop-attack');

  while (
    !state.attackStopRequested &&
    runId === state.attackRunId &&
    state.attackState.currentCoefficient < state.attackSecret.coeffs.length &&
    state.attackState.queries < ATTACK_QUERY_BUDGET
  ) {
    const batchSize = 80 * state.attackSpeed;
    for (let batch = 0; batch < batchSize; batch += 1) {
      if (
        state.attackStopRequested ||
        runId !== state.attackRunId ||
        state.attackState.currentCoefficient >= state.attackSecret.coeffs.length ||
        state.attackState.queries >= ATTACK_QUERY_BUDGET
      ) {
        break;
      }

      const attackedCoefficient = state.attackState.currentCoefficient;
      const result = attackIteration(state.attackState, state.attackMode === 'vulnerable');
      // Hold the analysis that last DECIDED a coefficient. Once a recovery has
      // happened, later mid-coefficient iterations are refilling a bucket that
      // was just cleared, and their `distinguishable = false` says nothing about
      // the signal — only that the samples have not been re-gathered yet.
      // Painting those would label a confidence of 0.999 "Noise floor only".
      // Before the first recovery there is nothing better, so track live.
      if (result.bitsRecoveredThisRound > 0 || state.attackState.currentCoefficient === 0) {
        state.attackAnalysis = result.analysis;
      }
      state.attackQueryTimes = trimTrace([...state.attackQueryTimes, result.queryTime]);

      if (result.bitsRecoveredThisRound > 0) {
        pushAttackEvent(attackedCoefficient, state.attackSecret.coeffs[attackedCoefficient]);
        pushLog(
          'recovery',
          `coeff ${attackedCoefficient} → ${state.attackSecret.coeffs[attackedCoefficient] >= 0 ? '+' : ''}${state.attackSecret.coeffs[attackedCoefficient]}`,
        );
        checkMilestone();
      }
    }

    paintAttackExhibit();
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }

  state.attackRunning = false;
  if (state.attackMode === 'vulnerable') {
    if (state.attackState.currentCoefficient === state.attackSecret.coeffs.length) {
      pushLog('success', `Run complete · ${state.attackState.queries} queries used · key fully recovered`);
    } else if (state.attackStopRequested) {
      pushLog('warning', `Run halted at ${state.attackState.currentCoefficient}/${state.attackSecret.coeffs.length}`);
    } else {
      pushLog(
        'warning',
        `Query budget exhausted at ${state.attackState.currentCoefficient}/${state.attackSecret.coeffs.length}`,
      );
    }
  } else {
    pushLog('info', 'Patched run finished — no statistical signal above noise floor');
  }
  setStatusMessage(
    state.attackMode === 'vulnerable'
      ? `Attack run complete. Recovered ${state.attackState.recoveredBits} of ${state.attackState.totalBits} bits.`
      : `Patched attack run complete. Recovered ${state.attackState.recoveredBits} bits.`,
  );
  render('launch-attack');
}

function prefersReducedMotion(): boolean {
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

function scrollToExhibit(id: string): void {
  const target = document.getElementById(id);
  if (target instanceof HTMLElement) {
    target.scrollIntoView({
      behavior: prefersReducedMotion() ? 'auto' : 'smooth',
      block: 'start',
    });
  }
}

function tourDelay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function runTour(): Promise<void> {
  if (state.tourRunning) {
    return;
  }
  state.tourRunning = true;
  state.tourStopRequested = false;
  state.attackSpeed = 16;
  setStatusMessage('Auto-tour starting · 30 second walkthrough of all five exhibits.');
  render();

  const guard = (): boolean => !state.tourStopRequested;

  scrollToExhibit('exhibit-1');
  await tourDelay(3500);
  if (!guard()) return endTour('Tour stopped.');

  scrollToExhibit('exhibit-2');
  await tourDelay(800);
  if (!guard()) return endTour('Tour stopped.');
  await runMeasurementBatch(60, 'run-hundred');
  if (!guard()) return endTour('Tour stopped.');
  await tourDelay(600);

  state.flipMode = 'before';
  setStatusMessage('Tour · showing the vulnerable signal on the shared scale.');
  render();
  await tourDelay(2200);
  if (!guard()) return endTour('Tour stopped.');

  state.flipMode = 'after';
  setStatusMessage('Tour · flipping to patched — same dataset, signal vanishes.');
  render();
  await tourDelay(2800);
  if (!guard()) return endTour('Tour stopped.');

  scrollToExhibit('exhibit-3');
  await tourDelay(700);
  if (!guard()) return endTour('Tour stopped.');
  state.attackMode = 'vulnerable';
  resetAttack('vulnerable');
  render();
  await startAttack();
  if (!guard()) return endTour('Tour stopped.');
  await tourDelay(900);

  scrollToExhibit('exhibit-4');
  await tourDelay(3200);
  if (!guard()) return endTour('Tour stopped.');

  scrollToExhibit('exhibit-5');
  await tourDelay(3000);

  endTour('Tour complete · scroll up to revisit any exhibit.');
}

function endTour(message: string): void {
  state.tourRunning = false;
  state.tourStopRequested = false;
  setStatusMessage(message);
  render();
}

function stopTour(): void {
  if (!state.tourRunning) {
    return;
  }
  state.tourStopRequested = true;
  state.attackStopRequested = true;
  setStatusMessage('Stopping auto-tour.');
  render();
}

function exportSamples(): void {
  const analysis = statisticalAnalysis(state.attackState.timingProfile);
  const payload = {
    mode: state.attackMode,
    queries: state.attackState.queries,
    recoveredBits: state.attackState.recoveredBits,
    totalBits: state.attackState.totalBits,
    timingProfile: Object.fromEntries(state.attackState.timingProfile.entries()),
    queryTrace: state.attackQueryTimes,
    analysis,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `kyberslash-${state.attackMode}-samples.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  setStatusMessage(`Exported ${state.attackMode} timing samples.`);
}

function measurementSummary(values: number[]): { value: number; stddev: number } {
  return aggregateTimings(values, 'mean');
}

function renderProgressRail(): string {
  return `
    <nav class="exhibit-rail" aria-label="Lab exhibits" id="exhibit-rail">
      ${EXHIBITS.map(
        (exhibit) => `
        <a class="rail-link" href="#${exhibit.id}" data-exhibit="${exhibit.number}">
          <span class="rail-number">${String(exhibit.number).padStart(2, '0')}</span>
          <span class="rail-title">${exhibit.shortTitle}</span>
        </a>`,
      ).join('')}
    </nav>`;
}

function renderBridge(index: number): string {
  const bridge = BRIDGES[index];
  if (!bridge) {
    return '';
  }
  return `
    <aside class="bridge" role="note" aria-label="Bridge between exhibits">
      <div class="bridge-row">
        <span class="bridge-label">Just proved</span>
        <p>${bridge.proved}</p>
      </div>
      <div class="bridge-row">
        <span class="bridge-label">Up next</span>
        <p>${bridge.next}</p>
      </div>
    </aside>`;
}

function renderHero(): string {
  const platformLabel = PLATFORM_LABELS[state.platform];
  const altPlatform: Platform = state.platform === 'cortex-a7' ? 'cortex-m4' : 'cortex-a7';
  const altLabel = PLATFORM_LABELS[altPlatform];
  // Names the leak's size on the active target, so the toggle is a comparison
  // rather than a decoration: +20 cycles at coefficient 833 on Cortex-A7 (the
  // __divsi3 jump), +2 at coefficient 192 on Cortex-M4 (the udiv crossover).
  const primaryStep = primaryCoefficientStep(state.platform);
  return `
    <section class="hero-shell">
      <div class="hero-copy">
        <header class="cl-hero">
          <div class="cl-hero-main">
            <h1 class="cl-hero-title">KyberSlash</h1>
            <p class="cl-hero-sub">ML-KEM (Kyber) · timing side-channel · FIPS 203</p>
            <p class="cl-hero-desc">Watch a secret-dependent division by q=3329 in Kyber's reference C leak its timing, then flip to the Barrett-reduction fix and run a live in-browser attack that recovers all 768 coefficients of an ML-KEM-768 secret key.</p>
          </div>
          <aside class="cl-hero-why" aria-label="Why it matters">
            <span class="cl-hero-why-label">WHY IT MATTERS</span>
            <p class="cl-hero-why-text">ML-KEM is the post-quantum KEM replacing RSA in TLS. Its reference code passed years of review, yet one variable-latency division on a $35 Raspberry Pi leaked the whole key — proof that standardization is not constant-time safety.</p>
          </aside>
        </header>
        <div class="hero-cta" role="group" aria-label="Auto-tour controls">
          ${
            state.tourRunning
              ? `<button type="button" class="control control--primary" data-action="stop-tour">Stop tour</button>
                 <span class="hero-cta-hint">Auto-tour running — sit back, it scrolls and runs everything.</span>`
              : `<button type="button" class="control control--primary" data-action="start-tour">▶ Take the 30-second tour</button>
                 <span class="hero-cta-hint">Auto-scrolls the five exhibits, runs the measurements, flips to patched, and recovers the key at 16×.</span>`
          }
        </div>
        <div class="platform-toggle" role="group" aria-label="Simulated target platform">
          <span class="platform-label">Target platform</span>
          <button type="button" class="chip ${state.platform === 'cortex-a7' ? 'is-active' : ''}" data-action="set-platform-a7" aria-pressed="${state.platform === 'cortex-a7'}" ${state.attackRunning || state.measuring ? 'disabled' : ''}>Cortex-A7</button>
          <button type="button" class="chip ${state.platform === 'cortex-m4' ? 'is-active' : ''}" data-action="set-platform-m4" aria-pressed="${state.platform === 'cortex-m4'}" ${state.attackRunning || state.measuring ? 'disabled' : ''}>Cortex-M4</button>
          <span class="platform-current">${state.attackRunning || state.measuring ? 'platform locked while a run is in progress' : `simulating ${escapeHtml(platformLabel)} — biggest exploitable division step here is <strong>+${primaryStep.jump} cycle${primaryStep.jump === 1 ? '' : 's'}</strong> at coefficient <strong>${formatInteger(primaryStep.coefficient)}</strong> · click to switch to ${escapeHtml(altLabel)}`}</span>
        </div>
        <div class="hero-notes">
          <span class="pill pill--danger">KyberSlash1: PKE decryption / poly_tomsg</span>
          <span class="pill pill--danger">KyberSlash2: PKE encryption / poly_compress &mdash; exploited via re-encryption inside decapsulation</span>
          <span class="pill pill--safe">Reference code patched 1 Dec 2023 &middot; public 15 Dec 2023</span>
        </div>
      </div>
    </section>`;
}

function renderCodeLines(lines: readonly CodeLine[]): string {
  return lines
    .map((line) => {
      const text = line.text.length === 0 ? ' ' : escapeHtml(line.text);
      const cls = line.hl ? ` code-line--hl-${line.hl}` : '';
      return `<span class="code-line${cls}">${text}</span>`;
    })
    .join('\n');
}

/**
 * 30-second Barrett-reduction intuition: floor(x/q) computed as
 * (x * (floor(2^32/q) + 1)) >> 32 swaps the one data-dependent operation (the
 * division — a hardware `udiv` on Cortex-M4, a call to the `__divsi3` software
 * routine on the paper's Cortex-A7 build) for two fixed-latency instructions
 * (mul, shift). Shows a side-by-side instruction contrast and the same
 * latency-band graphic going flat, so "constant-time" stops being a slogan.
 */
function renderBarrettIntuition(): string {
  const profile = getPlatformProfile(state.platform);
  const [, highProbe] = activeProbes();
  const dividend = kyberSlash1Dividend(highProbe);
  return `
    <section class="barrett" aria-label="Why the Barrett-reduction fix is constant-time">
      <header class="barrett-head">
        <span class="barrett-eyebrow">The fix, in 30 seconds</span>
        <h3>Why multiply-then-shift can&rsquo;t leak</h3>
        <p class="barrett-lead">${glossTerm('Barrett reduction', 'replacing a divide-by-constant with a precomputed multiply and a bit shift')} computes the exact same result as <code>floor(x / 3329)</code> — but by <em>multiplying</em> by the precomputed constant <code>floor(2<sup>32</sup>/3329) + 1 = ${formatInteger(BARRETT_INV_Q)}</code> and shifting right by 32. On a CPU, <code>mul</code> and <code>shift</code> take the <strong>same number of cycles no matter what the data is</strong>; only the division varies with the operand — and on this target that division is <code>${escapeHtml(profile.divisionOp)}</code>. Remove the division and you remove the leak.</p>
      </header>
      <div class="barrett-compare">
        <article class="barrett-col barrett-col--danger">
          <h4>Vulnerable · one division</h4>
          <code class="barrett-instr">t = (2&middot;w + 1664) <span class="hot">/ q</span></code>
          <p class="barrett-note"><span class="barrett-tag barrett-tag--danger">data-dependent</span> <code>${escapeHtml(profile.divisionOp)}</code> cost tracks the numerator — the step function you just saw.</p>
        </article>
        <article class="barrett-col barrett-col--safe">
          <h4>Patched · multiply + shift</h4>
          <code class="barrett-instr">t = ((2&middot;w + 1664) <span class="cool">&times; ${formatInteger(BARRETT_INV_Q)}) &gt;&gt; 32</span></code>
          <p class="barrett-note"><span class="barrett-tag barrett-tag--safe">fixed-latency</span> mul and shift ignore the numerator&rsquo;s magnitude — same cycles every time.</p>
        </article>
      </div>
      ${renderFlatCostBands(dividend)}
      <p class="barrett-flatline">Same numerator, same number line — but now every band collapses to one fixed cost. Where the numerator lands no longer changes the clock. That is what &ldquo;constant-time&rdquo; means, made mechanical.</p>
      <p class="barrett-flatline">What pq-crystals actually shipped is this shape with a smaller constant: <code>t &lt;&lt;= 1; t += 1665; t *= 80635; t &gt;&gt;= 28;</code> where <code>80635 = floor(2<sup>28</sup>/3329)</code>. The 32-bit constant above is the variant this lab computes with. Both agree with <code>floor(x / 3329)</code> on every numerator <code>poly_tomsg</code> can produce — checked exhaustively over all 3,329 coefficient values.</p>
    </section>`;
}

function renderSmokingGun(): string {
  const lines = state.codeMode === 'vulnerable' ? VULNERABLE_LINES : PATCHED_LINES;
  const annotations =
    state.codeMode === 'vulnerable'
      ? [
          'The vulnerable line divides a secret-dependent numerator 2·w + 1664 by q = 3329.',
          'What performs that division is target-specific. On the paper’s Raspberry Pi 2 (Cortex-A7, gcc 8.3.0 -Os) no divide instruction runs at all: the compiler emits a call to the __divsi3 software routine, whose cost jumps by 20 cycles once the numerator reaches 3,329 — i.e. once the decrypted coefficient reaches 833 (paper §5.1.1–5.1.2).',
          'On the Cortex-M4 (STM32F407VG) a hardware udiv does run, and the only crossover inside this line’s numerator range is 2^11 = 2,048, worth 2 cycles (paper Table 4). Smaller signal, same bug.',
          'Modern x86_64 often avoids the bug only because the compiler rewrites division into multiplication, but -Os can put division back.',
        ]
      : [
          'This is the upstream fix verbatim (pq-crystals/kyber commit dda29cc, 1 December 2023): the divide is replaced by a multiply by 80635 = floor(2^28/3329) and a 28-bit shift.',
          'Multiplication plus shift removes the variable-latency division instruction from the secret path — mul and shift cost the same on every operand.',
          `The lab's own JavaScript model uses the equivalent 32-bit constant floor(2^32/3329) + 1 = ${BARRETT_INV_Q}, explained below; both return exactly floor(x / 3329) over the range this line produces.`,
          'Rollout was not instant: the reference code was fixed two weeks before public disclosure, but most downstream libraries were patched in the weeks and months after it (see Exhibit 4).',
        ];

  return `
    <section class="panel exhibit" id="exhibit-1" data-exhibit="1">
      <div class="section-heading">
        <p class="kicker">Exhibit 1 of 5</p>
        <h2>The vulnerable line of code</h2>
      </div>
      ${renderTryThis(0)}
      <div class="toggle-row">
        <button type="button" class="chip ${state.codeMode === 'vulnerable' ? 'is-active' : ''}" data-action="code-vulnerable" aria-pressed="${state.codeMode === 'vulnerable'}">Vulnerable reference C</button>
        <button type="button" class="chip ${state.codeMode === 'patched' ? 'is-active' : ''}" data-action="code-patched" aria-pressed="${state.codeMode === 'patched'}">Patched Barrett reduction</button>
      </div>
      <div class="code-card ${state.codeMode === 'vulnerable' ? 'is-danger' : 'is-safe'}">
        <pre><code>${renderCodeLines(lines)}</code></pre>
      </div>
      <ul class="evidence-list">${annotations.map((item) => `<li>${item}</li>`).join('')}</ul>
      ${renderBarrettIntuition()}
      <footer class="code-citations" aria-label="Where this code lives upstream">
        <span class="citations-label">Upstream</span>
        <a class="citation-chip" href="https://github.com/pq-crystals/kyber/blob/main/ref/poly.c" target="_blank" rel="noopener">pq-crystals/kyber · ref/poly.c</a>
        <a class="citation-chip" href="https://eprint.iacr.org/2024/1049" target="_blank" rel="noopener">KyberSlash paper · eprint 2024/1049</a>
        <a class="citation-chip" href="https://csrc.nist.gov/pubs/fips/203/final" target="_blank" rel="noopener">FIPS 203 · ML-KEM standard</a>
      </footer>
    </section>`;
}

// Colors for the latency bands, cheapest -> costliest. Kept as CSS classes so
// both light and dark themes can set AA-contrast fills/text. The number of
// bands is platform-dependent (four on Cortex-A7, two on Cortex-M4), so the
// ramp is sampled rather than indexed directly.
const BAND_TONES = ['band--fast', 'band--mid', 'band--slow', 'band--slowest'] as const;

function bandTone(index: number, count: number): string {
  if (count <= 1) {
    return BAND_TONES[0];
  }
  const position = Math.round((index / (count - 1)) * (BAND_TONES.length - 1));
  return BAND_TONES[position] ?? BAND_TONES[BAND_TONES.length - 1];
}

/** Log-scaled x position within the active platform's display window. */
function bandScaler(): (magnitude: number) => number {
  const { min, max } = getPlatformProfile(state.platform).display;
  const logMin = Math.log2(min);
  const logMax = Math.log2(max);
  return (magnitude: number): number => {
    const clamped = Math.max(min, Math.min(max, Math.abs(magnitude) || min));
    return ((Math.log2(clamped) - logMin) / (logMax - logMin)) * 100;
  };
}

/** Where the active platform's numbers come from, spelled out under the figure. */
function renderModelProvenance(): string {
  const profile = getPlatformProfile(state.platform);
  return `<p class="bands-source"><span class="bands-source-label">Source</span> ${escapeHtml(profile.source)}. <span class="bands-source-label">Illustrative</span> ${escapeHtml(profile.illustrative)}.</p>`;
}

/**
 * The "why division leaks" number line: draws the active target's real cost
 * bands as colored segments with their cycle cost, and drops a marker for a
 * chosen numerator so a learner SEES the numerator's magnitude pick a cost.
 *
 * The bands are the ones that actually fall inside the numerator range this
 * line can produce (1,664–8,320), read straight off the platform profile — so
 * on Cortex-A7 you get the paper's __divsi3 steps at 3,329 / 4,096 / 8,192, and
 * on Cortex-M4 you get Table 4's single udiv crossover at 2,048. Bands are laid
 * out on a log scale so the narrow ones stay legible.
 *
 * `markerDividend` is the numerator handed to the divider; `caption` names it.
 */
function renderLatencyBands(markerDividend: number, caption: string): string {
  const bands = getDisplayBands(state.platform);
  const profile = getPlatformProfile(state.platform);
  const toX = bandScaler();
  const activeBand = displayBandIndex(markerDividend, state.platform);
  // On Cortex-M4 the profile carries Table 4's absolute measured cycle counts,
  // so the absolute number is the honest headline and stands alone. On
  // Cortex-A7 only the +20/+2/+1 steps are measured and they sit on an invented
  // base, so there the DELTA leads and the absolute figure is explicitly marked
  // as modelled. Same graphic, honest emphasis either way.
  const measuredAbsolute = profile.cycleBasis === 'absolute';
  const deltaLabel = (band: LatencyBand): string =>
    band.delta === 0 ? 'base' : `base +${band.delta}`;
  const bandFigures = (band: LatencyBand): string =>
    measuredAbsolute
      ? `${band.cycles} cyc`
      : `${deltaLabel(band)} <em>${band.cycles} cyc modelled</em>`;
  const markerFigure = (band: LatencyBand | undefined): string => {
    if (!band) {
      return '';
    }
    return measuredAbsolute ? `${band.cycles} cyc` : `${deltaLabel(band)} cyc`;
  };

  const segments = bands
    .map((band: LatencyBand, index: number) => {
      const start = toX(band.floor);
      const end = Number.isFinite(band.ceiling) ? toX(band.ceiling) : 100;
      const width = Math.max(0, end - start);
      const isActive = index === activeBand;
      return `<div class="band-seg ${bandTone(index, bands.length)}${isActive ? ' is-active' : ''}" style="left:${start.toFixed(2)}%;width:${width.toFixed(2)}%">
          <span class="band-cycles">${bandFigures(band)}</span>
          <span class="band-range">${escapeHtml(band.label)}</span>
        </div>`;
    })
    .join('');

  const markerX = toX(markerDividend);
  const active = bands[activeBand];
  const activeDescription = measuredAbsolute
    ? `costing ${active?.cycles ?? 0} cycles`
    : `costing ${active?.delta ?? 0} cycles more than the cheapest band`;

  return `
    <figure class="bands-figure">
      <figcaption class="bands-caption">${caption}</figcaption>
      <div class="bands-track" role="img" aria-label="Number line of the division numerator split into ${escapeHtml(profile.divisionOp)} cost bands on ${escapeHtml(profile.label)}; the current numerator ${formatInteger(markerDividend)} lands in the ${active?.label ?? ''} band, ${activeDescription}">
        ${segments}
        ${renderUnreachableScrims()}
        <div class="band-marker" style="left:${markerX.toFixed(2)}%">
          <span class="band-marker-dot"></span>
          <span class="band-marker-tag">numerator ${formatInteger(markerDividend)} → ${markerFigure(active)}</span>
        </div>
      </div>
      <p class="bands-reach-note">${reachNote()}</p>
      ${renderModelProvenance()}
    </figure>`;
}

/**
 * Scrims over the parts of the number line this line of code can never reach.
 * The numerator is `2t + 1664` for a coefficient `t` in 0…3328, so it is always
 * an even number in 1,664…8,320 — everything outside that is unreachable, and
 * a cost step out there is not exploitable no matter how large it is. Drawn as
 * shading rather than a bracket so it costs no vertical space in the track.
 */
function renderUnreachableScrims(): string {
  const toX = bandScaler();
  const start = toX(KYBERSLASH1_NUMERATOR_MIN);
  const end = toX(KYBERSLASH1_NUMERATOR_MAX);
  const left =
    start > 0.5
      ? `<div class="bands-scrim" style="left:0;width:${start.toFixed(2)}%" aria-hidden="true"></div>`
      : '';
  const right =
    end < 99.5
      ? `<div class="bands-scrim" style="left:${end.toFixed(2)}%;width:${(100 - end).toFixed(2)}%" aria-hidden="true"></div>`
      : '';
  return `${left}${right}`;
}

/** Caption suffix naming the reachable numerator window the scrims mark out. */
function reachNote(): string {
  return `Shaded ends are numerators <code>2&middot;w + 1664</code> can never produce — only ${formatInteger(KYBERSLASH1_NUMERATOR_MIN)}&ndash;${formatInteger(KYBERSLASH1_NUMERATOR_MAX)} is reachable, so only steps inside it are exploitable.`;
}

/**
 * The patched counterpart to {@link renderLatencyBands}: the same log-scaled
 * number line, but every band is greyed to one flat cost. The marker still sits
 * at the numerator's magnitude to prove the point — its position no longer
 * changes the cost, because there is only one cost.
 */
function renderFlatCostBands(markerDividend: number): string {
  const bands = getDisplayBands(state.platform);
  const toX = bandScaler();
  const flat = patchedDivCycles(state.platform);

  const segments = bands
    .map((band: LatencyBand) => {
      const start = toX(band.floor);
      const end = Number.isFinite(band.ceiling) ? toX(band.ceiling) : 100;
      const width = Math.max(0, end - start);
      return `<div class="band-seg band--flat" style="left:${start.toFixed(2)}%;width:${width.toFixed(2)}%">
          <span class="band-cycles">${flat} cyc</span>
          <span class="band-range">${escapeHtml(band.label)}</span>
        </div>`;
    })
    .join('');

  const markerX = toX(markerDividend);
  return `
    <figure class="bands-figure">
      <figcaption class="bands-caption">Patched path · one fixed cost across every numerator (${escapeHtml(PLATFORM_LABELS[state.platform])})</figcaption>
      <div class="bands-track bands-track--flat" role="img" aria-label="The same numerator number line under Barrett reduction: every band costs the same fixed number of cycles, so the numerator ${formatInteger(markerDividend)} no longer changes the timing">
        ${segments}
        ${renderUnreachableScrims()}
        <div class="band-marker band-marker--flat" style="left:${markerX.toFixed(2)}%">
          <span class="band-marker-dot"></span>
          <span class="band-marker-tag">numerator ${formatInteger(markerDividend)} → ${flat} cyc (fixed)</span>
        </div>
      </div>
      <p class="bands-source"><span class="bands-source-label">Illustrative</span> the paper does not benchmark the patched routine, so the exact constant here is invented. What is <em>not</em> invented is that it is a single number the operand cannot move — multiply and shift are fixed-latency instructions on both targets.</p>
    </figure>`;
}

/**
 * The mechanism panel. What actually performs the division is target-specific,
 * and the whole point of KyberSlash is that you cannot reason about it without
 * naming the target:
 *
 *   Raspberry Pi 2 / Cortex-A7 — gcc -Os builds for an ABI that does not
 *     guarantee a divide instruction, so no `udiv` executes; the division is a
 *     call to the `__divsi3` SOFTWARE routine, whose cost steps up at
 *     numerators 3,329 / 4,096 / 8,192 (paper §5.1.1).
 *   STM32F407VG / Cortex-M4 — a hardware `udiv` does execute, and its own
 *     latency is a step function of the numerator (paper Table 4).
 *
 * So this panel reads the mechanism off the active platform profile rather than
 * asserting one of them universally.
 */
function renderWhyDivisionLeaks(): string {
  const profile = getPlatformProfile(state.platform);
  const isSoftwareDivision = profile.divisionOp === '__divsi3';
  // Put the marker where the attack actually probes: the dividend of the high
  // probe, i.e. the first coefficient that lands on the target's biggest step.
  const [, highProbe] = activeProbes();
  const vulnerableDividend = kyberSlash1Dividend(highProbe);

  const lead = isSoftwareDivision
    ? `No divide instruction runs here at all. On the paper&rsquo;s Raspberry Pi 2 the reference C is built with <code>gcc -Os</code> for an ABI that does not guarantee a hardware divide, so <code>(2&middot;w + 1664) / 3329</code> becomes a call to ${glossTerm('__divsi3', 'the compiler\u2019s software integer-division routine, linked in when the target ABI does not guarantee a divide instruction')} — a software division routine. Its cost climbs in <strong>discrete jumps as the numerator grows</strong>. Because <code>w</code> is the decrypted coefficient, and the decrypted coefficient carries the secret, the clock moves with the secret.`
    : `The Cortex-M4 does have a hardware divide instruction (${glossTerm('udiv', 'the CPU\u2019s hardware integer-divide instruction, whose latency depends on the numerator')}) — and it does not take a fixed number of cycles. The paper reverse-engineers its latency as a <strong>step function of the numerator</strong>, 2 to 12 cycles. Because the numerator <code>2&middot;w + 1664</code> carries the secret-derived coefficient <code>w</code>, the clock moves with the secret.`;

  const steps = coefficientSteps(state.platform);
  const stepList = steps
    .map(
      (step) =>
        `<li><code>numerator &ge; ${formatInteger(step.numerator)}</code> <span class="why-leak-step-arrow">&rarr;</span> <strong>+${step.jump} cycle${step.jump === 1 ? '' : 's'}</strong> <span class="why-leak-step-coeff">(coefficient <code>t &ge; ${formatInteger(step.coefficient)}</code>)</span></li>`,
    )
    .join('');

  return `
    <section class="why-leak" aria-label="Why division time leaks the secret">
      <header class="why-leak-head">
        <span class="why-leak-eyebrow">Mechanism · ${escapeHtml(profile.device)}</span>
        <h3>Why the division time leaks</h3>
        <p class="why-leak-lead">${lead}</p>
      </header>
      <div class="why-leak-steps">
        <p class="why-leak-steps-label">Measured cost steps reachable from this line (${escapeHtml(profile.divisionOp)} on ${escapeHtml(profile.device)})</p>
        <ul>${stepList}</ul>
        <p class="why-leak-steps-note">Switch target and those steps move: they are a property of the compiler output and the CPU, not of Kyber. That is exactly why side-channel safety has to be audited per platform, not per algorithm.</p>
      </div>
      ${renderLatencyBands(vulnerableDividend, `Vulnerable path · the numerator&rsquo;s magnitude picks the cost (${escapeHtml(PLATFORM_LABELS[state.platform])})`)}
      <p class="why-leak-flat-note">${glossTerm('Barrett reduction', 'computing floor(x/q) with a fixed-cost multiply and shift instead of a data-dependent divide')} (the patch) replaces that division with a multiply and a shift — instructions whose latency does <em>not</em> depend on the data — so every coefficient costs the same fixed amount and the marker never moves. That flat line is what the fix in Exhibit&nbsp;1 buys you.</p>
    </section>`;
}

function renderOscilloscope(): string {
  const vulnerableStats = measurementSummary(state.vulnerableSamples);
  const patchedStats = measurementSummary(state.patchedSamples);
  const vulnerableVariance =
    state.vulnerableSamples.length > 1
      ? Math.max(...state.vulnerableSamples) - Math.min(...state.vulnerableSamples)
      : 0;
  const patchedVariance =
    state.patchedSamples.length > 1 ? Math.max(...state.patchedSamples) - Math.min(...state.patchedSamples) : 0;

  const vulnerableMean = vulnerableStats.value;
  const patchedMean = patchedStats.value;
  const deltaCycles = Math.max(0, vulnerableMean - patchedMean);
  const ratio = patchedMean > 0 ? vulnerableMean / patchedMean : 0;
  // The patched path is constant-time, so its spread collapses to exactly zero.
  // A swinging vulnerable path against a zero-variance patched path is the
  // strongest possible signal (an infinite ratio) — not an "edge case". Guard
  // the divide-by-zero so the verdict fires "leak" instead of reading 0×.
  const spreadRatio =
    patchedVariance > 0
      ? vulnerableVariance / patchedVariance
      : vulnerableVariance > 0
        ? Number.POSITIVE_INFINITY
        : 0;
  const spreadRatioLabel = Number.isFinite(spreadRatio)
    ? `${formatDecimal(spreadRatio, 1)}× wider`
    : '∞× wider';
  const samplesReady = state.vulnerableSamples.length >= 6 && state.patchedSamples.length >= 6;
  const verdictTone = !samplesReady ? 'pending' : spreadRatio >= 4 ? 'leak' : 'edge';
  const verdictHeadline =
    !samplesReady
      ? 'Collect a few measurements to see the contrast.'
      : verdictTone === 'leak'
        ? 'Leak detected — vulnerable path swings, patched path is flat.'
        : 'Edge case — collect more samples to widen the gap.';

  return `
    <section class="panel exhibit" id="exhibit-2" data-exhibit="2" aria-busy="${state.measuring}">
      <div class="section-heading">
        <p class="kicker">Exhibit 2 of 5</p>
        <h2>The oscilloscope</h2>
      </div>
      ${renderTryThis(1)}
      ${renderWhyDivisionLeaks()}
      <div class="verdict verdict--${verdictTone}" role="status">
        <div class="verdict-row">
          <span class="verdict-pill" tabindex="0" title="How much wider the vulnerable timing spread is than the patched one. A wide spread means the secret is moving the clock." aria-label="Variance ratio: how much wider the vulnerable timing spread is than the patched one. A wide spread means the secret is moving the clock.">Variance ratio</span>
          <strong>${samplesReady ? spreadRatioLabel : '—'}</strong>
        </div>
        <div class="verdict-row">
          <span class="verdict-pill" tabindex="0" title="How many more CPU cycles the vulnerable path averages than the patched path. This gap is the leak, in cycles." aria-label="Mean delta: how many more CPU cycles the vulnerable path averages than the patched path. This gap is the leak, in cycles.">Mean delta</span>
          <strong>${formatInteger(deltaCycles)} cycles</strong>
        </div>
        <div class="verdict-row">
          <span class="verdict-pill" tabindex="0" title="The vulnerable mean divided by the patched mean. Above 1.0 means the vulnerable path is consistently slower." aria-label="Mean ratio: the vulnerable mean divided by the patched mean. Above 1.0 means the vulnerable path is consistently slower.">Mean ratio</span>
          <strong>${samplesReady ? `${formatDecimal(ratio, 2)}×` : '—'}</strong>
        </div>
        <p class="verdict-headline">${verdictHeadline}</p>
      </div>
      <div class="controls-row">
        <button type="button" class="control" data-action="next-measurement" ${state.measuring ? 'disabled' : ''}>Next measurement</button>
        <button type="button" class="control" data-action="run-hundred" ${state.measuring ? 'disabled' : ''}>Run 100 measurements</button>
        <button type="button" class="control ghost" data-action="toggle-distribution" aria-pressed="${state.showDistribution}">${state.showDistribution ? 'Hide' : 'Show'} statistical distribution</button>
      </div>
      <div class="trace-grid">
        <article class="trace-card trace-card--danger">
          <header>
            <p>VULNERABLE IMPLEMENTATION</p>
            <strong>${escapeHtml(PLATFORM_LABELS[state.platform])} simulated leakage</strong>
          </header>
          ${createPolyline(state.vulnerableSamples, 'danger')}
          <ul class="trace-list">${latestMeasurements(state.vulnerableSamples)}</ul>
          <footer>
            <span>Mean: ${formatInteger(vulnerableStats.value)} cycles</span>
            <span>Variance span: ${formatInteger(vulnerableVariance)} cycles</span>
          </footer>
        </article>
        <article class="trace-card trace-card--safe">
          <header>
            <p>PATCHED IMPLEMENTATION</p>
            <strong>Barrett reduction, fixed cost</strong>
          </header>
          ${createPolyline(state.patchedSamples, 'safe')}
          <ul class="trace-list">${latestMeasurements(state.patchedSamples)}</ul>
          <footer>
            <span>Mean: ${formatInteger(patchedStats.value)} cycles</span>
            <span>Variance span: ${formatInteger(patchedVariance)} cycles</span>
          </footer>
        </article>
      </div>
      ${renderFlipOverlay()}
      ${
        state.showDistribution
          ? `<div class="distribution-card"><div class="histogram">${createHistogram()}</div><p class="distribution-caption">Red bars stay wide because secret-dependent division timing moves with the operand. Green bars collapse into a flat cluster because Barrett reduction keeps the path constant-time.</p></div>`
          : ''
      }
    </section>`;
}

/**
 * Slow-motion walkthrough of the two-probe attack for ONE coefficient. The two
 * probes straddle whatever cost step the ACTIVE target actually has — coefficient
 * 833 on the paper's Cortex-A7 (numerator 3,329, the +20-cycle `__divsi3` jump,
 * §5.1.1-§5.1.2), coefficient 192 on Cortex-M4 (numerator 2,048 = 2^11, the
 * +2-cycle `udiv` crossover, Table 4). The device adds the hidden secret, each
 * numerator lands below or above the step, and the fast/slow truth table reveals
 * the coefficient. All numbers come from walkthroughCoefficient() — the same
 * model the live attack uses.
 */
function renderProbeWalkthrough(): string {
  const secret = state.walkthroughSecret;
  const w = walkthroughCoefficient(secret);
  const signLabel = (s: number): string => (s > 0 ? '+1' : s < 0 ? '−1' : '0');
  const boundary = w.boundaryNumerator;
  const divisionOp = escapeHtml(w.divisionOp);
  // Only Cortex-M4 has absolute measured cycle counts (Table 4). On Cortex-A7
  // the paper gives the +20-cycle jump but not divsi3's base cost, so a probe
  // card there reports which side of the step it landed on rather than
  // parading a cycle count the paper never published.
  const measuredAbsolute = getPlatformProfile(state.platform).cycleBasis === 'absolute';
  const costPhrase = (step: { cycles: number; slow: boolean }): string =>
    measuredAbsolute
      ? `<strong>${formatDecimal(step.cycles, 0)} cycles</strong>`
      : `<strong>${step.slow ? `+${w.jumpCycles} cycles` : 'baseline'}</strong>`;

  const probeCard = (
    step: { probe: number; w: number; dividend: number; cycles: number; slow: boolean },
    note: string,
  ): string => `
    <article class="probe-card ${step.slow ? 'is-slow' : 'is-fast'}">
      <header class="probe-card-head">
        <span class="probe-chip">probe t=${formatInteger(step.probe)}</span>
        <span class="probe-verdict ${step.slow ? 'is-slow' : 'is-fast'}">${step.slow ? 'SLOW' : 'FAST'}</span>
      </header>
      <p class="probe-math">device adds secret: <code>w = ${signLabel(secret)} + ${formatInteger(step.probe)} = ${formatInteger(step.w)}</code></p>
      <p class="probe-math">numerator handed to <code>${divisionOp}</code>: <code>2&middot;${formatInteger(step.w)} + 1664 = ${formatInteger(step.dividend)}</code></p>
      ${renderBoundaryLine(step.dividend, step.slow, boundary)}
      <p class="probe-readout"><code>${divisionOp}</code> cost ${costPhrase(step)} — ${note}</p>
    </article>`;

  const rows = ([-1, 0, 1] as const)
    .map((s) => {
      const row = walkthroughCoefficient(s);
      const active = s === secret;
      return `<tr class="${active ? 'is-active' : ''}">
        <th scope="row">s = ${signLabel(s)}</th>
        <td class="${row.low.slow ? 'cell-slow' : 'cell-fast'}">${row.low.slow ? 'slow' : 'fast'}</td>
        <td class="${row.high.slow ? 'cell-slow' : 'cell-fast'}">${row.high.slow ? 'slow' : 'fast'}</td>
        <td class="cell-infer">${active ? '◀ this coefficient' : ''}</td>
      </tr>`;
    })
    .join('');

  return `
    <section class="walkthrough" aria-label="Two-probe attack walkthrough for a single coefficient">
      <header class="walkthrough-head">
        <span class="walkthrough-eyebrow">Slow motion · one coefficient</span>
        <h3>How two probes read one secret coefficient</h3>
        <p class="walkthrough-lead">The attacker cannot see the secret <code>s &isin; {&minus;1, 0, +1}</code>. It sends two crafted ciphertexts whose offsets straddle this target&rsquo;s division-cost step — the <strong>+${w.jumpCycles}-cycle</strong> jump at numerator <strong>${formatInteger(w.boundaryNumerator)}</strong>, i.e. at coefficient <strong>${formatInteger(w.boundaryCoefficient)}</strong> — and lets the timing decide. Pick a hidden secret and watch the inference; the grid below is just this trick run 768 times.</p>
      </header>
      <div class="walkthrough-picker" role="group" aria-label="Choose the hidden secret coefficient to trace">
        <span class="walkthrough-picker-label">Hidden secret s =</span>
        ${([-1, 0, 1] as const)
          .map(
            (s) =>
              `<button type="button" class="chip ${secret === s ? 'is-active' : ''}" data-action="walk-${s < 0 ? 'neg' : s > 0 ? 'pos' : 'zero'}" aria-pressed="${secret === s}">${signLabel(s)}</button>`,
          )
          .join('')}
      </div>
      <div class="probe-pair">
        ${probeCard(w.low, `t=${formatInteger(w.low.probe)} only reaches the step when s = +1`)}
        ${probeCard(w.high, `t=${formatInteger(w.high.probe)} reaches it when s is 0 or +1`)}
      </div>
      <div class="truth-panel">
        <table class="truth-table">
          <caption class="sr-only">Truth table mapping each secret value to its fast/slow timing pair</caption>
          <thead>
            <tr><th scope="col">secret</th><th scope="col">t=${formatInteger(w.low.probe)}</th><th scope="col">t=${formatInteger(w.high.probe)}</th><th scope="col"></th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
        <p class="truth-result" role="status">Timing pair <strong>(${w.low.slow ? 'slow' : 'fast'}, ${w.high.slow ? 'slow' : 'fast'})</strong> is unique to <strong>s = ${signLabel(w.inferred)}</strong> — the coefficient is recovered without ever reading the key.</p>
      </div>
      <p class="walkthrough-note">Simplification worth naming: the paper&rsquo;s own Raspberry Pi 2 demo does not use adjacent probes. It <em>scales</em> the secret coefficient by an attacker-chosen multiplier <code>û</code> (§5.1.2 works through <code>û = 72</code>, then notes that &minus;72 and 107 pick out the other values) so a single secret value swings the numerator clean across that target&rsquo;s 3,329 step, and a handful of <code>û</code> values separate Kyber512&rsquo;s full &minus;3&hellip;+3 range. This lab uses <code>û = 1</code> and two adjacent probes instead — the same mechanism with the bookkeeping stripped out, which is why the secret here is a reduced three-value toy rather than a conformant ML-KEM key.</p>
      ${renderModelProvenance()}
    </section>`;
}

/**
 * A compact one-dimensional band line for the walkthrough: shows this target's
 * cost step and where a single numerator lands relative to it (fast/slow side).
 * The step is passed in rather than hardcoded, because it moves with the target
 * — numerator 3,329 on Cortex-A7, 2,048 on Cortex-M4.
 */
function renderBoundaryLine(dividend: number, slow: boolean, boundary: number): string {
  // Zoom tightly around the step. The four numerators the walkthrough can show
  // are boundary-3, boundary-1, boundary+1 and boundary+3 (the dividend is
  // always even and the probes are adjacent), so +/-6 keeps them distinct.
  const halfWindow = 6;
  const lo = boundary - halfWindow;
  const hi = boundary + halfWindow;
  const pos = Math.max(0, Math.min(100, ((dividend - lo) / (hi - lo)) * 100));
  const boundaryPos = ((boundary - lo) / (hi - lo)) * 100;
  return `
    <div class="boundary-line" role="img" aria-label="Numerator ${formatInteger(dividend)} lands on the ${slow ? 'slow' : 'fast'} side of the ${formatInteger(boundary)} cost step">
      <span class="boundary-band boundary-band--fast" style="width:${boundaryPos.toFixed(2)}%"></span>
      <span class="boundary-band boundary-band--slow" style="left:${boundaryPos.toFixed(2)}%;width:${(100 - boundaryPos).toFixed(2)}%"></span>
      <span class="boundary-tick" style="left:${boundaryPos.toFixed(2)}%"><span class="boundary-tick-label">${formatInteger(boundary)}</span></span>
      <span class="boundary-dot ${slow ? 'is-slow' : 'is-fast'}" style="left:${pos.toFixed(2)}%"></span>
    </div>`;
}

function renderRecoveryGrid(): string {
  const total = state.attackSecret.coeffs.length;
  const recovered = state.attackState.currentCoefficient;
  const freshIndex =
    state.attackEvents.length > 0 && state.attackMode === 'vulnerable'
      ? state.attackEvents[0].coefficient
      : -1;

  let matches = 0;
  let assessable = 0;

  const cells: string[] = [];
  for (let index = 0; index < total; index += 1) {
    const value = getRecoveredCoeff(state.attackState, index);
    const known = value !== null;
    const truth = state.attackSecret.coeffs[index];
    const tone = !known
      ? 'unknown'
      : value === 1
        ? 'pos'
        : value === -1
          ? 'neg'
          : 'zero';
    const glyph = !known ? '·' : value === 1 ? '+' : value === -1 ? '−' : '0';
    if (known) {
      assessable += 1;
      if (value === truth) {
        matches += 1;
      }
    }
    const fresh = index === freshIndex ? ' is-fresh' : '';
    cells.push(
      `<span class="recovery-cell recovery-cell--${tone}${fresh}" role="listitem" aria-label="coefficient ${index} ${
        known ? `recovered as ${value}` : 'not yet recovered'
      }">${glyph}</span>`,
    );
  }

  const complete = recovered === total;
  const accuracyPct = assessable > 0 ? (matches / assessable) * 100 : 0;
  let banner = '';
  if (state.attackMode === 'patched') {
    banner = `<span class="match-pill match-pill--neutral">Patched path · zero coefficients leaked</span>`;
  } else if (complete && matches === total) {
    banner = `<span class="match-pill match-pill--total">Recovered key matches secret · ${matches} / ${total} (100%)</span>`;
  } else if (complete) {
    banner = `<span class="match-pill match-pill--partial">Recovered ${matches} / ${total} (${formatDecimal(accuracyPct, 1)}%)</span>`;
  } else if (assessable > 0) {
    banner = `<span class="match-pill match-pill--running">${matches} / ${assessable} verified · attack in progress</span>`;
  }

  return `
    <section class="recovery-section" aria-label="Secret key recovery status">
      <header class="recovery-header">
        <div>
          <p class="mini-label">Secret key recovery</p>
          <strong>${recovered} / ${total} coefficients revealed</strong>
        </div>
        ${banner}
      </header>
      <div class="recovery-grid" role="list" tabindex="0" aria-label="ML-KEM-768 secret key coefficients">
        ${cells.join('')}
      </div>
      <p class="recovery-legend" aria-hidden="true">
        <span class="recovery-cell recovery-cell--unknown" aria-hidden="true">·</span> unknown
        <span class="recovery-cell recovery-cell--neg" aria-hidden="true">−</span> −1
        <span class="recovery-cell recovery-cell--zero" aria-hidden="true">0</span> 0
        <span class="recovery-cell recovery-cell--pos" aria-hidden="true">+</span> +1
        <span class="recovery-cell recovery-cell--pos is-fresh" aria-hidden="true">+</span> just recovered
      </p>
    </section>`;
}

// The attack loop repaints these dynamic regions every frame. They are split out
// so paintAttackExhibit() can refresh them in place without touching the control
// buttons' DOM nodes — otherwise rebuilding the controls ~60×/s would drop a
// mouse click (e.g. Stop) that happens to span a repaint frame.
function renderMilestoneStripInner(): string {
  return MILESTONE_PCT.map((threshold) => {
    const reached = state.milestonesReached.includes(threshold);
    return `<span class="milestone ${reached ? 'is-reached' : ''}" aria-label="${threshold}% milestone${reached ? ' reached' : ''}">${threshold}%</span>`;
  }).join('');
}

function renderMeterStackInner(): string {
  const progress = (state.attackState.queries / ATTACK_QUERY_BUDGET) * 100;
  const recoveredProgress = (state.attackState.recoveredBits / state.attackState.totalBits) * 100;
  return `
          <div class="meter-block">
            <p class="meter-label">Queries sent</p>
            <div class="meter" aria-hidden="true"><span style="width:${progress}%"></span></div>
            <small>${formatInteger(state.attackState.queries)} / ${formatInteger(ATTACK_QUERY_BUDGET)}</small>
          </div>
          <div class="meter-block">
            <p class="meter-label">Bits recovered</p>
            <div class="meter meter--gold" aria-hidden="true"><span style="width:${recoveredProgress}%"></span></div>
            <small>${formatInteger(state.attackState.recoveredBits)} / ${formatInteger(state.attackState.totalBits)}</small>
          </div>
          <div class="meter-block">
            <p class="meter-label">Simulated elapsed time</p>
            <div class="meter meter--cyan" aria-hidden="true"><span style="width:${progress}%"></span></div>
            <small>${formatDecimal(state.attackState.queries / 1500, 1)} minutes</small>
          </div>`;
}

function renderAttackTraceInner(): string {
  return createPolyline(state.attackQueryTimes, state.attackMode === 'vulnerable' ? 'danger' : 'safe');
}

function renderAnalysisBoxInner(): string {
  const analysis = state.attackAnalysis ?? statisticalAnalysis(state.attackState.timingProfile);
  return `
            <p>Timing correlation test</p>
            <strong>${analysis.distinguishable ? 'Signal present' : 'Noise floor only'}</strong>
            <span>confidence = ${formatDecimal(analysis.confidenceLevel, 3)}</span>
            <span>estimated queries needed = ${formatInteger(analysis.estimatedQueriesNeeded)}</span>`;
}

function renderAttackLogInner(): string {
  return `
            <header class="attack-log-header">
              <p>Attack log</p>
              <span class="attack-log-count">${state.attackLog.length} event${state.attackLog.length === 1 ? '' : 's'}</span>
            </header>
            ${
              state.attackLog.length === 0
                ? `<p class="attack-log-empty">${
                    state.attackMode === 'patched'
                      ? 'Patched path produces no recoveries. Launch a run to confirm the noise floor.'
                      : 'Launch the attack to begin collecting distinguishable traces.'
                  }</p>`
                : `<ol class="attack-log-list">
                    ${state.attackLog
                      .map(
                        (entry) => `<li class="attack-log-entry attack-log-entry--${entry.kind}">
                          <span class="attack-log-time">T+${formatDecimal(entry.elapsedSeconds, 2)}s</span>
                          <span class="attack-log-text">${escapeHtml(entry.text)}</span>
                          <span class="attack-log-meta">q=${formatInteger(entry.query)}</span>
                        </li>`,
                      )
                      .join('')}
                  </ol>`
            }`;
}

function renderAttack(): string {
  const displayedMode = state.attackMode === 'vulnerable' ? 'YES' : 'PATCHED';

  return `
    <section class="panel exhibit" id="exhibit-3" data-exhibit="3" aria-busy="${state.attackRunning}">
      <div class="section-heading">
        <p class="kicker">Exhibit 3 of 5</p>
        <h2>Live attack progress</h2>
      </div>
      ${renderTryThis(2)}
      <div class="milestone-strip" role="group" aria-label="Recovery milestones">
        ${renderMilestoneStripInner()}
      </div>
      <div class="attack-summary">
        <div>
          <p class="mini-label">Attack variant</p>
          <strong>KyberSlash1 (poly_tomsg), modeled against ML-KEM-768</strong>
          <p class="attack-subtitle">This browser demo uses a deterministic timing model rather than real JavaScript timing. The attacker submits crafted ciphertexts, measures the modelled ${glossTerm('poly_tomsg', 'the decryption step that turns a polynomial back into the message bits')} division cost, and infers each secret coefficient from which side of <code>${escapeHtml(getPlatformProfile(state.platform).divisionOp)}</code>&rsquo;s cost step the timing lands on — the secret is never read directly, it emerges statistically from the noisy cycle counts.</p>
          <p class="attack-fieldnote">Field result: in the original work a real Kyber512 key fell on a Raspberry Pi 2 (Cortex-A7) within 2–4 hours in 10 of 10 experiments, with the demo budgeted to give up after 7&middot;2<sup>18</sup> = 1,835,008 decapsulations (KyberSlash, TCHES 2025(2), Table 1 and §5.2).</p>
        </div>
        <div class="attack-mode-toggle">
          <button type="button" class="chip ${state.attackMode === 'vulnerable' ? 'is-active' : ''}" data-action="mode-vulnerable" aria-pressed="${state.attackMode === 'vulnerable'}">Vulnerable path</button>
          <button type="button" class="chip ${state.attackMode === 'patched' ? 'is-active' : ''}" data-action="mode-patched" aria-pressed="${state.attackMode === 'patched'}">Patched path</button>
        </div>
      </div>
      <div class="speed-row" role="group" aria-label="Attack playback speed">
        <span class="speed-label">Playback speed</span>
        <button type="button" class="chip chip--speed ${state.attackSpeed === 1 ? 'is-active' : ''}" data-action="speed-1" aria-pressed="${state.attackSpeed === 1}">1×</button>
        <button type="button" class="chip chip--speed ${state.attackSpeed === 4 ? 'is-active' : ''}" data-action="speed-4" aria-pressed="${state.attackSpeed === 4}">4×</button>
        <button type="button" class="chip chip--speed ${state.attackSpeed === 16 ? 'is-active' : ''}" data-action="speed-16" aria-pressed="${state.attackSpeed === 16}">16×</button>
        <span class="speed-hint">${state.attackSpeed === 1 ? 'real-time streaming' : state.attackSpeed === 4 ? 'enough to skim a recovery' : 'fast-forward to the verified match'}</span>
      </div>
      ${renderProbeWalkthrough()}
      ${renderRecoveryGrid()}
      <div class="attack-layout">
        <div class="attack-card">
          <p class="attack-line"><span>Target:</span><strong>ML-KEM-768 secret key, 768 coefficients</strong></p>
          <p class="attack-line"><span>Implementation:</span><strong>${displayedMode}</strong></p>
          <p class="attack-line"><span>Target platform:</span><strong>Simulated ${escapeHtml(PLATFORM_LABELS[state.platform])}</strong></p>
          <div class="meter-stack">${renderMeterStackInner()}</div>
          <div class="controls-row">
            <button type="button" class="control" data-action="launch-attack" ${state.attackRunning ? 'disabled' : ''}>Launch KyberSlash attack</button>
            <button type="button" class="control ghost" data-action="stop-attack" ${state.attackRunning ? '' : 'disabled'}>Stop</button>
            <button type="button" class="control ghost" data-action="export-samples">Export timing samples</button>
          </div>
          <div class="controls-row compact">
            <button type="button" class="control subtle" data-action="switch-implementation">Switch to ${state.attackMode === 'vulnerable' ? 'patched' : 'vulnerable'} implementation</button>
            <button type="button" class="control subtle" data-action="regenerate-key" ${state.attackRunning ? 'disabled' : ''}>Generate new target key</button>
          </div>
        </div>
        <div class="attack-card attack-card--secondary" aria-live="polite">
          <div class="attack-trace-host">${renderAttackTraceInner()}</div>
          <div class="analysis-box">${renderAnalysisBoxInner()}</div>
          <div class="attack-log" aria-label="Attack event log">${renderAttackLogInner()}</div>
        </div>
      </div>
    </section>`;
}

function renderTimeline(): string {
  return `
    <section class="panel exhibit" id="exhibit-4" data-exhibit="4">
      <div class="section-heading">
        <p class="kicker">Exhibit 4 of 5</p>
        <h2>The disclosure timeline</h2>
      </div>
      ${renderTryThis(3)}
      <div class="timeline">
        ${TIMELINE.map(([date, text]) => `<article><span>${date}</span><p>${text}</p></article>`).join('')}
      </div>
      <div class="callout-row">
        <article class="callout danger">
          <h3>Had divisions on secret inputs at the start of December 2023</h3>
          <p>The pq-crystals reference C, and the ports that inherited its shape: liboqs, PQClean (clean and aarch64), pqm4, botan, aws-lc, cloudflare/circl (KyberSlash2 only), kyber-k2so, crystals-go, rustpq/pqcrypto (patched downstream in Signal on 5 January 2024), zig's std.crypto, kyberlib, pypqc. Two more — Argyle-Software/kyber and crystals-kyber-javascript — were still carrying a division as of the project's August 2025 survey.</p>
        </article>
        <article class="callout safe">
          <h3>Reportedly never had divisions on secret inputs</h3>
          <p>BoringSSL's Kyber, filippo.io/mlkem768, libjade's AVX2 and reference Kyber, and the AVX2 paths of pq-crystals/kyber, PQClean and kyberlib. Source: the KyberSlash project's own per-library survey — not a general claim that these are side-channel free.</p>
        </article>
      </div>
    </section>`;
}

function renderLessons(): string {
  const compressExample = polyCompressVulnerable(measurementCoefficients(3), KYBER_PARAMS.dv);
  const compressPatched = polyCompressPatched(measurementCoefficients(3), KYBER_PARAMS.dv);

  return `
    <section class="panel exhibit" id="exhibit-5" data-exhibit="5">
      <div class="section-heading">
        <p class="kicker">Exhibit 5 of 5</p>
        <h2>What this means for PQ deployment</h2>
      </div>
      ${renderTryThis(4)}
      <div class="lesson-grid">
        ${LESSONS.map((lesson, index) => `<article><span>Lesson ${index + 1}</span><p>${lesson}</p></article>`).join('')}
      </div>
      <div class="callout-row">
        <article class="callout neutral">
          <h3>KyberSlash2 in one line</h3>
          <p>poly_compress and polyvec_compress divide by q during PKE <em>encryption</em>. Inside encapsulation that is harmless — the ciphertext is public. The damage is that Kyber's Fujisaki-Okamoto transform re-runs encryption inside <em>decapsulation</em>, where the input is secret-derived, turning the timing into a plaintext-checking oracle. In this demo the same coefficient vector lands at ${formatInteger(compressExample.totalCycles)} cycles before the patch and ${formatInteger(compressPatched.totalCycles)} after it.</p>
        </article>
        <article class="callout neutral">
          <h3>What "responsible disclosure" actually looked like</h3>
          <p>The pq-crystals reference code was patched for KyberSlash1 on 1 December 2023, two weeks before the issue went public — but that is where the tidy version ends. KyberSlash2 was reported and patched on the day it was announced, and downstream libraries were fixed over the following weeks and months, in the open. This lab teaches the failure mode and the fix; it is not a guide to attacking maintained libraries.</p>
        </article>
      </div>
      <div class="crosslinks">
        <p class="kicker kicker--sub">Crypto Lab suite</p>
        <h3>Neighbouring exhibits worth a click</h3>
        <div class="crosslink-grid">
          ${CROSSLINKS.map(
            (link) => `
            <a class="crosslink-card crosslink-card--${link.tone}" href="${escapeHtml(link.href)}" target="_blank" rel="noopener">
              <div class="crosslink-slug">${escapeHtml(link.slug)}</div>
              <div class="crosslink-title">${escapeHtml(link.title)}</div>
              <p class="crosslink-copy">${escapeHtml(link.description)}</p>
              <span class="crosslink-arrow" aria-hidden="true">→</span>
            </a>`,
          ).join('')}
        </div>
      </div>
    </section>`;
}

function render(focusTarget?: string): void {
  const summary = measurementSummary(state.vulnerableSamples);
  const patchedSummary = measurementSummary(state.patchedSamples);
  const activeAction =
    document.activeElement instanceof HTMLElement
      ? document.activeElement.closest<HTMLElement>('[data-action]')?.dataset.action
      : undefined;
  const nextFocusTarget = focusTarget ?? activeAction;

  app.innerHTML = `
    <a class="skip-link" href="#main-content">Skip to main content</a>
    <main id="main-content" class="lab-shell" tabindex="-1">
      <div class="sr-only" role="status" aria-live="polite" aria-atomic="true">${escapeHtml(state.statusMessage)}</div>
      <header class="topbar">
        <p class="topbar-label">Educational side-channel lab</p>
        <strong>ML-KEM-768 — the post-quantum key exchange whose reference code leaked its secret key through division timing.</strong>
        <details class="param-disclosure">
          <summary>Kyber parameters (for the curious)</summary>
          <dl class="param-list">
            <div><dt>n = ${KYBER_PARAMS.n}</dt><dd>coefficients per polynomial</dd></div>
            <div><dt>k = ${KYBER_PARAMS.k}</dt><dd>polynomials in the secret vector (768 = 3×256 coefficients total)</dd></div>
            <div><dt>q = ${KYBER_PARAMS.q}</dt><dd>the prime modulus — the constant every coefficient is divided by, and the source of the leak</dd></div>
            <div><dt>η1 = ${KYBER_PARAMS.eta1}, η2 = ${KYBER_PARAMS.eta2}</dt><dd>noise widths of the centered binomial distribution the secret is sampled from — with η1 = 2 every real ML-KEM-768 secret coefficient lies in −2…+2. This lab narrows them to −1, 0, +1 so one coefficient falls out of exactly two timing probes.</dd></div>
            <div><dt>du = ${KYBER_PARAMS.du}, dv = ${KYBER_PARAMS.dv}</dt><dd>ciphertext compression bit-widths — dv drives the KyberSlash2 (poly_compress) variant</dd></div>
          </dl>
        </details>
      </header>
      ${renderHero()}
      <section class="status-strip">
        <article><span>Reference risk</span><strong>division on secret data</strong></article>
        <article><span>Current vulnerable mean</span><strong>${formatInteger(summary.value)} cycles</strong></article>
        <article><span>Current patched mean</span><strong>${formatInteger(patchedSummary.value)} cycles</strong></article>
        <article><span>Deployment lesson</span><strong>standardization is not safety</strong></article>
      </section>
      ${renderProgressRail()}
      ${renderSmokingGun()}
      ${renderBridge(0)}
      ${renderOscilloscope()}
      ${renderBridge(1)}
      ${renderAttack()}
      ${renderBridge(2)}
      ${renderTimeline()}
      ${renderBridge(3)}
      ${renderLessons()}
      <footer class="footer-note">
        <p>JavaScript cannot measure the real timing of CPU division instructions reliably. This demo therefore uses a deterministic leakage model aligned with the published KyberSlash paper rather than browser timing APIs.</p>
        <p class="citation">
          <span>Reference</span>
          Bernstein, Bhargavan, Bhasin, Chattopadhyay, Chia, Kannwischer, Kiefer, Paiva, Ravi, Tamvada — “KyberSlash: Exploiting secret-dependent division timings in Kyber implementations,” IACR TCHES 2025(2): 209–234. CHES 2025 Best Paper Award.
          <a href="https://eprint.iacr.org/2024/1049" target="_blank" rel="noopener">eprint.iacr.org/2024/1049</a>
          ·
          <a href="https://github.com/systemslibrarian/crypto-lab-kyberslash" target="_blank" rel="noopener">source on GitHub</a>
        </p>
        <p class="citation">
          <span>Related demos</span>
          <a href="https://systemslibrarian.github.io/crypto-lab-lattice-fault/" target="_blank" rel="noopener">crypto-lab-lattice-fault</a>
          ·
          <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">crypto-lab-kyber-vault</a>
          ·
          <a href="https://systemslibrarian.github.io/crypto-lab-hqc-timing/" target="_blank" rel="noopener">crypto-lab-hqc-timing</a>
          ·
          <a href="https://systemslibrarian.github.io/crypto-lab-ciphertext-mirror/" target="_blank" rel="noopener">crypto-lab-ciphertext-mirror</a>
        </p>
        <blockquote class="footer-verse">
          <p>${QUOTE}</p>
          <footer>1 Corinthians 10:31</footer>
        </blockquote>
      </footer>
      <div class="live-status" aria-hidden="true">
        <span class="live-status__dot ${state.attackRunning || state.measuring ? 'is-active' : ''}"></span>
        <span class="live-status__text">${escapeHtml(state.statusMessage)}</span>
      </div>
    </main>`;

  if (nextFocusTarget) {
    const focusElement = app.querySelector<HTMLElement>(`[data-action="${nextFocusTarget}"]`);
    if (focusElement && !focusElement.hasAttribute('disabled')) {
      focusElement.focus();
    }
  }

  setupScrollSpy();
}

let scrollSpyObserver: IntersectionObserver | null = null;

function setupScrollSpy(): void {
  if (typeof IntersectionObserver === 'undefined') {
    return;
  }
  if (scrollSpyObserver) {
    scrollSpyObserver.disconnect();
  }
  const exhibits = Array.from(app.querySelectorAll<HTMLElement>('.exhibit[data-exhibit]'));
  const links = Array.from(app.querySelectorAll<HTMLAnchorElement>('.rail-link[data-exhibit]'));
  if (exhibits.length === 0 || links.length === 0) {
    return;
  }

  const visible = new Map<string, number>();
  scrollSpyObserver = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const id = (entry.target as HTMLElement).dataset.exhibit ?? '';
        if (entry.isIntersecting) {
          visible.set(id, entry.intersectionRatio);
        } else {
          visible.delete(id);
        }
      }
      let activeId = '';
      let bestRatio = -1;
      for (const [id, ratio] of visible.entries()) {
        if (ratio > bestRatio) {
          bestRatio = ratio;
          activeId = id;
        }
      }
      for (const link of links) {
        const isActive = link.dataset.exhibit === activeId;
        link.classList.toggle('is-active', isActive);
        if (isActive) {
          link.setAttribute('aria-current', 'location');
        } else {
          link.removeAttribute('aria-current');
        }
      }
      if (activeId && window.history && typeof window.history.replaceState === 'function') {
        const desiredHash = `#exhibit-${activeId}`;
        if (window.location.hash !== desiredHash) {
          window.history.replaceState(null, '', desiredHash);
        }
      }
    },
    { rootMargin: '-30% 0px -55% 0px', threshold: [0, 0.25, 0.5, 0.75, 1] },
  );
  for (const exhibit of exhibits) {
    scrollSpyObserver.observe(exhibit);
  }
}

app.addEventListener('click', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const action = target.closest<HTMLElement>('[data-action]')?.dataset.action;
  if (!action) {
    return;
  }

  switch (action) {
    case 'code-vulnerable':
      state.codeMode = 'vulnerable';
      setStatusMessage('Showing the vulnerable reference code path.');
      render('code-vulnerable');
      break;
    case 'code-patched':
      state.codeMode = 'patched';
      setStatusMessage('Showing the patched Barrett-reduction code path.');
      render('code-patched');
      break;
    case 'next-measurement':
      void runMeasurementBatch(1, 'next-measurement');
      break;
    case 'run-hundred':
      void runMeasurementBatch(100, 'run-hundred');
      break;
    case 'toggle-distribution':
      state.showDistribution = !state.showDistribution;
      setStatusMessage(`${state.showDistribution ? 'Showing' : 'Hiding'} timing distribution histogram.`);
      render('toggle-distribution');
      break;
    case 'flip-before':
      if (state.flipMode !== 'before') {
        state.flipMode = 'before';
        setStatusMessage('Overlay showing vulnerable timing on the shared scale.');
        render('flip-before');
      }
      break;
    case 'flip-after':
      if (state.flipMode !== 'after') {
        state.flipMode = 'after';
        setStatusMessage('Flipped to patched — same dataset, signal vanished on the shared scale.');
        render('flip-after');
      }
      break;
    case 'speed-1':
      state.attackSpeed = 1;
      setStatusMessage('Playback speed: 1× (real-time).');
      render('speed-1');
      break;
    case 'speed-4':
      state.attackSpeed = 4;
      setStatusMessage('Playback speed: 4×.');
      render('speed-4');
      break;
    case 'speed-16':
      state.attackSpeed = 16;
      setStatusMessage('Playback speed: 16× (fast-forward).');
      render('speed-16');
      break;
    case 'walk-neg':
      state.walkthroughSecret = -1;
      setStatusMessage('Walkthrough: tracing a hidden secret coefficient of −1.');
      render('walk-neg');
      break;
    case 'walk-zero':
      state.walkthroughSecret = 0;
      setStatusMessage('Walkthrough: tracing a hidden secret coefficient of 0.');
      render('walk-zero');
      break;
    case 'walk-pos':
      state.walkthroughSecret = 1;
      setStatusMessage('Walkthrough: tracing a hidden secret coefficient of +1.');
      render('walk-pos');
      break;
    case 'start-tour':
      void runTour();
      break;
    case 'stop-tour':
      stopTour();
      break;
    case 'mode-vulnerable':
      resetAttack('vulnerable');
      render('mode-vulnerable');
      break;
    case 'mode-patched':
      resetAttack('patched');
      render('mode-patched');
      break;
    case 'launch-attack':
      void startAttack();
      break;
    case 'stop-attack':
      state.attackStopRequested = true;
      setStatusMessage('Stopping the current attack simulation.');
      render('stop-attack');
      break;
    case 'export-samples':
      exportSamples();
      render('export-samples');
      break;
    case 'switch-implementation':
      resetAttack(state.attackMode === 'vulnerable' ? 'patched' : 'vulnerable');
      render('switch-implementation');
      break;
    case 'regenerate-key':
      if (state.attackRunning) {
        break;
      }
      state.attackSecret = generateSecretKey();
      resetAttack(state.attackMode);
      setStatusMessage('Generated a new ML-KEM-768 secret key. Attack state reset.');
      render('regenerate-key');
      break;
    case 'set-platform-a7':
      void switchPlatform('cortex-a7', 'set-platform-a7');
      break;
    case 'set-platform-m4':
      void switchPlatform('cortex-m4', 'set-platform-m4');
      break;
    default:
      break;
  }
});

async function switchPlatform(platform: Platform, focusTarget: string): Promise<void> {
  if (state.platform === platform || state.measuring || state.attackRunning) {
    return;
  }
  state.platform = platform;
  setActivePlatform(platform);
  localStorage.setItem('platform', platform);
  state.measurementIndex = 0;
  state.vulnerableSamples = [];
  state.patchedSamples = [];
  for (let index = 0; index < 6; index += 1) {
    recordMeasurement();
  }
  resetAttack(state.attackMode);
  setStatusMessage(`Target platform set to ${PLATFORM_LABELS[platform]}. Recomputed timing baselines.`);
  render(focusTarget);
}

for (let index = 0; index < 6; index += 1) {
  recordMeasurement();
}

render();

const initialHash = window.location.hash;
if (initialHash && /^#exhibit-[1-5]$/.test(initialHash)) {
  requestAnimationFrame(() => {
    const target = document.querySelector(initialHash);
    if (target instanceof HTMLElement) {
      target.scrollIntoView({ behavior: 'auto', block: 'start' });
    }
  });
}

if (typeof window.matchMedia === 'function') {
  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  motionQuery.addEventListener?.('change', () => {
    setStatusMessage(motionQuery.matches ? 'Reduced motion enabled.' : 'Reduced motion disabled.');
  });
}
