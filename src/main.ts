import './style.css';

import {
  attackIteration,
  createAttackState,
  generateSecretKey,
  getRecoveredCoeff,
  statisticalAnalysis,
  type AttackState,
  type SecretKey,
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
  PLATFORM_LABELS,
  setActivePlatform,
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
  milestonesReached: number[];
  statusMessage: string;
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

const PATCHED_LINES: readonly CodeLine[] = [
  { text: '// Patched constant-time version - Barrett reduction' },
  { text: `// BARRETT_INV = floor(2^32 / 3329) + 1 = ${BARRETT_INV_Q}` },
  { text: '' },
  { text: 'for (int j = 0; j < 8; j++) {' },
  { text: '    t = a->coeffs[8*i+j];' },
  { text: '    t += ((int16_t)t >> 15) & KYBER_Q;' },
  { text: '' },
  { text: '    // No division instruction on secret data' },
  { text: '    t = ((((uint32_t)t << 1) + KYBER_Q/2)', hl: 'safe' },
  { text: '         * BARRETT_INV >> 32) & 1;', hl: 'safe' },
  { text: '' },
  { text: '    msg[i] |= t << j;' },
  { text: '}' },
];

const TIMELINE = [
  ['2022 Jul', 'NIST selects Kyber for post-quantum standardization.'],
  ['2024 Jan', 'Cryspen, Bhargavan, Kiefer, and Tamvada spot the division issue while building a verified Rust implementation.'],
  ['2024 Apr', 'KyberSlash paper submitted to TCHES.'],
  ['2024 Jun', 'Reference code patched before public disclosure.'],
  ['2024 Aug', 'Responsible disclosure window closes; ML-KEM lands in FIPS 203.'],
  ['2024-2025', 'Patches propagate through PQClean, liboqs, libpqcrypto, mlkem-native, OpenSSL integrations, and hardware designs.'],
  ['2025 Jan', 'Final paper published in TCHES 2025 issue 2.'],
  ['2025 Mar', 'CHES 2025 Best Paper Award.'],
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
  'Skim the dates. NIST standardised Kyber in <strong>2022</strong>. Cryspen spotted the bug in <strong>2024</strong>. That two-year gap is the window any real deployment had to weather, and it is why "standardised" and "safe to deploy" are not the same property.',
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
  milestonesReached: [],
  statusMessage: 'KyberSlash lab ready. Initial timing traces loaded.',
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
  return `
    <section class="hero-shell">
      <div class="hero-copy">
        <p class="eyebrow">Crypto Lab · KyberSlash</p>
        <h1>How a single CPU division leaked a post-quantum secret key</h1>
        <p class="lead">
          ML-KEM (formerly Kyber) is the post-quantum encryption replacing RSA in TLS and NIST <strong>FIPS 203</strong>. Its reference C code passed years of review before standardisation. But on a $35 Raspberry Pi, a single line of math took different amounts of time depending on the secret value being processed — and that timing gap alone was enough to recover the entire key.
        </p>
        <p class="lead">
          This page walks through the bug, the one-line patch, and a live in-browser attack that recovers all 768 coefficients of an ML-KEM-768 secret key — KyberSlash2 falls in minutes, KyberSlash1 in hours. <strong>Work down through Exhibits 1–5 below — each one tells you exactly what to click.</strong>
        </p>
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
          <span class="platform-current">${state.attackRunning || state.measuring ? 'platform locked while a run is in progress' : `simulating ${escapeHtml(platformLabel)} · click to switch to ${escapeHtml(altLabel)}`}</span>
        </div>
        <div class="hero-notes">
          <span class="pill pill--danger">KyberSlash1: decapsulation / poly_tomsg</span>
          <span class="pill pill--danger">KyberSlash2: encapsulation / poly_compress</span>
          <span class="pill pill--safe">Patched before disclosure</span>
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

function renderSmokingGun(): string {
  const lines = state.codeMode === 'vulnerable' ? VULNERABLE_LINES : PATCHED_LINES;
  const annotations =
    state.codeMode === 'vulnerable'
      ? [
          'The vulnerable line divides a secret-dependent dividend by q = 3329.',
          'On Cortex-A7 the corresponding udiv latency varies by roughly 7 to 30 cycles; on Cortex-M4 the spread is smaller but still exploitable.',
          'Modern x86_64 often avoids the bug only because the compiler rewrites division into multiplication, but -Os can put division back.',
        ]
      : [
          `The fix uses Barrett reduction with BARRETT_INV = ${BARRETT_INV_Q}.`,
          'Multiplication plus shift removes the variable-latency division instruction from the secret path.',
          'This was rolled out through major ML-KEM libraries before disclosure.',
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
      <footer class="code-citations" aria-label="Where this code lives upstream">
        <span class="citations-label">Upstream</span>
        <a class="citation-chip" href="https://github.com/pq-crystals/kyber/blob/main/ref/poly.c" target="_blank" rel="noopener">pq-crystals/kyber · ref/poly.c</a>
        <a class="citation-chip" href="https://eprint.iacr.org/2024/1049" target="_blank" rel="noopener">KyberSlash paper · eprint 2024/1049</a>
        <a class="citation-chip" href="https://csrc.nist.gov/pubs/fips/203/final" target="_blank" rel="noopener">FIPS 203 · ML-KEM standard</a>
      </footer>
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
      <div class="verdict verdict--${verdictTone}" role="status">
        <div class="verdict-row">
          <span class="verdict-pill">Variance ratio</span>
          <strong>${samplesReady ? spreadRatioLabel : '—'}</strong>
        </div>
        <div class="verdict-row">
          <span class="verdict-pill">Mean delta</span>
          <strong>${formatInteger(deltaCycles)} cycles</strong>
        </div>
        <div class="verdict-row">
          <span class="verdict-pill">Mean ratio</span>
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
            <strong>Cortex-A7 simulated leakage</strong>
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
  const analysis = statisticalAnalysis(state.attackState.timingProfile);
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
          <strong>KyberSlash2, modeled against ML-KEM-768</strong>
          <p class="attack-subtitle">This browser demo uses a deterministic timing model rather than real JavaScript timing. It mirrors the paper's leakage dynamics without pretending to measure actual CPU cycles in the browser.</p>
          <p class="attack-fieldnote">Field result: in the original work a real Kyber512 key fell on a Raspberry Pi 2 (Cortex-A7) within 2–4 hours across 10 of 10 trials.</p>
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
          <h3>Implementations that were vulnerable before patching</h3>
          <p>Reference C code, libpqcrypto-kyber, multiple liboqs-dependent stacks, embedded ports, and some hardware or FPGA designs.</p>
        </article>
        <article class="callout safe">
          <h3>Implementations that avoided the bug</h3>
          <p>Cryspen's verified Rust work, some constant-time libraries designed around multiplication-based reductions, and many AVX2 paths that never used this division pattern.</p>
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
          <p>poly_compress used secret-dependent division during encapsulation. In this demo the same coefficient vector lands at ${formatInteger(compressExample.totalCycles)} cycles before the patch and ${formatInteger(compressPatched.totalCycles)} after it.</p>
        </article>
        <article class="callout neutral">
          <h3>Responsible disclosure</h3>
          <p>The vulnerable paths were patched across major implementations before public disclosure. This lab teaches the failure mode and the fix; it is not a guide to attacking maintained libraries.</p>
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
        <strong>ML-KEM-768 / Kyber768 parameters: n=${KYBER_PARAMS.n}, k=${KYBER_PARAMS.k}, q=${KYBER_PARAMS.q}, eta1=${KYBER_PARAMS.eta1}, eta2=${KYBER_PARAMS.eta2}, du=${KYBER_PARAMS.du}, dv=${KYBER_PARAMS.dv}</strong>
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
