import './style.css';

import {
  attackIteration,
  createAttackState,
  generateSecretKey,
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
import { aggregateTimings } from './timing-model';

type ThemeMode = 'dark' | 'light';
type CodeMode = 'vulnerable' | 'patched';
type AttackMode = 'vulnerable' | 'patched';

interface RecoveryEvent {
  coefficient: number;
  confidence: number;
  value: number;
}

interface AppState {
  theme: ThemeMode;
  codeMode: CodeMode;
  showDistribution: boolean;
  measuring: boolean;
  measurementIndex: number;
  vulnerableSamples: number[];
  patchedSamples: number[];
  attackMode: AttackMode;
  attackRunning: boolean;
  attackStopRequested: boolean;
  attackRunId: number;
  attackSecret: SecretKey;
  attackState: AttackState;
  attackQueryTimes: number[];
  attackEvents: RecoveryEvent[];
}

const QUOTE = '"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."';
const ATTACK_QUERY_BUDGET = 20000;
const TRACE_LIMIT = 28;

const VULNERABLE_CODE = `// Kyber reference implementation - poly_tomsg function
// KyberSlash1, pre-patch reference C code

for (int j = 0; j < 8; j++) {
    t = a->coeffs[8*i+j];
    t += ((int16_t)t >> 15) & KYBER_Q;

    // Secret-dependent division by q = 3329
    t = (((t << 1) + KYBER_Q/2) / KYBER_Q) & 1;

    msg[i] |= t << j;
}`;

const PATCHED_CODE = `// Patched constant-time version - Barrett reduction
// BARRETT_INV = floor(2^32 / 3329) + 1 = ${BARRETT_INV_Q}

for (int j = 0; j < 8; j++) {
    t = a->coeffs[8*i+j];
    t += ((int16_t)t >> 15) & KYBER_Q;

    // No division instruction on secret data
    t = ((((uint32_t)t << 1) + KYBER_Q/2)
         * BARRETT_INV >> 32) & 1;

    msg[i] |= t << j;
}`;

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

const CROSSLINKS = [
  'crypto-lab-kyber-vault - ML-KEM-768 baseline demo',
  'crypto-lab-pq-tls-handshake - where ML-KEM lands in TLS 1.3',
  'crypto-lab-lattice-fault - fault-injection attacks on lattice systems',
  'crypto-lab-timing-oracle - classical timing-oracle failures',
  'crypto-lab-padding-oracle - implementation bugs defeating correct mathematics',
  'crypto-lab-model-breach - broader cryptographic deployment failures',
] as const;

const appRoot = document.querySelector<HTMLDivElement>('#app');

if (!appRoot) {
  throw new Error('Application root not found');
}

const app = appRoot;

document.title = 'KyberSlash Timing Attack on ML-KEM';

const initialTheme = (document.documentElement.getAttribute('data-theme') ?? 'dark') as ThemeMode;
const initialSecret = generateSecretKey();

const state: AppState = {
  theme: initialTheme,
  codeMode: 'vulnerable',
  showDistribution: false,
  measuring: false,
  measurementIndex: 0,
  vulnerableSamples: [],
  patchedSamples: [],
  attackMode: 'vulnerable',
  attackRunning: false,
  attackStopRequested: false,
  attackRunId: 0,
  attackSecret: initialSecret,
  attackState: createAttackState(initialSecret),
  attackQueryTimes: [],
  attackEvents: [],
};

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function setTheme(theme: ThemeMode): void {
  state.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
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

async function runMeasurementBatch(count: number): Promise<void> {
  if (state.measuring) {
    return;
  }

  state.measuring = true;
  render();

  for (let index = 0; index < count; index += 1) {
    recordMeasurement();
    if (index % 20 === 0) {
      render();
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    }
  }

  state.measuring = false;
  render();
}

function createPolyline(values: number[], tone: 'danger' | 'safe'): string {
  if (values.length === 0) {
    return `<svg viewBox="0 0 100 40" class="trace-svg"><line x1="0" y1="20" x2="100" y2="20" class="trace-line trace-line--${tone}" /></svg>`;
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

  return `<svg viewBox="0 0 100 40" class="trace-svg"><polyline points="${points}" class="trace-line trace-line--${tone}" /></svg>`;
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

function resetAttack(mode: AttackMode = state.attackMode): void {
  state.attackMode = mode;
  state.attackRunning = false;
  state.attackStopRequested = false;
  state.attackRunId += 1;
  state.attackState = createAttackState(state.attackSecret);
  state.attackQueryTimes = [];
  state.attackEvents = [];
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

async function startAttack(): Promise<void> {
  if (state.attackRunning) {
    return;
  }

  resetAttack(state.attackMode);
  state.attackRunning = true;
  state.attackStopRequested = false;
  const runId = state.attackRunId;
  render();

  while (
    !state.attackStopRequested &&
    runId === state.attackRunId &&
    state.attackState.currentCoefficient < state.attackSecret.coeffs.length &&
    state.attackState.queries < ATTACK_QUERY_BUDGET
  ) {
    for (let batch = 0; batch < 80; batch += 1) {
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
      }
    }

    render();
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }

  state.attackRunning = false;
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
  anchor.click();
  URL.revokeObjectURL(url);
}

function measurementSummary(values: number[]): { value: number; stddev: number } {
  return aggregateTimings(values, 'mean');
}

function renderHero(): string {
  return `
    <section class="hero-shell">
      <div class="hero-copy">
        <p class="eyebrow">crypto-lab-kyberslash</p>
        <h1>KyberSlash timing attack on ML-KEM</h1>
        <p class="lead">
          A browser-only educational lab showing how secret-dependent division in the Kyber reference implementation leaked keys on
          <strong>ARM Cortex-A7</strong> and <strong>Cortex-M4</strong>, even though ML-KEM became <strong>NIST FIPS 203</strong>.
        </p>
        <div class="hero-notes">
          <span class="pill pill--danger">KyberSlash1: decapsulation / poly_tomsg</span>
          <span class="pill pill--danger">KyberSlash2: encapsulation / poly_compress</span>
          <span class="pill pill--safe">Patched before disclosure</span>
        </div>
      </div>
      <aside class="hero-side">
        <blockquote>
          <p>${QUOTE}</p>
          <footer>1 Corinthians 10:31</footer>
        </blockquote>
        <div class="fact-grid">
          <article><span>Platform</span><strong>Raspberry Pi 2, Cortex-A7</strong></article>
          <article><span>Embedded target</span><strong>ARM Cortex-M4</strong></article>
          <article><span>Fast attack</span><strong>Minutes for KyberSlash2</strong></article>
          <article><span>Slower attack</span><strong>Hours for KyberSlash1</strong></article>
        </div>
      </aside>
    </section>`;
}

function renderSmokingGun(): string {
  const code = state.codeMode === 'vulnerable' ? VULNERABLE_CODE : PATCHED_CODE;
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
    <section class="panel">
      <div class="section-heading">
        <p class="kicker">Exhibit 1</p>
        <h2>The vulnerable line of code</h2>
      </div>
      <div class="toggle-row">
        <button class="chip ${state.codeMode === 'vulnerable' ? 'is-active' : ''}" data-action="code-vulnerable">Vulnerable reference C</button>
        <button class="chip ${state.codeMode === 'patched' ? 'is-active' : ''}" data-action="code-patched">Patched Barrett reduction</button>
      </div>
      <div class="code-card ${state.codeMode === 'vulnerable' ? 'is-danger' : 'is-safe'}">
        <pre><code>${escapeHtml(code)}</code></pre>
      </div>
      <ul class="evidence-list">${annotations.map((item) => `<li>${item}</li>`).join('')}</ul>
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

  return `
    <section class="panel">
      <div class="section-heading">
        <p class="kicker">Exhibit 2</p>
        <h2>The oscilloscope</h2>
      </div>
      <div class="controls-row">
        <button class="control" data-action="next-measurement" ${state.measuring ? 'disabled' : ''}>Next measurement</button>
        <button class="control" data-action="run-hundred" ${state.measuring ? 'disabled' : ''}>Run 100 measurements</button>
        <button class="control ghost" data-action="toggle-distribution">${state.showDistribution ? 'Hide' : 'Show'} statistical distribution</button>
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
      ${
        state.showDistribution
          ? `<div class="distribution-card"><div class="histogram">${createHistogram()}</div><p class="distribution-caption">Red bars stay wide because secret-dependent division timing moves with the operand. Green bars collapse into a flat cluster because Barrett reduction keeps the path constant-time.</p></div>`
          : ''
      }
    </section>`;
}

function renderAttack(): string {
  const analysis = statisticalAnalysis(state.attackState.timingProfile);
  const displayedMode = state.attackMode === 'vulnerable' ? 'YES' : 'PATCHED';
  const progress = (state.attackState.queries / ATTACK_QUERY_BUDGET) * 100;
  const recoveredProgress = (state.attackState.recoveredBits / state.attackState.totalBits) * 100;
  const attackTrace = createPolyline(state.attackQueryTimes, state.attackMode === 'vulnerable' ? 'danger' : 'safe');

  return `
    <section class="panel">
      <div class="section-heading">
        <p class="kicker">Exhibit 3</p>
        <h2>Live attack progress</h2>
      </div>
      <div class="attack-summary">
        <div>
          <p class="mini-label">Attack variant</p>
          <strong>KyberSlash2, modeled against ML-KEM-768</strong>
          <p class="attack-subtitle">This browser demo uses a deterministic timing model rather than real JavaScript timing. It mirrors the paper's leakage dynamics without pretending to measure actual CPU cycles in the browser.</p>
        </div>
        <div class="attack-mode-toggle">
          <button class="chip ${state.attackMode === 'vulnerable' ? 'is-active' : ''}" data-action="mode-vulnerable">Vulnerable path</button>
          <button class="chip ${state.attackMode === 'patched' ? 'is-active' : ''}" data-action="mode-patched">Patched path</button>
        </div>
      </div>
      <div class="attack-layout">
        <div class="attack-card">
          <p class="attack-line"><span>Target:</span><strong>ML-KEM-768 secret key, 768 coefficients</strong></p>
          <p class="attack-line"><span>Implementation:</span><strong>${displayedMode}</strong></p>
          <p class="attack-line"><span>Target platform:</span><strong>Simulated Raspberry Pi 2 / Cortex-A7</strong></p>
          <div class="meter-block">
            <label>Queries sent</label>
            <div class="meter"><span style="width:${progress}%"></span></div>
            <small>${formatInteger(state.attackState.queries)} / ${formatInteger(ATTACK_QUERY_BUDGET)}</small>
          </div>
          <div class="meter-block">
            <label>Bits recovered</label>
            <div class="meter meter--gold"><span style="width:${recoveredProgress}%"></span></div>
            <small>${formatInteger(state.attackState.recoveredBits)} / ${formatInteger(state.attackState.totalBits)}</small>
          </div>
          <div class="meter-block">
            <label>Simulated elapsed time</label>
            <div class="meter meter--cyan"><span style="width:${progress}%"></span></div>
            <small>${formatDecimal(state.attackState.queries / 1500, 1)} minutes</small>
          </div>
          <div class="controls-row">
            <button class="control" data-action="launch-attack" ${state.attackRunning ? 'disabled' : ''}>Launch KyberSlash attack</button>
            <button class="control ghost" data-action="stop-attack" ${state.attackRunning ? '' : 'disabled'}>Stop</button>
            <button class="control ghost" data-action="export-samples">Export timing samples</button>
          </div>
          <div class="controls-row compact">
            <button class="control subtle" data-action="switch-implementation">Switch to ${state.attackMode === 'vulnerable' ? 'patched' : 'vulnerable'} implementation</button>
          </div>
        </div>
        <div class="attack-card attack-card--secondary">
          ${attackTrace}
          <div class="analysis-box">
            <p>Timing correlation test</p>
            <strong>${analysis.distinguishable ? 'Signal present' : 'Noise floor only'}</strong>
            <span>confidence = ${formatDecimal(analysis.confidenceLevel, 3)}</span>
            <span>estimated queries needed = ${formatInteger(analysis.estimatedQueriesNeeded)}</span>
          </div>
          <div class="recent-events">
            <p>Recent recoveries</p>
            ${
              state.attackMode === 'patched'
                ? `<ul><li>Correlation collapses to the measurement noise floor.</li><li>No coefficient advances because the distribution stays statistically flat.</li></ul>`
                : `<ul>${state.attackEvents
                    .map(
                      (event) => `<li>Coefficient ${event.coefficient}: +${formatDecimal(event.confidence, 2)} confidence -> value = ${event.value}</li>`,
                    )
                    .join('')}</ul>`
            }
          </div>
        </div>
      </div>
    </section>`;
}

function renderTimeline(): string {
  return `
    <section class="panel">
      <div class="section-heading">
        <p class="kicker">Exhibit 4</p>
        <h2>The disclosure timeline</h2>
      </div>
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
    <section class="panel">
      <div class="section-heading">
        <p class="kicker">Exhibit 5</p>
        <h2>What this means for PQ deployment</h2>
      </div>
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
        <h3>Cross-links in the suite</h3>
        <ul>${CROSSLINKS.map((item) => `<li>${item}</li>`).join('')}</ul>
      </div>
    </section>`;
}

function render(): void {
  const summary = measurementSummary(state.vulnerableSamples);
  const patchedSummary = measurementSummary(state.patchedSamples);

  app.innerHTML = `
    <main class="lab-shell">
      <header class="topbar">
        <div>
          <p class="topbar-label">Educational side-channel lab</p>
          <strong>ML-KEM-768 / Kyber768 parameters: n=${KYBER_PARAMS.n}, k=${KYBER_PARAMS.k}, q=${KYBER_PARAMS.q}, eta1=${KYBER_PARAMS.eta1}, eta2=${KYBER_PARAMS.eta2}, du=${KYBER_PARAMS.du}, dv=${KYBER_PARAMS.dv}</strong>
        </div>
        <button class="theme-toggle" data-action="toggle-theme">Theme: ${state.theme}</button>
      </header>
      ${renderHero()}
      <section class="status-strip">
        <article><span>Reference risk</span><strong>division on secret data</strong></article>
        <article><span>Current vulnerable mean</span><strong>${formatInteger(summary.value)} cycles</strong></article>
        <article><span>Current patched mean</span><strong>${formatInteger(patchedSummary.value)} cycles</strong></article>
        <article><span>Deployment lesson</span><strong>standardization is not safety</strong></article>
      </section>
      ${renderSmokingGun()}
      ${renderOscilloscope()}
      ${renderAttack()}
      ${renderTimeline()}
      ${renderLessons()}
      <footer class="footer-note">
        <p>JavaScript cannot measure the real timing of CPU division instructions reliably. This demo therefore uses a deterministic leakage model aligned with the published KyberSlash paper rather than browser timing APIs.</p>
      </footer>
    </main>`;
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
    case 'toggle-theme':
      setTheme(state.theme === 'dark' ? 'light' : 'dark');
      render();
      break;
    case 'code-vulnerable':
      state.codeMode = 'vulnerable';
      render();
      break;
    case 'code-patched':
      state.codeMode = 'patched';
      render();
      break;
    case 'next-measurement':
      void runMeasurementBatch(1);
      break;
    case 'run-hundred':
      void runMeasurementBatch(100);
      break;
    case 'toggle-distribution':
      state.showDistribution = !state.showDistribution;
      render();
      break;
    case 'mode-vulnerable':
      resetAttack('vulnerable');
      render();
      break;
    case 'mode-patched':
      resetAttack('patched');
      render();
      break;
    case 'launch-attack':
      void startAttack();
      break;
    case 'stop-attack':
      state.attackStopRequested = true;
      render();
      break;
    case 'export-samples':
      exportSamples();
      break;
    case 'switch-implementation':
      resetAttack(state.attackMode === 'vulnerable' ? 'patched' : 'vulnerable');
      render();
      break;
    default:
      break;
  }
});

for (let index = 0; index < 6; index += 1) {
  recordMeasurement();
}

render();
