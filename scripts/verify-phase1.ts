import { aggregateTimings, simulatedDecapsulationTime, simulatedDivCycles } from '../src/timing-model';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// The default target is the paper's Raspberry Pi 2 / Cortex-A7 build, where the
// division is a call to the `__divsi3` SOFTWARE routine (§5.1.1) and its cost is
// a STEP function of the numerator: flat until 3329, then +20 cycles, +2 more at
// 4096, +1 more at 8192. So the checks below are "flat inside a band, and a jump
// exactly at the paper's boundary" — not the monotone-with-magnitude assumption
// an earlier hardware-udiv model used.
const tiny = simulatedDivCycles(0, 3329, false);
const small = simulatedDivCycles(10, 3329, false);
const medium = simulatedDivCycles(1000, 3329, false);
const belowStep = simulatedDivCycles(3328, 3329, false);
const atStep = simulatedDivCycles(3329, 3329, false);

assert(
  tiny === small && small === medium && medium === belowStep,
  `expected a flat cost below the 3329 step, got ${tiny}/${small}/${medium}/${belowStep}`,
);
assert(
  atStep - belowStep === 20,
  `expected the paper's +20-cycle jump at numerator 3329, got ${atStep - belowStep}`,
);
assert(
  simulatedDivCycles(4096, 3329, false) - simulatedDivCycles(4095, 3329, false) === 2,
  'expected the paper\'s +2-cycle jump at numerator 4096',
);
assert(
  simulatedDivCycles(8192, 3329, false) - simulatedDivCycles(8191, 3329, false) === 1,
  'expected the paper\'s +1-cycle jump at numerator 8192',
);

const lowSignal = new Int16Array(256);
const highSignal = new Int16Array(256);
highSignal.fill(1664);

const lowTime = simulatedDecapsulationTime(lowSignal, true);
const highTime = simulatedDecapsulationTime(highSignal, true);

assert(lowTime !== highTime, 'expected different secret-dependent inputs to produce different times');

const stableMeasurements = Array.from({ length: 10000 }, () => simulatedDivCycles(1000, 3329, true));
const stableMean = aggregateTimings(stableMeasurements, 'mean');
const noiseless = simulatedDivCycles(1000, 3329, false);
const relativeError = Math.abs(stableMean.value - noiseless) / noiseless;

assert(relativeError <= 0.01, `expected aggregate mean within 1% of noiseless model, got ${relativeError}`);

console.log(
  JSON.stringify(
    {
      tiny,
      small,
      medium,
      belowStep,
      atStep,
      lowTime,
      highTime,
      stableMean,
      relativeError,
    },
    null,
    2,
  ),
);