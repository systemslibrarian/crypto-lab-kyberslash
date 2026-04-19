import { aggregateTimings, simulatedDecapsulationTime, simulatedDivCycles } from '../src/timing-model';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const tiny = simulatedDivCycles(0, 3329, false);
const small = simulatedDivCycles(10, 3329, false);
const medium = simulatedDivCycles(1000, 3329, false);

assert(tiny >= 6.9 && tiny <= 7.6, `expected near-7 cycles for zero dividend, got ${tiny}`);
assert(medium > small, `expected 1000/3329 to cost more cycles than 10/3329: ${medium} <= ${small}`);

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
      lowTime,
      highTime,
      stableMean,
      relativeError,
    },
    null,
    2,
  ),
);