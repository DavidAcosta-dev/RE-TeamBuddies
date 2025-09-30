// Entry point for early JS simulation strictly grounded in RE artifacts
import { Entity, stepEntity, vec2, DT } from './core.js';
import { bootstrapFromFindings } from './pipeline.js';

// Initialize pipeline from findings (aliases only for now)
const registered = bootstrapFromFindings();

function simulateNFrames(n, inputFn, params = {}) {
  const e = new Entity();
  const trace = [];
  for (let i = 0; i < n; i++) {
    const input = inputFn(i);
    stepEntity(e, input, params);
    trace.push({ i, t: (i + 1) * DT, pos: { ...e.pos }, vel: { ...e.vel } });
  }
  return trace;
}

// Basic demo: constant rightward accel
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(`registered phys placeholders: ${registered}`);
  const out = simulateNFrames(
    10,
    () => ({ ax: 1, ay: 0 }),
    { accelScale: 1.0 }
  );
  console.log(JSON.stringify(out, null, 2));
}

export { simulateNFrames };
