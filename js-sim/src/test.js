import { simulateNFrames } from './index.js';

// Tiny smoke test to validate the scaffold runs
const out = simulateNFrames(3, () => ({ ax: 0.5, ay: 0 }), { accelScale: 1 });
console.log('frames', out.length);
console.log('last', out[out.length - 1]);
