import { Entity, stepEntity } from '../src/core.js';
import { CONFIG } from '../src/config.js';

const cv = document.getElementById('cv');
const ctx = cv.getContext('2d');

// Simple keyboard state
const keys = new Set();
window.addEventListener('keydown', (e) => keys.add(e.key.toLowerCase()));
window.addEventListener('keyup', (e) => keys.delete(e.key.toLowerCase()));

function inputFromKeys() {
  let ax = 0, ay = 0;
  if (keys.has('arrowleft') || keys.has('a')) ax -= 1;
  if (keys.has('arrowright') || keys.has('d')) ax += 1;
  if (keys.has('arrowup') || keys.has('w')) ay -= 1;
  if (keys.has('arrowdown') || keys.has('s')) ay += 1;
  return { ax, ay };
}

const e = new Entity();
const params = { accelScale: 60 }; // placeholder scale for visible motion at 60 FPS

function draw() {
  ctx.clearRect(0, 0, cv.width, cv.height);
  ctx.fillStyle = '#42e6a4';
  ctx.fillRect(Math.round(160 + e.pos.x), Math.round(120 + e.pos.y), 4, 4);
}

let acc = 0;
function loop(ts) {
  // Fixed-step accumulator for stable sim
  acc += (1 / 60);
  while (acc >= CONFIG.dt) {
    const input = inputFromKeys();
    stepEntity(e, input, params);
    acc -= CONFIG.dt;
  }
  draw();
  requestAnimationFrame(loop);
}

requestAnimationFrame(loop);
