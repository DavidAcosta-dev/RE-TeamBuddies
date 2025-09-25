// Core primitives derived strictly from RE findings (addresses as references)
// We only model behavior we have evidence for in the exports/suspects_bookmarks.json

// Minimal vector math placeholder until more precise ops are identified
export function vec2(x = 0, y = 0) {
  return { x, y };
}

export function add(a, b) { return { x: a.x + b.x, y: a.y + b.y }; }
export function sub(a, b) { return { x: a.x - b.x, y: a.y - b.y }; }
export function scale(v, s) { return { x: v.x * s, y: v.y * s }; }

// Time step fixed at 1/60 until we identify exact tick from MAIN loop
// Default dt comes from config so we can align with findings later
import { CONFIG } from './config.js';
export const DT = CONFIG.dt;

// Physics integration hint: based on clustered physics suspects around MAIN.EXE:
//  - phys_FUN_00014f80 (0x00014f80)
//  - phys_FUN_0001f340 (0x0001f340)
//  - phys_FUN_00021c64 (0x00021c64)
// These likely participate in per-frame kinematics update. We'll start with semi-implicit Euler
// as a placeholder and refine once decomp yields exact formulas.
export function integrateSemiImplicitEuler(pos, vel, acc) {
  // new velocity first, then position with new velocity
  const v = add(vel, scale(acc, DT));
  const p = add(pos, scale(v, DT));
  return { p, v };
}

// Controller mapping hint: controller tokens clustered in GAME.BIN suggest signed input in [-1,1]
// This function is a placeholder interface; real mapping will use PSYQ pad bits once we confirm.
export function controllerInputToAccel(input, accelScale = 1.0) {
  // input: { ax: float, ay: float } inferred from analog-like mapping
  return vec2(input.ax * accelScale, input.ay * accelScale);
}

// Entity with minimal state we have confidence exists: position, velocity
export class Entity {
  constructor() {
    this.pos = vec2(0, 0);
    this.vel = vec2(0, 0);
  }
}

// Candidate main loop slice: apply controller to acceleration, integrate
export function stepEntity(entity, input, params = {}) {
  const accelScale = params.accelScale ?? 1.0;
  const acc = controllerInputToAccel(input, accelScale);
  if (CONFIG.enableSimpleIntegration) {
    const integ = integrateSemiImplicitEuler(entity.pos, entity.vel, acc);
    entity.pos = integ.p;
    entity.vel = integ.v;
  }
}
