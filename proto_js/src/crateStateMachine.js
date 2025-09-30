// Crate State Machine Prototype
// Mirrors reverse engineered tri-slot model (+0x38 base, +0x3c pickup, +0x40 throw)
// Polarity field emulated as polarity (0x1000 neutral, 0xfffff000 throw)

export const POLARITY_NEUTRAL = 0x1000;
export const POLARITY_THROW = 0xfffff000;

export class CrateActor {
  constructor() {
    // Emulate structure fields
    this.slotBase = null;   // +0x38
    this.slotPickup = null; // +0x3c
    this.slotThrow = null;  // +0x40

    this.field14 = 0; // +0x14
    this.field1c = 0; // +0x1c
    this.field20 = 0; // +0x20
    this.polarity = POLARITY_NEUTRAL; // +0x24

    this.globalCounter = 1; // mirrors -0x7dee seed

    // install states
    this.slotBase = new BaseState(this);
    this.slotPickup = new PickupState(this);
    this.slotThrow = new ThrowState(this);

    // start in base
    this.current = this.slotBase;
  }

  schedule(slot) {
    this.current = slot;
  }

  frame(inputMask) {
    // Emulate input hub decisions (subset: 0x40 pickup, 0x10 throw)
    if (inputMask & 0x40) {
      if (this.current === this.slotBase) {
        crate_pickup_start(this);
        this.schedule(this.slotPickup);
      }
    } else if (inputMask & 0x10) {
      if (this.current === this.slotPickup || this.current === this.slotBase) {
        crate_throw_start(this);
        this.schedule(this.slotThrow);
      }
    }
    // Paired callbacks conceptualized as primary/secondary phases
    this.current.onFramePrimary();
    this.current.onFrameSecondary();
  }
}

class BaseState {
  constructor(actor) { this.a = actor; }
  onEnter() {}
  onExit() {}
  onFramePrimary() {
    // idle/carry logic placeholder
  }
  onFrameSecondary() {
    // could advance animation or effects
    crate_anim_fx_step(this.a);
  }
}

class PickupState {
  constructor(actor) { this.a = actor; this.timer = 0; }
  onEnter() { this.timer = 0; }
  onExit() {}
  onFramePrimary() {
    this.timer++;
    // after a few frames, return to base unless throw already triggered
    if (this.timer > 20 && this.a.current === this.a.slotPickup) {
      this.a.schedule(this.a.slotBase);
    }
  }
  onFrameSecondary() {}
}

class ThrowState {
  constructor(actor) { this.a = actor; this.air = 0; }
  onEnter() { this.air = 0; }
  onExit() {}
  onFramePrimary() {
    this.air++;
    // simple flight duration then reset
    if (this.air > 15) {
      crate_state_reset_init(this.a);
      this.a.schedule(this.a.slotBase);
    }
  }
  onFrameSecondary() {}
}

// Functions modeled after reverse engineered writers
export function crate_pickup_start(a) {
  a.field14 = 6;
  a.field1c = POLARITY_NEUTRAL;
  a.field20 = 0;
  a.polarity = POLARITY_NEUTRAL;
}

export function crate_throw_start(a) {
  a.field1c = 0; // cleared
  a.field20 = 0;
  a.polarity = POLARITY_THROW;
  a.globalCounter += 1;
}

export function crate_state_reset_init(a) {
  a.polarity = POLARITY_NEUTRAL;
  a.field1c = POLARITY_NEUTRAL;
  a.field20 = 0;
  // Additional extended clears would happen here (+0x48..+0x50 in native)
}

export function crate_state_scheduler_enqueue(actor, slotObj) {
  // Conceptual stand-in for FUN_00035324: in native code this likely registers
  // the slot pointer & paired callbacks for the frame pump. Here we just switch.
  actor.schedule(slotObj);
}

export function crate_anim_fx_step(actor) {
  // Placeholder for FUN_00035cc0 side-effects (animation frames, visual FX, etc.)
  // Could be extended with a frame counter or debug log.
  return;
}
