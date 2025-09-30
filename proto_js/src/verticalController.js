// VerticalController models the reverse-engineered vertical progression system
// Fields (native offsets in comments):
//  progress       (0x5c) accumulates by step each tick
//  progressPrev   (0x5e) snapshot on phase rollover
//  step           (0x60) per-tick increment (velocity)
//  scale          (0x62) multiplier involved in scaled emission ((step * scale) >> 1)
//  phaseToggleA   (0x3c) & phaseToggleB (0x40) XOR flipped to swap phase sets
//  phaseComplete  (0x30) set when progress crosses current bound once
//  phase base/extent pairs: (0x4c,0x50) and mirrored second pair assumed at (0x4c+8,0x50+8)
// Simplified: we track two phases with base=0 for first; second uses same for now until more data

export class VerticalController {
  constructor(mode = 3) {
    // Core shorts
    this.progress = 0;       // +0x5c
    this.progressPrev = 0;   // +0x5e
    this.step = 0;           // +0x60
    this.scale = 0xF0;       // +0x62 default from init

    // Phase & bounds
    this.phaseToggleA = 0;   // +0x3c
    this.phaseToggleB = 0;   // +0x40
    this.phaseComplete = 0;  // +0x30
    this.mode = mode;        // +0x44 analog

    // Bound pair A
    this.baseA = 0;          // +0x4c
    this.extentA = this._half(mode * 0x140); // mirrors +0x50 / +0x58 half amplitude
    // Bound pair B (unknown real values; placeholder mirror)
    this.baseB = 0;          // +0x54 (mirroring structure pattern)
    this.extentB = this.extentA; // +0x56

    // Derived step (mode * 0x10)/2 with signed half rounding
    this.step = this._half(mode * 0x10);
    this.scale = 0xF0; // constant until writer changes
  }

  _half(val) {
    // emulate (val >>1) with sign correction if negative and odd
    if (val < 0 && (val & 1)) return (val + 1) >> 1;
    return val >> 1;
  }

  tick(onEmit) {
    // Accumulate progress by step
    this.progress = (this.progress + this.step) & 0xffff; // keep 16-bit wrap
    // Signed comparison bound check
    const signedProgress = (this.progress << 16) >> 16;
    const bound = this._currentBase() + this._currentExtent();
    if (signedProgress >= bound) {
      // Emit scaled value analogous to FUN_0002d220 call in writer
      const scaled = this._half(((this.step << 16) >> 16) * ((this.scale << 16) >> 16));
      if (onEmit) onEmit({scaled, step:this.step, scale:this.scale});
      // Phase rollover
      this.phaseComplete = 1;
      this.progressPrev = this.progress;
      // Reset progress to phase base (native sets from struct fetch) – simplified to base
      this.progress = this._currentBase() & 0xffff;
      // Flip toggles (XOR 1 semantics observed)
      this.phaseToggleA ^= 1;
      this.phaseToggleB ^= 1;
    }
  }

  _currentBase() {
    return (this.phaseToggleB & 1) ? this.baseB : this.baseA;
  }
  _currentExtent() {
    return (this.phaseToggleB & 1) ? this.extentB : this.extentA;
  }

  sampleEmitterY(baseY) {
    // Current guess: emitter gate uses step (index0x30) for gating, but height likely progress.
    // Provide both for debugging.
    const signedProgress = (this.progress << 16) >> 16;
    return {y: baseY + signedProgress, gate: (this.step << 16) >> 16};
  }
}

// Simple harness if executed standalone (node):
if (typeof module !== 'undefined' && require.main === module) {
  const vc = new VerticalController(3);
  for (let i=0;i<40;i++) {
    vc.tick(ev => console.log('Emit', i, ev));
    if (i % 5 === 0) {
      const s = vc.sampleEmitterY(1000);
      console.log('Frame', i, 'Y', s.y, 'Gate', s.gate, 'phase', vc.phaseToggleB);
    }
  }
}
