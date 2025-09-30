import { CrateActor } from './crateStateMachine.js';

// Simple demo loop: simulate frames with timed input masks
const actor = new CrateActor();

// Scripted input sequence: pickup at frame 2, throw at frame 30
const inputs = [];
for (let i = 0; i < 60; i++) {
  let mask = 0;
  if (i === 2) mask |= 0x40;      // pickup
  if (i === 30) mask |= 0x10;     // throw
  inputs.push(mask);
}

for (let frame = 0; frame < inputs.length; frame++) {
  actor.frame(inputs[frame]);
  if (frame % 5 === 0) {
    console.log(`f${frame} state=${actor.current.constructor.name} polarity=0x${actor.polarity.toString(16)} counter=${actor.globalCounter}`);
  }
}

console.log('Done.');
