import { CrateActor, POLARITY_NEUTRAL, POLARITY_THROW } from './crateStateMachine.js';

function assert(cond, msg) { if (!cond) throw new Error('Assertion failed: ' + msg); }

// Test sequence: pickup then throw
const actor = new CrateActor();
assert(actor.polarity === POLARITY_NEUTRAL, 'initial polarity');

actor.frame(0x40); // pickup press
assert(actor.current.constructor.name === 'PickupState', 'pickup scheduled');
assert(actor.polarity === POLARITY_NEUTRAL, 'pickup polarity neutral');

// Advance some frames
for (let i = 0; i < 5; i++) actor.frame(0);

actor.frame(0x10); // throw press
assert(actor.current.constructor.name === 'ThrowState', 'throw scheduled');
assert(actor.polarity === POLARITY_THROW, 'throw polarity');

for (let i = 0; i < 20; i++) actor.frame(0); // let throw resolve
assert(actor.current.constructor.name === 'BaseState', 'returned to base after throw');
assert(actor.polarity === POLARITY_NEUTRAL, 'polarity reset');

console.log('All crate state tests passed.');
