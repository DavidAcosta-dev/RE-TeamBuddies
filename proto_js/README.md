# Team Buddies Crate State Prototype (JS)

Prototype of reverse engineered crate state machine derived from MAIN.EXE analysis.

## Features

- Tri-slot model: base (+0x38), pickup (+0x3c), throw (+0x40)
- Input mask mapping: 0x40 -> pickup; 0x10 -> throw
- Polarity field emulation (0x1000 neutral, 0xfffff000 throw)
- Basic lifecycle test script

## Run Demo

```bash
npm install   # (no deps, creates lockfile)
npm start     # runs demo showing state progression
```

## Run Tests

```bash
npm test
```

## Next Steps

- Integrate timing/animation once FUN_00035cc0 semantics clarified.
- Flesh out BaseState internal logic after identifying native +0x38 function body.
- Add logging hooks mirroring scheduler callback pair separation.
