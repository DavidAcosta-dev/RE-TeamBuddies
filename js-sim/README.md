# TB reverse-engineering JS simulation (grounded)

Scope

- This directory contains a minimal JavaScript scaffold to mirror game logic strictly from confirmed RE findings.
- All function identities are derived from exports/suspects_bookmarks.json (addresses, names, scores).
- Behavior is placeholder-only until we translate exact formulas from decomp; stubs are clearly marked.

How this is grounded

- js-sim/findings.json is generated from exported bookmarks and lists top physics suspects per binary.
- The runtime builds a pipeline from these aliases (e.g., phys_FUN_00014f80) but does not invent behavior.
- Optional simple integration can be toggled to sanity-check the harness; turn off when validating exactness.

Usage

1) Regenerate findings from the latest bookmarks
   npm run findings

2) Run a tiny smoke test (uses optional simple integration)
   npm test

3) Run the demo simulation
   npm start

Notes

- dt (tick) is configurable (src/config.js). The default 1/60 is a placeholder until corroborated by RE.
- As decomp for target functions lands, replace stubs in src/pipeline.js or add precise functions in src/core.js.
