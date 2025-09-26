# Mechanics Mapping Scoreboard

## Overview

- Total unique functions scanned: 2257
- Subsystem tagging (function counts):
  - cdstream: 125
  - crate: 166
  - gravity: 9
  - input: 69
  - naming_suggestions: 211
  - orientation: 13
  - pickup_drop: 162
  - vertical_consumer: 329
  - vertical_core: 27

## Subsystem completion

| Subsystem | Completion | Notes |
|---|---:|---|
| Crate system | 87.0% | State machine and edges mapped; timings pending |
| Orientation | 10.9% | 3 integrator∩orientation, basis chain surfaced |
| Physics integrators | — | 6/12 mapped (direct pos writers) |
| Q12-heavy pool | — | total: 12, ∩: 3, integ-only: 9, orient-only: 3 |

## Priority targets

- Tag/rename the 3 integrator ∩ orientation functions and confirm TbActorState prefix reads/writes.
- Wire integrator config (gravity/drag/track magnet) into validated callsites.
- Finish crate timings and enumerate pickup/drop candidates.
