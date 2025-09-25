# Gravity Neighborhood Extend

Integrators analyzed: 17

| Integrator | SpatialHits | VerticalHits | Shifts | Callees |
|------------|------------:|------------:|-------:|--------:|
| FUN_00006dd0 | 0 | 0 | 1 | 0 |
| FUN_0001ec7c | 0 | 3 | 1 | 0 |
| FUN_00023698 | 0 | 0 | 2 | 0 |
| FUN_00026c68 | 0 | 5 | 3 | 2 |
| FUN_00032c18 | 0 | 0 | 9 | 0 |
| FUN_00040a4c | 8 | 4 | 3 | 4 |
| FUN_00040a98 | 8 | 4 | 3 | 4 |
| FUN_000438fc | 0 | 10 | 2 | 2 |
| FUN_000443b8 | 0 | 4 | 1 | 1 |
| FUN_00044754 | 0 | 2 | 1 | 0 |
| FUN_00044a14 | 0 | 16 | 6 | 0 |
| FUN_00044f80 | 0 | 22 | 10 | 0 |
| FUN_00045a80 | 0 | 7 | 2 | 0 |
| FUN_00046024 | 0 | 12 | 3 | 1 |
| FUN_000475dc | 0 | 19 | 3 | 0 |
| FUN_00048150 | 0 | 9 | 4 | 2 |
| FUN_000489a8 | 0 | 9 | 4 | 3 |

## Callee Metrics (non-zero interesting ones)

| Integrator | Callee | CalleeSpatial | CalleeVertical | CalleeShifts |
|------------|--------|--------------:|--------------:|------------:|
| FUN_00026c68 | FUN_000402e0 | 0 | 4 | 0 |
| FUN_00040a4c | FUN_00022e5c | 0 | 6 | 3 |
| FUN_00040a4c | FUN_0004033c | 0 | 3 | 0 |
| FUN_00040a98 | FUN_00022e5c | 0 | 6 | 3 |
| FUN_00040a98 | FUN_0004033c | 0 | 3 | 0 |
| FUN_000438fc | FUN_0004033c | 0 | 3 | 0 |
| FUN_000443b8 | FUN_00023180 | 0 | 2 | 3 |
| FUN_00046024 | FUN_00023000 | 0 | 6 | 2 |
| FUN_00048150 | FUN_00023000 | 0 | 6 | 2 |
| FUN_00048150 | FUN_0004033c | 0 | 3 | 0 |
| FUN_000489a8 | FUN_00023488 | 0 | 2 | 0 |
| FUN_000489a8 | FUN_0004033c | 0 | 3 | 0 |

### Notes

Callees with spatial+shift or vertical+shift likely contain partial integration math split from core loop.
