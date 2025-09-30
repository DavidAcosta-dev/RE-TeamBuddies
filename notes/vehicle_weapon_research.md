# Vehicle & Weapon System Research Log

Last updated: 2025-09-28

## Current Knowledge Snapshot

### Vehicles

- **Acquisition flow:** Tutorial scripts confirm that stacking **8 crates** on a pad spawns a vehicle (tank in training mission). Crate automation reports show consistent callbacks through `crate_stateframe_cb_*` pairs; we need to trace where the spawn event pivots into vehicle construction.
- **Main EXEC state machine:** `phys_FUN_00008528` in `MAIN.EXE` polls controller masks at `gp-0x7e3x` every frame and advances three states: (0) idle, (1) confirm input, (2) spawn/reset. While in state 0 it debounces **left/right** (`0x2000/0x8000`) to cycle the crate slot via `FUN_000204e4`, and **square/cross** (`0x40/0x10`) to confirm; once confirmed it calls into the pickup scheduler stack and eventually re-enters state 0.
- **Spawn dispatch:** `phys_FUN_0001cba8` is the gateway that crate logic uses to advance the scheduler (it’s invoked with modes `3` and `5` from `phys_FUN_00008528`). The function jumps through a small dispatch table at `0x8001cba8`, so the actual spawn/cleanup routines live behind opaque pointers; we still need to resolve which entry performs the vehicle instantiation.
  - ✅ The five entries behind the `gp-0x3a14` jump table now map cleanly to concrete helpers:
      1. `stub_ret0_FUN_0001cc74` (index `1`, addr `0x8001cc74`) — sanity-checks the crate slot bounds via `FUN_00034508`; bails out early when indices fall outside the active roster.
      2. `FUN_0001cd1c` (index `2`, addr `0x8001cd1c`) — pulls the global crate manager (`_DAT_80053b50`) and kicks `FUN_00033a4c`, which appears to queue the pad HUD refresh.
      3. `FUN_0001cd54` (index `3`, addr `0x8001cd54`) — also rooted in the crate manager but funnels into `FUN_00033764`, the routine that stages spawn payload descriptors.
      4. `FUN_0001ce0c` (index `4`, addr `0x8001ce0c`) — iterates the `_DAT_80053b7c` ring, resets failure flags, and prepares the next free seat block before a spawn.
      5. `FUN_0001cfcc` (index `5`, addr `0x8001cfcc`) — the heavyweight state machine that actually mutates the pad actor (writes at `+0x57`, `+0xe6`, etc.) and issues the follow-up crate/UI calls. This is the likeliest entry where the vehicle object is constructed.
  - On fresh pads (`*(short *)(actor+0xe6) == 0` or slot pointer null), it primes the HUD bytes (`actor+0x57..0x5b`), enforces a resource throttle via `_DAT_80053b84 += 0x0A`, and only calls `FUN_00034a38` when the incoming crate descriptor advertises a vehicle payload (`(*(actor+0x28)[0] & 0xC0) == 0x40` with the second byte’s bit 0 set).
  - When seat data is already staged (`*(short *)(actor+0xe6) != 0`), it clamps the scan count to `min(actor+0x34, 6)` and walks the roster array at `actor+0x5d`, comparing each seat index to the payload bytes referenced by `actor+0x28`. The loop derives a capability mask from the seat descriptor (`*(actor+4)[(slot*5)+2] ? 0xFF : 0x01`) and, on a match, calls `FUN_000348a0(seatEntry, seatIndex, 1)` before exiting. A special-case path on `actor+0xe8 == 3` flips `actor+0x57` and jumps straight to `FUN_00034a38`, hinting at a “force spawn now” state, while the generic fallback blasts `actor+0x57..0x5b` with `1`s to mark the pad as armed for the next update tick. Direct disassembly of `SCES_019.23` shows both `FUN_000348a0` and `FUN_00034a38` are linker stubs (`nop` / `movt` sequences and long `nop` runs respectively); they don’t contain spawn logic in the base executable. That suggests the real constructor lives in an overlay (likely `GAME.BIN`) that patches these slots at runtime.
  - 📌 Follow-up: Walk the callees (`FUN_00033a4c`, `FUN_00033764`, `FUN_00032a20`, `FUN_00034fb8`, etc.) to isolate the exact spot that allocates the vehicle actor and to see whether any of them cross into `GAME.BIN` overlays. Reverse the overlay loader that populates addresses `0x800348a0`/`0x80034a38` (the current stubs) and trace their overlay equivalents—`FUN_00034fb8` appears to be a pointer table rather than executable code.
- **Seat selector shim:** `FUN_000204e4` subtracts from `actor+0xb4` each frame and compares against `-*(actor+0xb8)`; when the counter underflows or the user taps the matching input, it emits the `0x3200` audio cue and kicks the helper display routine `FUN_00035324`. This is the “scroll through crew slots” function the tutorial voiceover hints at.
- **Pad setup helpers:** `FUN_00021424` zeroes the 0x7c-linked structure (`+0x1c = 0x1000`, `+0x14 = 6`, clears velocity vectors). `FUN_0002230c` / `suspect_FUN_0002233c` allocate five work buffers (`actor+0xbc`..`actor+0xd8`) using the same allocator that backs weapon particles, and they toggle `actor+0xba`/`actor+0xe4` flags to mark the UI as “hot”.
- **Cooldown reset:** `FUN_00020654` clears the countdown words at `actor+0x20` and jumps into `suspect_FUN_00023390`, which tears down any retained handles, releases HUD widgets, and resets `actor+0xb9`. This appears to be the transition back to the neutral crate state after a spawn or timeout.
- **Handle lifecycle:** Vehicle handles reuse the same retain/release rules now enforced by `sys_retain` / `sys_release` (addresses 0x74950 / 0x74970). After the new `EnsureRetainReleaseFunctions` pre-script, all seat assignment call sites can be surfaced via bundle queries.
- **Actor fields:** `TbActorState` offsets `+0xF4` (handle) and `+0xF8` (follow target) track mounted vehicles or carried crates. Cooldowns at `+0xBE`, `+0xF0`, and `+0xFC` throttle reassignment; expect vehicle embark/exit logic to update the same timers.
- **Input linkage:** `button_to_action_map.md` labels action **12** as “kicking/entering vehicle.” Entry routines likely hang off the input hub candidates around `FUN_00023588`/`FUN_000235d4`; these also participate in crate pickup, so disentangling requires tracing pad masks.

### Weapons

- **Config data:** `TbActorState` offsets `0x16A–0x188` capture weapon type, cooldown, and per-weapon status counters (`electroCount`, `revConCount`, `specialCount`). These values mirror Wipeout’s `WeaponData` timers.
- **Resource lumps:** `bind_index_BUDDIES.DAT.csv` exposes weapon asset packs (e.g., `WEAPONS.BIN`, `10_BT_ALL_FLAME_WEAPONS.BIN`). `scripts/extract_bind.py` can dump them for schema inspection.
- **Tutorial flow:** Dialogue files (`buddies_script.json/.md`) outline crate-to-weapon build steps, weapon firing controls, and ammo counters—useful for designing Unity HUD equivalents.
- **Struct parallels:** `notes/wipeout_cross_reference.md` highlights the Wipeout `WeaponData` struct; durations like `ROCKET_DURATION (20*FR10)` should guide interpretation of TB timers once we identify the equivalent constants.

## Active Investigations

1. **Identify vehicle spawn routine**
   - Trace from crate scheduler callbacks (`FUN_000204e4`, `FUN_0002391c`) into any branch that writes to vehicle slots or calls `createVehicle` in mission scripts.
   - Use `bundle_GAME.BIN.jsonl` to locate functions referencing the tutorial string hashes (`"THIS IS A TANK"`, `_CPROTOTYPE VEHICLE FOUND`).
   - ✅ Located the pad interaction state machine (`phys_FUN_00008528`) and its helpers inside `MAIN.EXE`; still need the downstream call that instantiates the actual vehicle actor (likely hiding in `GAME.BIN`).
      - New clue: the state machine funnels through `phys_FUN_0001cba8` with command IDs `3` and `5` before handing control to an indirect call table. Those targets aren’t resolved yet—next step is to decode the jump table entries to find the actual vehicle constructor.
      - Latest sweep over `bundle_GAME.BIN.jsonl` (searching for `0x2000`, `0x3200`, `0xfa1`, and candidate function names) returned lots of controller/physics code but no obvious vehicle spawner, suggesting we may need to follow the `phys_FUN_0001cba8` jump table or symbol map instead of string matching.

2. **Seat assignment & input handling**
   - Inspect the high-scoring input candidates (especially `FUN_00023588`/`FUN_000235d4`) for writes to actor offsets associated with seating.
   - Map pad bitmasks to action constants using `exports/action_button_ids.json` to confirm the enter/exit flow.

3. **Weapon firing loop**
   - Search for functions touching `actor+0x180` (`weaponCooldown`) and neighbouring counters. Correlate with HUD updates (ammo counter strings) to isolate the fire/reload pipeline.
   - Compare timer increments against Wipeout macros (`FR10`, `FR40`) to recover original unit scaling.

4. **Asset schema extraction**
   - Run `scripts/extract_bind.py` on entries like `WEAPONS.BIN` to inspect table layouts (weapon ID, damage, ammo, firing cadence).
   - Document findings in a new section of this log for direct Unity import.

5. **Unity mapping**
   - Once timers and seat logic are validated, extend the Unity prototype design document with:
     - Vehicle prefab requirements (crew seats, turret behaviour, firing arcs).
     - Weapon ScriptableObject schema (type, cooldown, projectile prefab, ammo capacity, UI strings).

## Next Deliverables

- [ ] Callgraph summary linking crate callbacks → vehicle spawner.
- [ ] Disassembly snippets showing writes to `weaponCooldown` and counter fields.
- [ ] Extracted weapon configuration table annotated with tentative column names.
- [ ] Updated `mechanics_dossier.md` reflecting vehicle embark/exit rules and weapon metrics.

_Keep this log synchronized with `mechanics_dossier.md` as we lock down additional metrics._
