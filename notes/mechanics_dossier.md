# Team Buddies Gameplay Mechanics Dossier

## Purpose

This document captures code-agnostic system behaviour and gameplay metrics extracted from the reverse engineering effort. It is intended to drive a modern Unity 6.2 prototype by supplying the *what* (rules, timings, magnitudes) while leaving the *how* to Unity-native implementation.

---

## Simulation cadence and numeric conventions

- **Tick rate:** 30 Hz fixed update (derived from Q12 integrator cadence).
- **Fixed-point math:** Positions, velocities, and angles use Q12 format (value << 12). Integration steps frequently shift right by 6 when accumulating (\(>> 6\)), matching PSX accumulator scaling.
- **Angle mask:** Angular values are wrapped with `0x0FFF` to maintain 12-bit resolution.
- **Saturation constants:** Orientation reset/initialization routines clamp certain fields to 0x80 to enforce bounds; treat these as tunables for Unity-side normalisation.

### Q12 helper summary

| Routine (RE name) | Behaviour | Unity analogue |
| --- | --- | --- |
| `phys_integrate_pos_z_step[1-5]` | Sequential Q12 integrator stages updating actor positions, applying angle masks between stages | Custom FixedUpdate integrator maintaining Q12 storage but exposing floats |
| `q12_vec3_normalize*` (MAIN.EXE) | Length, normalisation, and safe normalisation helpers | Utility static methods operating on `Vector3` with optional double precision |

---

## Actor state model (TbActor approximation)

- **Key offsets (for reference only):**
  - `+0x42`: Flag word controlling battle-ready / reprojection state bit at `0x10`.
  - `+0x50`: Bitfield; bit `0x10` indicates an active reprojection state.
  - `+0xBC`, `+0xBE`: Timers used for follow-target blend phases (e.g., 0x19 tick windows).
  - `+0xF0`: Cooldown preventing immediate follow-target reassignment.
  - `+0xF4`: Handle/pointer to active reprojection controller.
  - `+0xF8`: Follow-target entity pointer.
  - `+0xFC`: Timestamp of the last follow-target activation.
  - `+0x1A8` block: Cached vertex positions for reprojection height calculations.
  - `+0x264`: Cached world-space projection data.

Treat these as logical fields when shaping Unity components. For example, model `+0xF4`/`+0xF8` as strong references to `ReprojectionHandle` and `Actor` objects, respectively, and implement the retain/release behaviour as explicit lifecycle hooks.

---

## Reference management semantics

### Functions

- `sys_retain(handleOwner, handle)` increments a reference count or acquires ownership before storing.
- `sys_release(handleOwner, handle)` decrements/releases when a handle is replaced or cleared.

### Behavioural rules

1. Before writing a new handle pointer (e.g., `+0xF4`), release any existing handle via `sys_release`.
2. Retain the incoming handle via `sys_retain` before assignment.
3. These rules also apply to follow-target pointers (`+0xF8`).

### Unity translation

- Model handles as lightweight ScriptableObjects or C# classes with `Retain()`/`Release()` methods.
- Ensure `ActorComponent` wraps assignment through helper methods enforcing this contract.

---

## Follow-target system

### Core routines

- `phys_gte_reproject_set_follow_target` (0x42450)
- `phys_gte_reproject_follow_target_step` (0x42518)
- `phys_gte_reproject_full_on_match` (0x423FC)
- `phys_gte_reproject_update_follow_target_nearby` (0x26E4C)

### State flow

1. **Set target:** When a new target is requested, validate it, retain the handle (`+0xF4`), and store the target pointer (`+0xF8`). Stamp `+0xFC` with the current global tick.
2. **Step phase:** Each tick, if a follow-target is present, blend towards the target using Q12 integrators. Reset timer `+0xBE` to `0x19` when certain thresholds are met to schedule full reprojection.
3. **Full reprojection:** When the target handle matches the cached handle, perform a full GTE reprojection to refresh world-space caches and min Y values.
4. **Auto-update:** Nearby entity scans can auto-assign follow-targets when certain criteria (type == 6) and cooldown (`+0xF0`) permit.

### Timers and triggers

- `+0xBE` (ushort) counts down from `0x19`; when it reaches zero, enforce full reprojection.
- `+0xFC` holds last assignment tick to prevent thrashing.
- `+0xF0` acts as a cooldown preventing rapid auto-reassignment.

### Unity implementation notes

- Use a dedicated `FollowTargetController` MonoBehaviour handling timers in FixedUpdate.
- Represent timers in milliseconds (`duration = 0x19 / 30 ≈ 0.633s`).
- Convert Q12 vectors to floats for Unity physics, but maintain the same blend curve (e.g., multiply by `1/4096f`).
- Replace GTE reprojection with Unity transforms / Cinemachine updates while preserving cadence (step vs full refresh).

---

## Crate system (logic only)

> Detailed damage/weapon payload logic still pending – this section captures current understanding of crate ownership and targeting mechanics.

1. **Crate acquisition:** When an actor interacts with a crate, the system invokes the follow-target setters to treat the crate as the new target/handle.
2. **Reference lifecycle:** The crate handle must be retained on pickup and released on drop/destroy.
3. **State reset:** Crate cleanup routines call the full reprojection cleanup functions (`phys_gte_reproject_cleanup`, `phys_gte_reproject_cleanup_scene`) to clear cached world-space data and drop handles.
4. **Auto targeting:** Nearby crate scan (`phys_gte_reproject_update_follow_target_nearby`) periodically searches for eligible crates and assigns them if no current target is present and cooldown permits.

### Outstanding questions

- Crate content selection and reward distribution are still under investigation (weapon tiers, health packs, etc.).
- Interaction with battle phases and team ownership remains to be mapped.

---

## Combat metrics (partial)

- **Health pools:** TBD – need to mine from damage application routines.
- **Damage application:** Functions not yet conclusively identified; expect operands to use Q12 scaling plus resistances.
- **Battle timers:** Offsets around `+0xBC/+0xBE` used for follow-target also likely inform battle phase transitions.

Plan to update this section once damage-system functions are labeled and verified.

---

## Movement metrics

| Metric | Source | Notes |
| --- | --- | --- |
| Position integration steps | `phys_integrate_pos_z_step*` | Each stage corresponds to partial velocity/position updates; maintain step ordering in Unity. |
| Orientation update | `phys_FUN_00040a4c`, `phys_FUN_00040a98` | Handles per-axis angle accumulation with Q12 shifts and saturations; apply when actor turns or resets. |
| Basis recompute | `phys_FUN_000475dc`, `phys_FUN_00048150`, `phys_recompute_basis` | Rebuilds orientation matrix after angle changes; necessary before camera or projectile spawn alignment. |

---

## Unity prototype translation checklist

- **Fixed update loop** replicating 30 Hz logic with Q12 conversions.
- **Actor component** wrapping:

  - Follow-target references.
  - Timers/cooldowns.
  - Orientation & position integrators.

- **Crate component** implementing retain/release and cleanup hooks.
- **Reprojection substitute** using Unity transforms/Cinemachine, triggered by the same timers and thresholds.
- **Debug HUD** exposing key fields (`followTarget`, `handle`, timers, state flags) for parity validation.
- **Metrics ingestion** pipeline to sync new findings from `exports/rename_review.csv` into ScriptableObject data tables.

---

## Open research threads

- Map weapon/health/crate reward logic (pending function identification).
- Confirm AI decision routines; currently only low-level follow-target behaviour is mapped.
- Verify trig LUT helpers at `0x1C7FC/0x1C83C` before porting exact aim/basis curves.
- Decode resource archives (`BUDDIES.DAT`, etc.) for authentic level setup once gameplay parity is established.

---

## Usage notes

- Treat this dossier as a living document. Update sections as new addresses are confirmed or metrics refined.
- When implementing in Unity, prefer ScriptableObject-driven configuration so updates from reverse engineering can be applied without code churn.
