# Unity Prototype Scaffold (Physics & Orientation)

Early fidelity layer mirroring reverse engineered integrator & direction hashing.

## Components

- `FixedPoint.cs`: Q12 helpers (shift 12) matching native >> 0xC.
- `CrateThrowPhysics.cs`: Implements pos -= (vel * scalar >> 12) pattern for X/Z; placeholder Y + gravity.
- `DirectionTable.cs`: Generates a 4096-entry (cos,sin) table approximating the native trig table indexed by `(angleHash & 0xFFF)`.

## Usage

1. Create a new Unity project (URP or 3D core). Copy `unity_proto/Scripts` into `Assets/Scripts`.
2. In Unity, create a GameObject `Crate` and add `CrateThrowPhysics`.
3. (Optional) Create `DirectionTable` asset via Create > TeamBuddies > DirectionTable (auto-generates on first query).
4. Call `SeedThrow(worldVelocity)` from a test harness or editor script to simulate throw.

## Matching Native Behavior

| Native Pattern | Unity Implementation | Notes |
|----------------|---------------------|-------|
| velX * iVar10 >> 0xC subtraction from posX | `posX -= Mul(velX, frameScalar);` | Confirmed integrator in phys_FUN_000406ac |
| Angle hashing via FUN_00022e5c & 0xFFF | `DirectionTable.GetDir(hash)` | Real table to override once dumped |
| Gravity (unknown constant) | `gravityPerFrame` placeholder | Update after Y offset & decrement found |

## Next Steps

- Add real Y velocity offset once identified in binary.
- Replace generated trig table with dumped short pairs for perfect parity.
- Integrate state machine events to seed velocities on `crate_throw_start`.

## Instrumentation Idea

Add logging: each frame record (frame, posX,posZ,velX,velZ,frameScalar) to verify curve shape against original traces when available.
