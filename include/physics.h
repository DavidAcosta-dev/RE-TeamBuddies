#ifndef TB_PHYSICS_H
#define TB_PHYSICS_H

#include "../datatypes/tb_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    // Forward declarations -------------------------------------------------------

    typedef struct TbPhysicsWorld TbPhysicsWorld; // opaque world accumulator

    typedef struct TbPhysicsIntegratorConfig
    {
        int32_t gravity_q12;       // default: TB_Q12(-24.0f) pulled from FUN_000029f8 traces
        uint16_t drag_shift;       // default: 1 (velocity >>= 1 after impact)
        uint16_t pad_drag;         // align to 32-bit for consistent PSX ABI mirroring
        int32_t track_magnet_q12;  // matches Wipeout TRACK_MAGNET (pull-to-track strength)
        int32_t resistance_q12;    // baseline drag (ShipData.resistance analogue)
        int32_t skid_friction_q12; // side-slip dampening (ShipData.skid analogue)
    } TbPhysicsIntegratorConfig;

    // Public API ----------------------------------------------------------------

    // Retrieve the singleton integration config used by the in-game update loop.
    // During RE we treat this as mutable to experiment with values in scripted tests.
    // @addr 0x000027f0 (FUN_000027f0 + relocation) -- preliminary catalog entry.
    TbPhysicsIntegratorConfig *tbPhysicsGetConfig(void);

    // Integrate a single physics body for dt frames (dt >= 1). Applies gravity
    // and velocity integration in Q12, mirroring: pos += vel >> 0xC.
    // @addr 0x000029f8 (FUN_000029f8) -- verified via integrator detector.
    void tbPhysicsIntegrateBody(TbPhysicsState *body, int32_t dt_frames);

    // Write a new velocity vector (already in Q12). Useful for gameplay systems
    // such as AI or crate throwing routines before handing back to the scheduler.
    void tbPhysicsSetVelocity(TbPhysicsState *body, const TbVec3Q12 *velocity);

    // Sample the shared sin/cos lookup tables (rooted ~0x26800/0x27800 in ROM).
    // The angle is masked by 0x0FFF internally to match the hardware-friendly layout.
    // @addr 0x00021C64 (FUN_00021c64) -- orientation helper used by camera + AI.
    TbVec3Q12 tbPhysicsOrientationToForward(TbAngleQ12 yaw, TbAngleQ12 pitch);

    // Update an entity's yaw/pitch from stick input. Returns clamped angles and
    // populates an optional forward vector when requested.
    void tbPhysicsApplyInputAngles(TbPhysicsState *body,
                                   int16_t stick_dx,
                                   int16_t stick_dy,
                                   TbVec3Q12 *out_forward_opt);

    // World management ----------------------------------------------------------

    // Attach a physics body to the global world list used by AI / collision.
    void tbPhysicsWorldAttachBody(TbPhysicsWorld *world, TbPhysicsState *body);

    // Detach a physics body (e.g. when despawning entities or entering cutscenes).
    void tbPhysicsWorldDetachBody(TbPhysicsWorld *world, TbPhysicsState *body);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // TB_PHYSICS_H
