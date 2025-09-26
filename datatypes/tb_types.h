#ifndef TB_TYPES_H
#define TB_TYPES_H

#include <stdint.h>
#include "tb_flags.h"

// Fixed-point helper macros -------------------------------------------------
// All physics math in Team Buddies uses Q12 fixed-point (>> 0xC shifts).
// Use TB_Q12(x) to convert floating point literals at compile time if desired.
#define TB_Q12_SHIFT 12
#define TB_Q12_ONE (1 << TB_Q12_SHIFT)
#define TB_Q12(x) ((int32_t)((x) * (float)TB_Q12_ONE + ((x) >= 0 ? 0.5f : -0.5f)))
// Common Q12 ops used by integrators/orientation
#define TB_Q12_MUL(a, b) ((int32_t)(((int64_t)(int32_t)(a) * (int64_t)(int32_t)(b)) >> TB_Q12_SHIFT))
#define TB_Q12_TO_INT(a) ((int32_t)(a) >> TB_Q12_SHIFT)
#define TB_INT_TO_Q12(a) ((int32_t)(a) << TB_Q12_SHIFT)

// Position integration step uses >> 6 (Q6 scale for velocity contribution)
#define TB_POS_INTEGRATE_SHIFT 6
#define TB_POS_INTEGRATE_STEP(pos_q12, vel_q12) ((int32_t)(pos_q12) + ((int32_t)(vel_q12) >> TB_POS_INTEGRATE_SHIFT))

// Core math primitives ------------------------------------------------------

typedef struct TbVec3Q12
{
    int32_t x; // world offset +0x08
    int32_t y; // world offset +0x0C
    int32_t z; // world offset +0x10
} TbVec3Q12;

// Orientation tables index with angle & 0xFFF, stride 4 bytes (analysis circa 0x26800).
#define TB_ANGLE_MASK 0x0FFF
typedef uint16_t TbAngleQ12; // same mask semantics as sin/cos table consumers

// Physics state -------------------------------------------------------------

// NOTE: The following "TbPhysicsState" was an early hypothesis and is retained
// to avoid breaking includes. Prefer using TbActorPrefix (below), which maps
// verified offsets in the 0x00–0x127 region. This struct may be removed once
// all references migrate to TbActorPrefix.
typedef struct TbPhysicsState
{
    TbVec3Q12 position; // +0x08 .. +0x13
    int16_t unk_0x14;
    int16_t unk_0x16;
    TbVec3Q12 velocity; // legacy guess; DO NOT RELY (basis occupies 0x34..0x40)
    TbAngleQ12 yaw;     // +0x20
    TbAngleQ12 pitch;   // +0x22
    TbAngleQ12 roll;    // +0x24
    uint16_t flags;     // +0x26 (TbActorFlags mask)
} TbPhysicsState;

// Actor state prefix (0x00–0x127) -----------------------------------------
// Structured mapping for fields accessed by integrator/orientation chains.
// All offsets are relative to the start of the actor struct as used in GAME.BIN.
typedef struct TbActorPrefix
{
    uint8_t _pad00[0x08];         // 0x00..0x07: unknown
    TbVec3Q12 position;           // 0x08..0x13: world position (Q12)
    uint8_t _pad14[0x0C];         // 0x14..0x1F: unknown
    TbAngleQ12 yaw;               // 0x20
    TbAngleQ12 pitch;             // 0x22
    TbAngleQ12 roll;              // 0x24
    uint16_t flags;               // 0x26: collision/state flags (TbActorFlags; see exports/actor_flags_usage.md)
    uint8_t _pad28[0x0C];         // 0x28..0x33: unknown
    int16_t basis_fwd_x;          // 0x34: normalized forward.x (SVECTOR/Q12)
    int16_t basis_fwd_y;          // 0x36: normalized forward.y
    int16_t basis_fwd_z;          // 0x38: normalized forward.z
    int16_t basis_len;            // 0x3A: forward length (pre/post norm) [hyp]
    int16_t basis_src_x;          // 0x3C: source basis.x (pre-normalization)
    int16_t basis_src_y;          // 0x3E: source basis.y
    int16_t basis_src_z;          // 0x40: source basis.z
    int16_t speed_q12;            // 0x44: speed magnitude (Q12)
    uint8_t _pad46[0x128 - 0x46]; // 0x46..0x127: unknown tail to config block
} TbActorPrefix;

// Actor configuration tail -------------------------------------------------

// Represents the 0x128..0x18C region populated by FUN_00032c18. Field names
// mirror the Wipeout ShipData attributes they align with. All values use the
// native Team Buddies fixed-point conventions (Q12 where noted).
typedef struct TbActorConfigBlock
{
    int32_t actor_config_word;     // +0x128: raw config word (low 16 bits store type)
    int32_t actor_id;              // +0x12C: masked actor identifier (param_1 & 0x0FFF)
    int32_t script_ptr;            // +0x130: pointer handed to control/update routines
    int32_t track_section_ptr;     // +0x134: resolved TrackSection pointer
    int16_t unit_forward_x;        // +0x138: forward vector (SVECTOR) X component (/64)
    int16_t unit_forward_y;        // +0x13A: forward vector Y component (/64)
    int16_t unit_forward_z;        // +0x13C: forward vector Z component (/64)
    int16_t unit_forward_len;      // +0x13E: forward vector length (/64)
    int16_t height_target_q12;     // +0x140: desired track height (Q12)
    int16_t roll_bias;             // +0x142: roll bias (/64, sign flipped)
    int16_t velocity_forward_q12;  // +0x144: forward velocity component (Q12)
    int16_t velocity_up_q12;       // +0x146: vertical velocity component (Q12)
    int16_t mass;                  // +0x148: mass (raw short, actor-type dependent)
    int16_t drag_pad;              // +0x14A: auxiliary steering/brake constant
    int16_t max_thrust;            // +0x14C: maximum thrust magnitude
    int16_t turn_rate;             // +0x14E: heading increment (/64)
    int16_t brake_rot_left;        // +0x150: left air-brake rotation limit
    int16_t height_to_forward_q12; // +0x152: magnet ratio (Q12)
    int16_t thrust_mag;            // +0x154: baseline thrust magnitude
    int16_t thrust_boost_q12;      // +0x156: thrust boost factor (Q12 product)
    int16_t remote_thrust_mag;     // +0x158: remote ship thrust magnitude
    int16_t remote_fight_back;     // +0x15A: AI aggression constant
    int16_t remote_max_thrust;     // +0x15C: remote ship thrust cap
    int16_t brake_rot_right;       // +0x15E: right air-brake rotation limit
    int16_t resistance_q12;        // +0x160: drag constant (Q12)
    int16_t rescue_timer;          // +0x162: rescue countdown timer
    int16_t skid_friction_q12;     // +0x164: sideways friction (Q12)
    int16_t combat_attr;           // +0x166: combat attribute flags
    int16_t mass_q12;              // +0x168: secondary mass/drag scaling (Q12)
    int16_t weapon_type;           // +0x16A: initial weapon loadout
    int16_t thrust_ramp_q12;       // +0x16C: throttle ramp factor (Q12)
    int16_t target_ship;           // +0x16E: target selection index
    int16_t speed_q12;             // +0x170: current speed (Q12)
    int16_t max_heading;           // +0x172: maximum heading delta (/64, actor-type scaled)
    int16_t max_heading_copy;      // +0x174: duplicate heading cap (used by updates)
    int16_t lap_time_low;          // +0x176: race timer low word
    int16_t lap_time_high;         // +0x178: race timer high word
    int16_t lap_time_init;         // +0x17A: initial lap time entry
    int16_t update_count;          // +0x17C: frame/update counter
    int16_t pad_17E;               // +0x17E: alignment padding (unused in init)
    int32_t weapon_cooldown;       // +0x180: weapon cooldown timer (cleared to zero)
    int16_t electro_count;         // +0x184: electric weapon timer
    int16_t revcon_count;          // +0x186: reverse control timer
    int16_t special_count;         // +0x188: special weapon timer
    int16_t lap_no;                // +0x18A: current lap index
    int16_t rescue_flag;           // +0x18C: rescue control flag
} TbActorConfigBlock;

typedef struct TbActorState
{
    TbActorPrefix prefix;      // 0x00..0x127: physics/orientation/basis fields
    TbActorConfigBlock config; // 0x128..0x18C: configuration block populated at spawn
} TbActorState;

// Scheduler / crate ecosystem ----------------------------------------------

typedef struct TbCrateCallbacks
{
    void (*primary)(void *context, void *crateSlot);   // usually FUN_00023f50 variants
    void (*secondary)(void *context, void *crateSlot); // usually FUN_000240a0 variants
} TbCrateCallbacks;

typedef enum TbCrateSlotId
{
    TB_CRATE_SLOT_BASE = 0x38,
    TB_CRATE_SLOT_PICKUP = 0x3C,
    TB_CRATE_SLOT_THROW = 0x40,
} TbCrateSlotId;

// Canonical crate scheduler install signature captured from FUN_00035324.
typedef void (*TbCrateSchedulerInstall)(void *context,
                                        void *slot_ptr,
                                        void (*cb_secondary)(void *, void *),
                                        void (*cb_primary)(void *, void *));

// Convenience bundle representing a crate entity during scheduling.
typedef struct TbCrateSchedulerContext
{
    void *scheduler_ctx;  // first parameter handed to installers (a1)
    void *slot_ptr;       // raw slot pointer (a2)
    TbCrateCallbacks cbs; // resolved callback pair for slot install
    uint16_t pad_flags;   // observed pad mask (e.g. 0x10 for pickup chains)
} TbCrateSchedulerContext;

#endif // TB_TYPES_H
