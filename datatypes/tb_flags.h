#ifndef TB_FLAGS_H
#define TB_FLAGS_H

// Auto-generated baseline by scripts/generate_tb_flags_header.py, then hand-touched.
// Source: exports/actor_flags_usage.json (global mask histogram)
// NOTE: Only 16-bit-safe bits are exposed here because TbActorPrefix.flags is uint16_t.
// Some large masks (e.g., 2147397986, 2147127136, 65536) come from non-actor contexts
// (menus/other binaries) and are not part of the 0x26 flags.

typedef enum TbActorFlags
{
    TB_FLAG_BIT00 = 0x0001, // hits≈24, bit 0
    TB_FLAG_BIT02 = 0x0004, // hits≈4,  bit 2
    TB_FLAG_BIT04 = 0x0010, // hits≈4,  bit 4
    TB_FLAG_BIT05 = 0x0020, // hits≈8,  bit 5
    // additional bits reserved; refine after UI validation
} TbActorFlags;

#define TB_FLAG_MASK_ALL (TB_FLAG_BIT00 | TB_FLAG_BIT02 | TB_FLAG_BIT04 | TB_FLAG_BIT05)

#endif // TB_FLAGS_H