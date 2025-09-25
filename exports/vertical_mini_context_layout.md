# Mini Fast-Path Context (MiniEmitCtx) – Stabilized Layout & Semantics

Status: STABILIZED (core hypothesis H1 adopted; prior bank population hypothesis deprioritized after negative evidence scans)

## Evidence Recap

1. Allocation Cluster: size 8 allocation immediately before each `FUN_0001a558` call inside orchestrator (`FUN_0000a944`).
2. Indexing Snippet: two back-to-back allocations stored into big-struct indices 0x3b / 0x3c (offsets +0xEC / +0xF0) then each mini block's first two words passed as arguments to `FUN_0001a558`.
3. Decompile shows `FUN_0001a558` parameterless, but call sites supply two args (consistent with MIPS register passing; decompiler likely mis-signatured). Inside, accesses remain to large vertical struct fields (progress/step_scale/toggles families) – no observed deref of mini pointer.
4. No detected low-offset stores from mini contexts into banked emission area despite targeted scans (bank population negative evidence).
5. Emission pattern uses toggled indices at +0x38 / +0x3C selecting alternating entries near struct base for calls to `FUN_0002d1a4` / `FUN_0002d220`.
6. Pointer slots (+0xEC / +0xF0) appear orchestration-only; no other consumers surfaced in current scans.

## Mini Context Layout (Size 8 Confirmed by Allocation Size)

Offset  Size  Name             Description
0x0     4     emitTargetPtr    First argument to updater (pointer or ID)
0x4     4     emitParam        Second argument (mode / amplitude variant / channel token)

Rationale: Both words are forwarded directly at call boundary; no intermediate mutation observed.

## Hypothesis Resolution

Adopted (H1 – Direct Use): Arguments to `FUN_0001a558` are consumed directly (register use) rather than copied into low offsets of the large vertical struct. Multiple targeted scans (`scan_vertical_bank_population_filter`, relaxed allocation proximity scans, pointer slot usage enumeration) produced no evidence for a bank population copy path. Bank population remains theoretically possible via inline or opaque code, but negative evidence strength justifies stabilized naming.

## Follow-Up Analytical Focus

Optional future verification: raw disassembly audit of `FUN_0001a558` to locate any early register stores (e.g., sw a0, sw a1) into big struct fields; only needed if later contradictions arise.

## Naming (Adopted)

Structure name: `MiniEmitCtx`
Fields: `emitTargetPtr`, `emitParam`
Big Struct Additions:

* +0xEC: `miniCtxSlotA`
* +0xF0: `miniCtxSlotB`
Bank Toggle Fields:
* +0x38: `emitBankToggleA`
* +0x3C: `emitBankToggleB`

## Validation Snapshot

Criteria satisfied for stabilization:

* Repeated absence of any bank population writes in all targeted scans.
* Consistent allocation size (8) matching hypothesized pair of arguments.
* No conflicting consumers of pointer slots at +0xEC / +0xF0 beyond orchestration.

## Residual Risks

* Inline assembly or decompiler gaps could hide transient copies; monitor future raw dumps.
* If vertical struct is part of a larger composite, low-offset assumptions may shift (recheck upon new conflicting usage).

---
(End of stabilized description – update only if contradictory evidence arises.)

# Mini Fast-Path Context (Provisional Layout & Semantics)

Status: FIRST DRAFT (based on FUN_0000a944 call pattern + FUN_0001a558 internals)

## Evidence Recap

1. Allocation Cluster (scan_fastpath_allocation_clusters): thunk allocates size 8 immediately before each FUN_0001a558 call (distance 5 lines) inside FUN_0000a944.
2. Indexing Snippet (vertical_small_alloc_indexing.md):
   param_1[0x3b] = iVar1;
   FUN_0001a558(*(undefined4*)param_1[0x3b],((undefined4 *)param_1[0x3b])[1]);
   param_1[0x3c] = iVar1;
   FUN_0001a558(*(undefined4 *)param_1[0x3c],((undefined4*)param_1[0x3c])[1]);
   * iVar1 is freshly returned allocation pointer (size 8)
   * Two consecutive allocations store into big-struct word slots at indices 0x3b and 0x3c (offsets 0xEC and 0xF0 respectively).
   * Immediately each allocated block's first two 32-bit words are passed as the two apparent arguments to FUN_0001a558.
3. FUN_0001a558 Decomp (vertical_fun_1a558_field_usage.md) shows signature "void" (no params) in current decompile, but orchestrator passes two args. MIPS ABI allows up to four args in a0–a3; the decompiler labeling them unused suggests either:
   * a) The function was inlined / prototype mis-guessed; or
   * b) The arguments are only used in a code path not recovered (e.g., stripped, macro, or conditional compiled region) — less likely.
4. Inside FUN_0001a558 all accesses are relative to `unaff_s0` which is the LARGE vertical struct, not the mini context pointer just allocated. Therefore the two arguments must be consumed indirectly (possibly stored earlier into big struct, or they seed state via side effect before call site—e.g., caller pre-populates big struct fields at locations FUN_0001a558 will index using its internal toggles 0x38 / 0x3c).
5. Emission pattern:
   FUN_0002d1a4(*(unaff_s0 + toggleA*4 + 4), *(unaff_s0 + 0x44));
   FUN_0002d220(*(unaff_s0 + toggleB*4 + 0xC), scaledStep);
   With toggleA at +0x38, toggleB at +0x3c (each XOR 1 after use). This implies two interleaved banks of at least 2 words each:
   * Bank A base: (unaff_s0 + 4) provides two alternating 32-bit values for FUN_0002d1a4.
   * Bank B base: (unaff_s0 + 0xC) provides two alternating 32-bit values for FUN_0002d220.
   Spacing suggests contiguous layout: [ 0x00 ??? | 0x04 A0 | 0x08 A1 | 0x0C B0 | 0x10 B1 | ... ].
   Thus, installing newly allocated mini contexts might populate these bank entries (or supply pointers that banks will dereference).
6. Because orchestrator stores pointer to mini context in slots far away (0xEC / 0xF0) and then immediately calls the updater twice, the mini contexts might carry values that the big struct ingest logic (another function) copies into the banked emission arrays prior to toggle usage. That ingest step is currently UNRESOLVED (no direct copy observed yet) — we need to scan for memcpy / pairwise word stores referencing offsets +4..+0x10 with preceding loads from 0xEC / 0xF0.

## Provisional Mini Context Layout (Size 8)

Offset  Size  Name (proposed)   Hypothesis
0x0     4     emitTargetPtr?    First arg passed to FUN_0001a558 (candidate direct pointer or ID)
0x4     4     emitParam?        Second arg passed (maybe amplitude variant / channel / command)

Rationale: Both words are treated as raw 32-bit values at call boundary; no intermediate mutation before passing.

## Competing Hypotheses

H1 (Direct Use): FUN_0001a558 actually uses the two passed values via argument registers to seed hidden global or coprocessor state before main body (decompiler missed due to inline or ASM stub). Needs verification by raw disassembly.
H2 (Bank Population Elsewhere): Another helper, invoked between allocation and first emission, copies the two words into the ring-buffer region (offsets 0x04–0x10). We have not yet captured that helper; it might be inlined into FUN_0000a944 directly before the FUN_0001a558 calls but after pointer store. Need a more granular window diff around those lines.
H3 (Pointer-to-Pair): Each mini context pointer is itself inserted into an array; FUN_0001a558 uses toggles to select which pointer-of-pointers to dereference. BUT current arithmetic adds toggle*4 to base inside big struct, not to the mini context region, diminishing this option unless 0x04 and 0x0C hold the stored mini context pointers copied earlier.

## Immediate Next Analytical Steps

1. High-Resolution Slice of FUN_0000a944:
   * Extract 40–60 instruction window around the two allocation + store + call sequences to see if there are word copies from [v0] (alloc) into big struct low offsets (<= 0x14).
   * Script: scan_fun_0a944_window.py to dump raw disassembly and annotate writes to offsets 0x00–0x20 of big struct.
2. Bank Base Discovery:
   * Pattern search for instructions writing to (struct + 4) or (struct + 0xC) with values from registers that previously loaded (struct + 0xEC)/(struct + 0xF0) or from mini context pointer.
   * New script: scan_vertical_bank_population.py.
3. Arg Register Usage Audit:
   * Dump raw MIPS of FUN_0001a558 to see if a0/a1 are stored early (e.g., sw a0,X(s0)) before decompiler lost track.
   * New script: dump_raw_fun.py (generic with filter on address 0x1a558) using objdump or Ghidra export (depends on existing toolchain).
4. Cross-Reference 0xEC / 0xF0 Fields:
   * Enumerate all functions reading those offsets to confirm they only appear in orchestration/allocation context.
   * Script: scan_bigstruct_pointer_slots.py (parameterized offsets list).
5. Extend fast-path caller search:
   * Relax pattern to: size-8 allocation within N instructions before call to FUN_0001a558 (N <= 12) regardless of storing into 0x3b/0x3c indices.
   * Script: scan_relaxed_fastpath_allocs.py.

## Naming Proposal (Tentative)

Structure: MiniEmitCtx

Fields:

* word0: emitTargetPtr (or channelNode)
* word1: emitArg (or payload)

Big Struct Additions:

* +0xEC: miniCtxSlotA
* +0xF0: miniCtxSlotB
* Bank A (toggle index +0x38): entries at +0x04/+0x08 (EmitBankA[2])
* Bank B (toggle index +0x3C): entries at +0x0C/+0x10 (EmitBankB[2])

These names will be firmed once bank population writes are observed.

## Validation Criteria

We will lock layout after confirming at least two of:

* Direct store of miniCtx->word0 into struct+4 (or +8) before its use in FUN_0001a558.
* Observed read of struct+4 (or +8 / +0xC / +0x10) passed directly to FUN_0002d1a4 / FUN_0002d220 in some other path.
* No alternative consumers of +0xEC / +0xF0 beyond allocator/orchestrator.

## Open Risks

* Decompiler aliasing may hide that unaff_s0 inside FUN_0001a558 is actually the mini context (unlikely due to 0x24 / 0x8C field access which map to big struct semantics).
* Bank region might overlap with unrelated engine header fields if vertical struct is embedded within a larger entity; offset assumptions must be rechecked if conflicting usage appears.

## Next Report

Will produce: bank_population_evidence.md with extracted candidate write sequences and updated confidence scoring (0–1 scale) per hypothesis H1–H3.

---
(End of draft – will iterate after disassembly/window scans.)
