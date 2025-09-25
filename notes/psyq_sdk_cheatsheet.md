# PSYQ SDK quick reference (for Team Buddies RE)

This is a concise index of the most useful PSYQ headers, APIs, constants, and recognition patterns for matching library calls in our decompilation bundles.

- Where: assets/PSYQ_SDK/psyq/include/*.H
- Docs: assets/PSYQ_SDK/psyq/DOCS (LibRef/LibOvr, FAQ, TechNotes)

## Input / Timing

Header: LIBETC.H

- Pad bitmasks (sio pad):
  - PADLup (1<<12), PADLdown (1<<14), PADLleft (1<<15), PADLright (1<<13)
  - PADRup (1<<4), PADRdown (1<<6), PADRleft (1<<7), PADRright (1<<5)
  - PADi (1<<9) [triangle], PADj (1<<10) [circle], PADk (1<<8) [cross], PADl (1<<3) [square]
  - PADm (1<<1) [R2], PADn (1<<2) [L1], PADo (1<<0) [L2], PADh (1<<11) [Start]
  - Macros PADL1,PADL2,PADR1,PADR2,PADstart,PADselect
- Core APIs: PadInit(int mode), u_long PadRead(int id), VSync(int mode), VSyncCallback, Get/SetVideoMode

Header: LIBPAD.H (extended controller)

- Advanced pad init/control: PadInitDirect, PadStartCom/StopCom, PadGetState, PadInfoMode/Act/Comb, PadSetMainMode, PadSetAct/PadSetActAlign, multitap, gun
- Useful to identify controller probing code (InfoMode/Act sequences)

Recognition patterns

- Game loop often calls VSync(0) each frame; PadInit then PadRead(0/1). Edge detection: new = pad ^ old; press = new & pad; release = new & ~pad

## Graphics (GPU / GS)

Header: LIBGPU.H (low-level GPU primitives)

- Structures: RECT/DRAWENV/DISPENV; primitive structs POLY_F3/FT3/G3/GT3/F4/FT4/G4/GT4, LINE_*, SPRT/TILE, DR_* control packets
- Core APIs: ResetGraph, SetDefDispEnv/DrawEnv, PutDispEnv/DrawEnv, SetDispMask(1), DrawSync, ClearOTag/ClearOTagR, DrawOTag/DrawOTagEnv, LoadTPage/LoadClut/LoadImage/StoreImage/MoveImage
- Macros: setPoly*, setRGB*, setXY*, setUV*, addPrim/addPrims/termPrim; getTPage/getClut; setDrawMode/TPAGE/TEXWINDOW

Header: LIBGS.H (higher-level scene lib)

- Object/OT types (GsOT, GsDOBJx), sprite/bg helpers, TMD/TIM helpers
- If the title uses raw LIBGPU, you’ll see DrawOTag, SetDefDispEnv; if LIBGS, GsInitGraph/GsDrawOt/GsSortObject*

Recognition patterns

- Double-buffer init: ResetGraph(0) → SetDefDispEnv/DrawEnv for two buffers → SetDispMask(1)
- Per-frame: ClearOTag, build prim chains (addPrim), DrawOTag, DrawSync(0)

## Geometry (GTE)

Header: LIBGTE.H

- Math types: MATRIX, VECTOR, SVECTOR, CVECTOR, DVECTOR
- Core APIs: InitGeom, SetGeomOffset/Screen, RotTransPers[3|4], RotTrans, NormalColor*, AverageZ*, NormalClip, GTE matrix setters (SetRot/Trans/Light/ColorMatrix)
- Many rendering helpers for PMD/TMD paths

Recognition patterns

- Calls to SetGeomOffset/Screen near video init; RotTransPers* in render code; heavy SVECTOR usage

## CD-ROM (data + XA)

Header: LIBCD.H (classic CD)

- Core APIs: CdInit, CdReset, CdControl/CdControlB/CdControlF, CdSync/CdReady, CdDataSync
- File helpers: CdSearchFile(CdlFILE*, "NAME"), CdReadFile("NAME", dst, nbytes)
- Streaming: St* ring buffer helpers declared if LIBDS isn’t included (StSetRing, StGetNext, etc.)
- Commands: CdlSetloc, CdlReadN, CdlReadS, CdlPlay, CdlSeekL/P; mode bits (CdlMode*) and status bits (CdlStat*)

Header: LIBDS.H (data streaming)

- Replaces Cd\* with Ds\* (asynchronous command queue); same concepts (Dsl\*)
- St* ring buffer API duplicated here (for STR movies / CD-XA streaming)

Recognition patterns

- Name-based loading: CdSearchFile/CdReadFile("FILE"); however this game likely uses sector/index-based reads into custom packs (BUDDIES.DAT, ENG.BIN). Expect: CdControl(CdlSetloc, …) + CdReadN/CdReadS loop with CdReadSync/Ready
- Typical loop: setloc → setmode (Stream/Speed/Report) → read → poll ready/data sync; copy 2048/2328/2340 bytes per sector
- XA audio: CdlModeRT | CdlModeDA | CdlModeSF + filter (CdlSetfilter)

## Sound (SPU + libsnd)

Header: LIBSPU.H (SPU low-level)

- Voices 0..23, SpuInit/Start/Quit, SpuWrite & transfer modes, SpuSetKey/VoiceAttr, reverb controls, IRQ, DMA

Header: LIBSND.H (sequencer + VAB/VAG)

- Bank loading: SsVabOpenHead/TransBody/Transfer, SsVabClose
- Sequence playback: SsInit/Start, SsSeqOpen/Play/Stop, SsSep*
- One-shots/utility: SsUtKeyOn(V), SsUtChangeADSR, SsPitchFromNote

Recognition patterns

- Boot: SsInit/SsStart or SpuInit/SpuStart; sound banks loaded from files (often via CdReadFile or from pack) then SsVabTransfer
- XA: often combined with DS/St streaming and Spu CD input mix (SpuSetCommonCDMix)

## Memory Card

Header: LIBMCRD.H (libmcard)

- MemCardInit/Start/Stop/Exist/Accept
- File ops: MemCardOpen/Close/ReadData/WriteData, MemCardGetDirentry, MemCardFormat
- Events via MemCardSync + callbacks

## Compression / MDEC

Header: LIBPRESS.H

- MDEC decode: DecDCTReset, DecDCTvlc*, DecDCTin/out, callbacks; DECDCTENV/DECDCTTAB
- SPU encoder (ENCSPU*) helpers for generating VAG-like data (less likely in retail)

Recognition patterns

- Movies: DS/St + DecDCT* used together; not needed for ENG.BIN text

## Kernel / FS / ROMIO / SIO

Header: KERNEL.H

- Exec structures: struct EXEC (used by CdReadExec), XF_HDR (PS-X EXE header), struct DIRENTRY (file dir entries)
- Event descriptors (HwVBLANK/HwGPU/HwCdRom, RCnt*, EvSp*, TCB, EvCB)

Header: FS.H / ROMIO.H

- Device table and IO block definitions; rarely called directly in game code

Header: LIBSIO.H

- Serial IO control bits and callbacks; rarely used in retail builds

## What to search for in our decomp bundles

High-confidence API names (if not stripped):

- Input: PadInit, PadRead, VSync, VSyncCallback
- Video: ResetGraph, SetDefDispEnv/DrawEnv, DrawSync, DrawOTag, SetDispMask
- Geometry: InitGeom, SetGeomOffset, SetGeomScreen, RotTransPers
- CD: CdInit, CdRead, CdReadFile, CdControl, CdSync, CdReady, CdlSetloc/CdlReadN/CdlReadS
- Streaming: Ds*/St* (StSetRing, StGetNext, StCdInterrupt)
- Sound: SpuInit/Start/SetKey/VoiceAttr, SsInit/SsVab\* / SsSeq\*
- Memcard: MemCard*

If names are stripped, identify by patterns:

- Pad: function returning 32-bit mask with bit tests against constants like 0x800 (1<<11), 0x1000 (1<<12), etc., called once per frame.
- VSync: tight loop function returning int, called every frame, sometimes used to pace at 50/60; may reference RCnt* counters.
- CD Read (indexed): sequence of small functions where one writes 3 BCD bytes (min/sec/sector) into a struct then issues a command (value 0x15/0x16/0x06/0x1B) via a generic control wrapper; polling loop calling a status/sync function until DataReady (0x01) or Complete (0x02).
- Draw: functions manipulating OT linked lists (addr/len/code layout), setcode(0x2x/0x3x/0x6x/0x7x), then DrawOTag.
- Sound bank load: large memory copy into SPU RAM followed by SsVabTrans* and SsVabTransCompleted polling.

## PSYQ Docs worth opening (PDFs)

- DOCS/LIBREF46.PDF (library reference), DOCS/LIBOVR46.PDF (overview)
- DOCS/TECHNOTE: ordtbl.pdf (ordering tables), Memcard.PDF (save system), CDSWITCH.PDF (disc swapping), SPURAM.PDF, palguide.pdf

## How this helps ENG.BIN mapping

- Likely no string literals in code. Focus CD routines that read raw sectors and custom index tables:
  - Look for CdInit early; later a loop doing CdControl(CdlSetloc)+CdReadN/CdlReadS and a sector-copy routine that writes into buffers.
  - Identify a pack/dir parser that builds tables of offsets/sizes used by systems (UI, speech, models). This should sit downstream of the CD block reader.
- Target search anchors:
  - Any function issuing ‘seek + read + sync’ sequences repeatedly (with small structs of 3 BCD fields) → candidate raw reader.
  - Functions that convert between BCD and int (btoi/itob macros are simple) → helpers around CdLOC.
  - Callers of sound/texture loaders that accept (offset,size) pairs rather than names.
