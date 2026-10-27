# RSP: verification notes (Ghidra-Rare)

Language `RSP:BE:32:default` (see README.md). Provenance and the list of changes are in
[CREDITS.md](CREDITS.md). Everything below is reproduced by `test/run-tests.sh [--real] <workdir>`
(needs `unidasm` from MAME on PATH, `ARMIPS` = armips and, for `--real`, `BASS` = bass: `test/build-tools.sh <dir>`
builds both; g++ and git for the ares oracle). Run against Ghidra 12.1.4; the release zips also build for 12.1.3 and
12.2 (the emulator suite and the ares comparison were re-run on all three: 58/58 and 5528/5528 on each).

## Results

| Area | Result |
|---|---|
| Build | `rsp.slaspec` compiles on 12.1.3, 12.1.4 and 12.2 with no pattern conflicts; `.sla` 187 KB; release zips build for all three (`tools/build-module.sh --standard --name RSP`). The upstream loader did not compile on Ghidra 12 |
| Decode vs armips (assembler) | All 5,494 forms armips accepts (every mnemonic, every element, every sub-opcode, shift amount, COP0/control register) decode back to the same text: 5,494/5,494. Round trip of Ghidra's text through armips on the 11,680-word structured corpus (every opcode/function/sub-op/element) and 200,000 random words: bytes identical or identical after ignoring fields the RSP ignores (74,541 + 5,626), 0 different; armips cannot express `vmacq vd`, the unnamed reserved function codes, `lwu`, and `vmov` with e < 8 |
| Decode vs MAME `unidasm -arch rsp` | Structured + 200,000 random words: 0 unexplained differences (122,198 + 5,734 both invalid, 70,682 + 4,463 exact, the rest in the explained classes below) |
| Every constructor reached | 477/477 |
| Semantics | Emulator (EmulatorHelper): 58 hand-computed sequences (ALU, flags, shifts, loads/stores with extension and unaligned access, DMEM wrap, delay slots, jal/jalr/jr/bltzal/bgezal links, COP0, MFC2/MTC2/CFC2/CTC2, vector add/sub/mul/logic/compare/merge/carry ops, broadcast elements, reciprocal, LQV/LRV/SQV/SRV/LDV/LBV/LSV/LLV/LPV/LUV/LHV/LFV/LTV/STV...) all pass; one deliberately wrong expectation is reported. Differential test: 12,688 random single instructions (every vector function code x all 16 elements x aliased registers, all COP2 moves, all 23 LWC2/SWC2 forms x 16 elements, random accumulators, flags, divider state and memory) against the vector unit of the ares emulator built as a black box: 12,688/12,688 identical (registers, accumulators, VCO/VCC/VCE, divider state, 1,280 bytes of DMEM, GPRs). Mutating the p-code makes this test fail (checked with a wrong multiplier) |
| Real code | Ten of thirteen freely licensed RSP programs by Peter Lemon (The Unlicense; three use an old bass syntax current bass rejects), assembled with bass, loaded with the module's loader (with DMEM), auto-analysed: 2,185 instructions, 0 bad-instruction/error bookmarks, every function decompiles (10/10, the warning is the final `break` falling off the end of IMEM). Every instruction agrees with MAME apart from the explained classes and, after being re-assembled by armips at its address, is byte-identical to the bass output (two other assemblers agree with Ghidra: 2,185/2,185, the RCP-family `e` bit aside) |

## Method

- **Decode.** Three opinions: armips (assembler; table read, MIT), MAME `unidasm` (black box) and the
  ares disassembler/decoder (read; ISC). The armips round trip is the strict one (exact bytes); MAME is
  compared after both texts are parsed to a canonical form, and every difference must fall in a named class.
- **Semantics.** The vector unit is generated (`gen/gen_rsp_vector.py`). It is checked against hand-computed
  results and, for coverage, against the ares emulator's vector unit (SSE code path): the harness
  `test/ares/harness.cpp` includes ares's `interpreter-vpu.cpp` at a pinned commit (fetched at test time, never
  committed) and `test/SemDiff.java` runs the same case file in Ghidra's emulator.
- **Ghidra emulator note.** The legacy `EmulatorHelper` cannot write sub-ranges of `unique` temporaries
  (`UniqueMemoryBank.setChunk` indexes out of bounds), so the generated p-code assembles values with shifts and
  ORs instead of assigning bit ranges of locals.
- **Real code.** `test/fetch-samples.sh` fetches (pinned commit and SHA-256) the sources of Peter Lemon's RSP
  demos; `test/real-check.sh` builds them with bass, without the ROM header and boot code.

## Explained differences from MAME (bugs of its disassembler, checked against armips's encoder and ares)

- `mfc2`/`mtc2`: the element is read from bits 10..6 (5 bits) instead of 10..7 (e.g. element 5 prints as 10 or 11).
- `vrcp`/`vrcpl`/`vrcph`/`vrsq`/`vrsql`/`vrsqh`/`vmov` with e < 8: the source lane printed differs from the
  emulated one (MAME's emulator, like ares, reads lane e & 7 for the reciprocal family).
- `lui` prints a bogus `rs` operand; `vmacq` prints vs and vt (only vd is used); `vsar` is spelled `vsaw` and its
  slice printed as `???`; `mfc0`/`mtc0` with COP0 register 16-31 print `???` (the RSP masks to 4 bits);
  `cfc2`/`ctc2` name control register n `FLAGn` (the RSP masks to 2 bits).
- MAME has no `lwu` (the RSP executes it as `lw`) and decodes `lwv` (LWC2 sub-opcode 10), which the RSP does not
  have; it prints `[???]` for e = 1 and rejects the function codes the RSP does not implement (which execute as a
  zeroing instruction on hardware, per ares).
- armips notes (not bugs): `jalr` operands are `rs,rd`; it has no `lwu`, no one-operand `vmacq`, no name for
  function codes 0x2e/0x2f/0x3b, and reads `v1[0h]` as lane 0 in the scalar-element forms.

## Doesn't work

| Gap | Why |
|---|---|
| Multi-byte loads/stores that cross the end of DMEM (e.g. `lw` at 0xFFE) do not wrap to 0; the base address is wrapped but the access is one p-code load | A byte-wise model of every access would make the decompiler output unusable; LQV/LRV/SQV/SRV, which hardware keeps inside an aligned 16-byte block, are exact |
| COP0 registers (SP_*, DPC_*) are plain registers: DMA starts, status set/clear bits, the semaphore and the RDP interface have no side effects | Peripheral hardware state outside the processor |
| `break` falls through (it is a pcodeop, `rsp_break`) | The CPU restarts the RSP at the next instruction; flow after a `break` is real code (yield points), so analysis keeps going. Falling off the end of IMEM shows a "bad instruction" warning in the decompiler |
| A branch in a delay slot, and sequential execution from 0x1FFC wrapping to 0x1000 | Ghidra's delay-slot model and linear address space |
| No ELF opinion or DWARF mapping | RSP ELF files (libdragon) carry the MIPS machine type; no compiler emits RSP DWARF |

## Unverified

- Everything about real hardware: the reference for the vector unit is the ares emulator (validated by its authors against
  hardware test ROMs), not hardware. Specifically unverified there: the unimplemented function codes
  (modelled as ares does: `ACC_L = vs + vte`, `vd = 0`), `veq`/`vne`/`vge` clearing VCC's high byte, `cfc2`/`ctc2`
  register 3 as VCE, and `vrcp`-family reads of lane e & 7 for e < 8 (Peter Lemon's PlotTriangle demo uses e = 4..7).
- Three of the thirteen sample programs could not be assembled (old bass syntax), so macros of the DCT video
  decoders with RDP code are not covered; no real main/boot microcode of a commercial game was used (none may be).
