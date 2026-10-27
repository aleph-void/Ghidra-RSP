# Credits and provenance

## Upstream

- Repository: <https://github.com/Random06457/Ghidra-RSP>
- Forked at commit `35fa20ea2fc9e51f817b496d04d6e7f510f797db` ("add ghidra ver 11.0.1 to 11.1.2 in the CI",
  2024-09-18); the fork keeps the upstream history.
- License: MIT (see `LICENSE`); the changes in this fork are under the same license.
- Original authors (from the history, 27 commits): **Random06457** (Ghidra module, RSP loader, `OSTask`
  structure, README) and **Antonio Vazquez** (GitHub `antoniovazquezblanco`, the CI pipeline, pull request #1).
- The upstream spec was built on the MIPS32 processor module that ships with Ghidra (Apache-2.0,
  National Security Agency); that copied code (`mips.sinc`, `mips32Instructions.sinc`) was replaced in this
  fork. The `rsp.cspec`, `rsp.pspec`, `rsp.ldefs`, the loader skeleton and `OSTask` are the upstream files with
  the changes listed below.
- No other Ghidra implementation of the RSP was found (`gh search repos "ghidra rsp"`, `"ghidra rsp n64"`,
  `"n64 rsp sleigh"`).

## What Ghidra-Rare changed

Each item is a commit on branch `ghidra-rare`.

- **Standalone spec.** `data/languages/rsp.slaspec` is rewritten: the RSP's own scalar instruction set
  (no MIPS32 extras), delay slots, 12-bit PC folded into IMEM, `jal`/`jalr`/`bltzal`/`bgezal` link value, DMEM
  address wrap, ADD/ADDI/SUB never trap, LWU = LW, `r0` read as a constant and writes dropped, `r29` named
  `sp`, COP0 SP/DPC registers by name, CFC2/CTC2 for VCO/VCC/VCE.
- **Vector unit in p-code.** `gen/gen_rsp_vector.py` generates `data/languages/rsp_vector.sinc`: all
  implemented VU computational instructions (accumulators, flag registers, saturation, broadcast elements,
  the reciprocal / reciprocal-square-root unit with its tables computed in p-code), all LWC2/SWC2 forms
  (including LTV/STV, LRV/SRV, packed/half/fourth forms) and the unimplemented function codes (which execute as
  a zeroing instruction on hardware). Upstream had pcodeops for most of this, wrote `vt` instead of `vd` in `vmudh`
  and `vxor`, spelled `vnxor` as `vvxor`, and indexed vector elements from the wrong end.
- **Loader.** Ported to the Ghidra 12 loader API (`load(Program, ImporterSettings)`); the DMEM file is a loader
  option instead of a GUI prompt (so it works headless); the loader is no longer a preferred match for every
  file; checks for IMEM overflow; labels `boot_ucode`/`main_ucode` and `OSTask`.
- **Spec files.** `rsp.cspec` no longer lists a register range that does not exist (`r29` is the stack pointer),
  `rsp.pspec` no longer refers to MIPS classes and registers, empty `rsp.opinion` removed.
- **Extension build.** `build.gradle` (plain extension build, test/generator folders excluded from the zip),
  `extension.properties`.
- **Tests and documents.** `test/` (see `GHIDRA-RARE.md`), `gen/`, `GHIDRA-RARE.md`, this file, README updates.

## Sources used for the work

- Instruction set and vector-unit behaviour: the n64brew RSP documentation and Nintendo's public
  descriptions of the instruction set, cross-checked against the **ares** emulator (ISC license, Near and the
  ares team; <https://github.com/ares-emulator/ares>, commit `5d093ad9e63c3715752a1d7b8e1a077892ae13fb`): its
  decoder, disassembler and vector-unit interpreter were read to settle encodings and corner cases, and its
  vector unit is built and run as a black-box oracle by the test suite (fetched at test time, never copied
  into this repository).
- **armips** (MIT, Kingcom; <https://github.com/Kingcom/armips>) as an independent assembler (RSP mode); its
  opcode table was read to settle mnemonics and the unimplemented function-code names.
- **MAME**'s `unidasm -arch rsp` (run as a black box only; its source was not read) as an independent disassembler.
- **bass** (ISC, byuu / ARM9; <https://github.com/ARM9/bass>) to assemble the real-code samples.
- Real code: Peter Lemon's N64 RSP demos (<https://github.com/PeterLemon/N64>, The Unlicense), fetched by
  pinned commit and SHA-256 and never committed.
