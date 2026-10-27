# Ghidra-RSP

A Nintendo 64 RSP processor module and loader for [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

![Demo](https://github.com/Random06457/Ghidra-RSP/assets/28494085/64c587df-c587-4ef0-8982-8126af713f57)

> **Ghidra-Rare fork.** This fork keeps the original authors' module and loader and brings them to
> Ghidra 12.1.x / 12.2, with a complete RSP instruction set (the vector unit is now modelled in p-code
> rather than left as pcodeops), a headless-capable loader and a test suite. See
> [GHIDRA-RARE.md](GHIDRA-RARE.md) for what was changed and verified and [CREDITS.md](CREDITS.md) for
> provenance. Prebuilt extension zips are on this repository's Releases page.

# Usage
- Drop a RSP binary in Ghidra (content of IMEM), choose the language `Nintendo 64 RSP (RSP:BE:32:default)`
  and the loader `Nintendo 64 RSP loader`. (The loader is offered for any file of at most 4 KB whose size is a
  multiple of 4; it is never selected automatically, because an IMEM image has no signature.)

- In the loader options, you can decide whether to load the RSP binary as a boot microcode or main microcode. (This will just change the base address of the binary, 0x1000 or 0x1080 respectively for boot or main microcode).

- The option `DMEM file (optional)` takes the path of a file with the content of DMEM to load at address 0
  (it used to be a file prompt shown after the OK button, which could not work headless). Headless:
  `-loader GhidraRSPLoader -loader-isBoot true -loader-dmemFile <path>`.

Address model: DMEM is 0x0000-0x0FFF and IMEM 0x1000-0x1FFF of one address space. Data accesses always
go to DMEM and wrap at 4 KB, jump and branch targets are folded into IMEM (the RSP's PC is 12 bits),
and the link value written by `jal`/`jalr`/`bltzal`/`bgezal` is the 12-bit PC, as on hardware.

# Installation

- Open Ghidra
- File-> Install Extensions
- Import zip file from the release section

The zips are built for Ghidra 12.1.3, 12.1.4 and 12.2 (the original release targeted 11.x and its loader
no longer compiled on Ghidra 12).

# Known limitations

The original README listed none. These are the ones found, with their state in this fork:

| Limitation | State |
|---|---|
| Built for Ghidra 11.0.1-11.1.2; the loader did not compile against the Ghidra 12 loader API | Fixed: builds and runs on 12.1.3, 12.1.4 and 12.2 |
| The loader opened a GUI file chooser, which fails headless, and claimed every file as a preferred RSP image | Fixed: DMEM is a loader option; the loader is offered only for plausible IMEM sizes |
| The spec included Ghidra's whole MIPS32 instruction set (multiply/divide, FPU, unaligned loads, traps, ...), none of which exists on the RSP, with unresolved pattern conflicts | Fixed: the RSP's own instruction set only |
| Most vector instructions were pcodeops (`vmulf`, `vadd`, ... returned an opaque value), several wrote the wrong register (`vmudh`, `vxor` wrote `vt`) and `vnxor` was spelled `vvxor`; vector elements were numbered from the wrong end; `lqv`/`lrv`/`lpv`/`luv`/`lhv`/`lfv`/`ltv` and their stores were pcodeops | Fixed: the whole vector unit, accumulators, VCO/VCC/VCE and the reciprocal unit are p-code, checked against the ares emulator |
| `jr`/`jal`/branch targets were MIPS absolute addresses, not IMEM addresses; the link value was a full address | Fixed (see Address model above) |
| `sp` was a separate register, not `r29` | Fixed: `r29` is `sp` |
| Wrapping of multi-byte accesses that cross the end of DMEM, exceptions, DMA and the peripheral side effects of COP0 register writes | Remaining; see [GHIDRA-RARE.md](GHIDRA-RARE.md) |
| No ELF/DWARF handling | Not applicable: no compiler targets the RSP with DWARF, and RSP ELF files (libdragon) carry the MIPS machine type |
