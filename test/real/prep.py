#!/usr/bin/env python3
"""prep.py <sample.asm> <out.asm> <rom-name>: turn a Peter Lemon demo into an assembler input that bass
can build without the ROM header and the 4032-byte boot code (not fetched): both lines are replaced by 4096
bytes of zero fill, so every address stays where the author put it; other insert lines (frame data
for the CPU side) are dropped.  A final print statement reports
the file offsets of the RSP code and data (RSPCode/RSPCodeEnd/RSPData/RSPDataEnd)."""
import sys
out = []
for l in open(sys.argv[1], errors='replace').read().split('\n'):
    if l.startswith('output '):
        l = 'output "%s", create' % sys.argv[3]
    elif l.startswith('include "LIB/N64_HEADER.ASM"'):
        l = 'fill 4096 // the 64-byte header and the boot code are not used'
    elif l.lstrip().startswith('insert "'):
        continue        # boot code, video frames, ...: data the RSP code does not depend on
    out.append(l)
out.append('print "OFFSETS ", hex:(RSPCode & $FFFFFF), " ", hex:(RSPCodeEnd & $FFFFFF), " ", hex:(RSPData & $FFFFFF), " ", hex:(RSPDataEnd & $FFFFFF), "\\n"')
open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
