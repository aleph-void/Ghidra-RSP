#!/usr/bin/env python3
"""build_cases.py [cases.src [cases.txt]]: turn the hand-written cases.src (assembler text + expectations)
into cases.txt (instruction words + expectations) with armips (black box).  The words are checked in so
the emulator suite needs no assembler."""
import os, re, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
src = sys.argv[1] if len(sys.argv) > 1 else here + '/cases.src'
dst = sys.argv[2] if len(sys.argv) > 2 else here + '/cases.txt'
armips = os.environ.get('ARMIPS', 'armips')
tmp = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
out = []
asm = None
for line in open(src):
    s = line.rstrip('\n')
    if asm is not None:
        if s.strip() == 'endasm':
            open(tmp + '/c.asm', 'w').write('.rsp\n.create "%s/c.bin",0x1000\n.org 0x1000\n%s\n.close\n' % (tmp, '\n'.join(asm)))
            r = subprocess.run([armips, tmp + '/c.asm'], capture_output=True, text=True)
            if r.returncode:
                sys.exit('armips failed:\n' + r.stdout + r.stderr + '\n'.join(asm))
            data = open(tmp + '/c.bin', 'rb').read()
            for a in asm:
                out.append('# ' + a.strip())
            out.append('code ' + ' '.join('%08x' % int.from_bytes(data[i:i + 4], 'big') for i in range(0, len(data), 4)))
            asm = None
        else:
            asm.append(s)
    elif s.strip() == 'asm':
        asm = []
    else:
        out.append(s)
open(dst, 'w').write('\n'.join(out) + '\n')
print('wrote', dst)
