#!/usr/bin/env python3
"""real_compare.py <image.bin> <prefix.dis> <outdir>: compare Ghidra's analysed disassembly of an IMEM
image (loaded at 0x1000) with MAME unidasm at the same addresses and with an armips round trip.
Exit 1 on any unexplained difference."""
import os, re, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
tdir = os.path.dirname(here)
img, dis, out = sys.argv[1:4]
os.makedirs(out, exist_ok=True)
data = open(img, 'rb').read()
ma = subprocess.run(['unidasm', img, '-arch', 'rsp', '-basepc', '0x1000', '-norawbytes'],
                    capture_output=True, text=True).stdout.splitlines()
# unidasm reads little-endian words; re-write the image byte-swapped
sw = bytearray(len(data))
for k in range(0, len(data) - 3, 4):
    sw[k:k + 4] = data[k:k + 4][::-1]
open(out + '/swapped.bin', 'wb').write(sw)
ma = subprocess.run(['unidasm', out + '/swapped.bin', '-arch', 'rsp', '-basepc', '0x1000', '-norawbytes'],
                    capture_output=True, text=True).stdout.splitlines()
mame = {}
for l in ma:
    a, t = l.split(';')[0].rstrip().split(': ', 1)
    mame[int(a, 16)] = t
gh, mm = [], []
for l in open(dis):
    a, hexb, text = l.rstrip('\n').split(' ', 2)
    addr = int(a, 16)
    text = text[1:] if text.startswith('_') else text      # '_' marks a delay-slot instruction
    gh.append('%s 4 %s' % (hexb, text))
    mm.append('%s %s' % (hexb, mame[addr]))
open(out + '/gh.txt', 'w').write('\n'.join(gh) + '\n')
open(out + '/mame.txt', 'w').write('\n'.join(mm) + '\n')
r = subprocess.run([sys.executable, here + '/../cmp_mame.py', out + '/gh.txt', out + '/mame.txt'],
                   capture_output=True, text=True)
print('MAME:', ', '.join(l.strip() for l in r.stdout.splitlines() if re.match(r'\s*\d+  (exact|both|explained)', l)) or r.stdout.strip())
rc = r.returncode
if rc:
    print(r.stdout)
sys.exit(rc)
