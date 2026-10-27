#!/usr/bin/env python3
"""rt_image.py <image.bin> <prefix.dis> <workdir>: assemble Ghidra's text for every analysed instruction
with armips at its address and compare with the bytes bass produced."""
import os, re, subprocess, sys
img, dis, wd = sys.argv[1:4]
os.makedirs(wd, exist_ok=True)
armips = os.environ.get('ARMIPS', 'armips')
data = open(img, 'rb').read()
SCALAR = set('vrcp vrcpl vrcph vmov vrsq vrsql vrsqh'.split())
lines = ['.rsp', '.create "%s/o.bin",0x1000' % wd]
items = []
for l in open(dis):
    a, hexb, text = l.rstrip('\n').split(' ', 2)
    text = text[1:] if text.startswith('_') else text      # '_' marks a delay-slot instruction
    t = re.sub(r'\[0x([0-9a-f]+)\]', lambda m: '[%d]' % int(m.group(1), 16), text)
    items.append((int(a, 16), hexb, t))
bad = set()
for attempt in range(6):
    asm = ['.rsp', '.create "%s/o.bin",0x1000' % wd]
    where = {}
    for k, (a, hexb, t) in enumerate(items):
        if k in bad:
            continue
        asm.append('.org 0x%x' % a)
        asm.append(t)
        where[len(asm)] = k
    asm.append('.close')
    open(wd + '/o.asm', 'w').write('\n'.join(asm) + '\n')
    r = subprocess.run([armips, wd + '/o.asm'], capture_output=True, text=True)
    errs = re.findall(r'o\.asm\((\d+)\) error', r.stdout + r.stderr)
    if not errs:
        break
    for e in errs:
        bad.add(where[int(e)])
out = open(wd + '/o.bin', 'rb').read()
ident = diff = 0
for k, (a, hexb, t) in enumerate(items):
    if k in bad:
        continue
    got = out[a - 0x1000:a - 0x1000 + 4].hex()
    mn = t.split()[0]
    if mn in ('vrcp', 'vrcpl', 'vrcph', 'vrsq', 'vrsql', 'vrsqh'):
        # the source lane is e & 7; armips always writes e = 8 + lane (and ignores bits 15-14 of vs)
        canon = lambda h: '%08x' % ((int(h, 16) & ~(15 << 21) & ~(3 << 14)) | ((8 | (int(h, 16) >> 21 & 7)) << 21))
        same = canon(got) == canon(hexb)
    else:
        same = got == hexb
    if same:
        ident += 1
    else:
        diff += 1
        print('  differs:', hex(a), hexb, t, '->', got)
print(f'armips round trip: {ident} identical to the bass output, {diff} different, {len(bad)} not assemblable by armips'
      + (': ' + ', '.join(sorted({items[k][2].split()[0] for k in bad})) if bad else ''))
sys.exit(1 if diff else 0)
