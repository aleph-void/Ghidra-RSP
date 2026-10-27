#!/usr/bin/env python3
"""sem_cmp.py <cases.txt> <ares.out> <ghidra.out> : compare final states; group differences by instruction."""
import collections, sys
cases = [l.split(' ', 1)[0] for l in open(sys.argv[1])]
a = [l.split() for l in open(sys.argv[2])]
g = [l.split() for l in open(sys.argv[3])]
assert len(cases) == len(a) == len(g), (len(cases), len(a), len(g))
names = ['v%d' % i for i in range(32)] + ['ACC_H', 'ACC_M', 'ACC_L', 'VCO', 'VCC', 'VCE', 'DIVIN', 'DIVOUT', 'DIVDP'] + \
        ['r%d' % i for i in range(32)] + ['dmem']
bad = collections.defaultdict(list)
n = ok = 0
for w, x, y in zip(cases, a, g):
    n += 1
    word = int(w, 16)
    key = '%02x/%02x' % (word >> 26, (word & 0x3f) if (word >> 25 & 1) and word >> 26 == 0x12 else (word >> 11 & 31 if word >> 26 in (0x32, 0x3a) else word >> 21 & 31))
    if x == y:
        ok += 1
        continue
    diffs = [names[i] for i in range(len(x)) if x[i] != y[i]]
    bad[key].append((w, diffs, x, y))
print(f'{ok}/{n} cases identical')
for k, v in sorted(bad.items()):
    print(f'  {k}: {len(v)} differ, e.g. {v[0][0]} fields {v[0][1][:6]}')
sys.exit(1 if bad else 0)
