#!/usr/bin/env python3
"""Run MAME's unidasm (black box) over a word list: mame_dis.py <words.txt> <out.txt> [basepc]
Output: one line per word: "<hex> <mame text>".  Words are placed at basepc (default 0x1000) + 4*(i & 0x3ff)
is not needed here: every word is disassembled at the same pc, one file per call."""
import os, struct, subprocess, sys, tempfile

words = [l.split()[0] for l in open(sys.argv[1]) if l.strip()]
out = sys.argv[2]
base = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x1000
tmp = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
res = []
# unidasm disassembles a file sequentially; put each word at base + 4*(i%1024) by chunks of 1024
for c in range(0, len(words), 1024):
    chunk = words[c:c + 1024]
    p = os.path.join(tmp, 'c.bin')
    with open(p, 'wb') as f:
        for w in chunk:
            f.write(struct.pack('<I', int(w, 16)))
    o = subprocess.run(['unidasm', p, '-arch', 'rsp', '-basepc', hex(base), '-norawbytes'],
                       capture_output=True, text=True).stdout.splitlines()
    assert len(o) == len(chunk), (c, len(o), len(chunk))
    for w, line in zip(chunk, o):
        res.append((w, line.split(';')[0].rstrip().split(': ', 1)[1]))
with open(out, 'w') as f:
    for w, t in res:
        f.write(f"{w} {t}\n")
os.remove(os.path.join(tmp, 'c.bin')); os.rmdir(tmp)
