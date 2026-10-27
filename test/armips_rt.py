#!/usr/bin/env python3
"""Round trip through the armips assembler (black box): armips_rt.py <ghidra.txt> <workdir> [armips]

Every instruction Ghidra decodes is written as assembler text, assembled by armips at the same
address, and the bytes compared with the original word.  Lines armips rejects are reported
separately (armips cannot express some encodings; see GHIDRA-RARE.md)."""
import collections, os, re, subprocess, sys

gh = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[1])]
wd = sys.argv[2]
armips = sys.argv[3] if len(sys.argv) > 3 else os.environ.get('ARMIPS', 'armips')
os.makedirs(wd, exist_ok=True)


def fix(text):
    # small hex numbers inside [] are element numbers: armips wants decimal ones
    text = re.sub(r'\[0x([0-9a-f]+)\]', lambda m: '[%d]' % int(m.group(1), 16), text)
    return text


SCALAR = set('vmov'.split())
RCP_FAMILY = set('vrcp vrcpl vrcph vrsq vrsql vrsqh'.split())
items = []
inexpressible = collections.defaultdict(list)
for i, (w, n, t) in enumerate(gh):
    if t == 'BAD':
        continue
    mn = t.split()[0]
    if mn in SCALAR and not re.search(r'\[\d\]$', fix(t)):
        # vmov with e < 8: armips only has the vt[lane] form (e >= 8); it misreads [0h] etc. as a lane
        inexpressible[mn].append((w, t))
        continue
    items.append((i, w, fix(t)))
bad = set()
for attempt in range(8):
    lines = ['.rsp']
    chunk = -1
    ln = 1
    where = {}
    for i, w, t in items:
        if i in bad:
            continue
        c = i // 1024
        if c != chunk:
            if chunk >= 0:
                lines.append('.close'); ln += 1
            lines.append('.create "%s/c%d.bin",0x1000' % (wd, c)); ln += 1
            chunk = c
        lines.append('.org 0x%x' % (0x1000 + 4 * (i & 1023))); ln += 1
        lines.append(t); ln += 1
        where[ln] = i
    lines.append('.close')
    asm = os.path.join(wd, 'rt.asm')
    open(asm, 'w').write('\n'.join(lines) + '\n')
    r = subprocess.run([armips, asm], capture_output=True, text=True)
    errs = re.findall(r'rt\.asm\((\d+)\) error: (.*)', r.stdout + r.stderr)
    if not errs:
        break
    for l, m in errs:
        bad.add(where[int(l)])
else:
    print('armips kept failing'); sys.exit(1)

def bits(hi, lo):
    return ((1 << (hi - lo + 1)) - 1) << lo


IGN = {}
for m in ('sll', 'srl', 'sra', 'lui'):
    IGN[m] = bits(25, 21)
for m in ('sllv', 'srlv', 'srav'):
    IGN[m] = bits(10, 6)
for m in 'add addu sub subu and or xor nor slt sltu'.split():
    IGN[m] = bits(10, 6)
IGN['jr'] = bits(20, 6)
IGN['jalr'] = bits(20, 16) | bits(10, 6)
IGN['break'] = bits(25, 6)
IGN['mfc0'] = IGN['mtc0'] = bits(10, 0) | bits(15, 15)
IGN['mfc2'] = IGN['mtc2'] = bits(6, 0)
IGN['cfc2'] = IGN['ctc2'] = bits(15, 13) | bits(10, 0)
for m in ('bltz', 'bgez', 'bltzal', 'bgezal', 'beq', 'bne'):
    IGN[m] = bits(15, 10)
for m in ('blez', 'bgtz'):
    IGN[m] = bits(15, 10) | bits(20, 16)
IGN['j'] = IGN['jal'] = bits(25, 10)
IGN['vnop'] = IGN['vnull'] = bits(25, 6)
IGN['vmacq'] = bits(24, 11)
for m in ('vrcp', 'vrcpl', 'vrcph', 'vrsq', 'vrsql', 'vrsqh', 'vmov'):
    IGN[m] = bits(15, 14)
VEC_E = set('vmulf vmulu vrndp vmulq vmudl vmudm vmudn vmudh vmacf vmacu vrndn vmadl vmadm vmadn vmadh vadd vsub '
            'vabs vaddc vsubc vsar vlt veq vne vge vcl vch vcr vmrg vand vnand vor vnor vxor vnxor vsut vaddb '
            'vsubb vaccb vsucb vsad vsac vsum vacc vsuc vextt vextq vextn vinst vinsq vinsn vrcp vrcpl vrcph vmov '
            'vrsq vrsql vrsqh'.split())


def canon(mn, w):
    w &= ~IGN.get(mn, 0)
    if mn in ('cfc2', 'ctc2') and (w >> 11) & 3 == 3:
        w ^= 1 << 11
    if mn in RCP_FAMILY:                   # the source lane is e & 7: armips always writes e = 8 + lane
        w = (w & ~(15 << 21)) | ((8 | (w >> 21 & 7)) << 21)
    elif mn in VEC_E and (w >> 21) & 15 == 1:
        w &= ~(1 << 21)
    return w


stats = collections.Counter()
diffs = collections.defaultdict(list)
rejected = collections.defaultdict(list)
for i, w, t in items:
    mn = t.split()[0]
    if i in bad:
        stats['armips rejects'] += 1
        rejected[mn].append((w, t))
        continue
    c, k = divmod(i, 1024)
    data = open('%s/c%d.bin' % (wd, c), 'rb').read()
    word = int.from_bytes(data[4 * k:4 * k + 4], 'big')
    if word == int(w, 16):
        stats['identical'] += 1
    elif canon(mn, word) == canon(mn, int(w, 16)):
        stats['same after ignoring unused fields'] += 1
    else:
        stats['different'] += 1
        diffs[mn].append((w, t, '%08x' % word))
for k, v in stats.items():
    print(f'{k:20} {v}')
print('not expressible in armips syntax (vmov with e < 8):', sum(len(v) for v in inexpressible.values()))
print('--- armips rejects (by mnemonic)')
for mn, v in sorted(rejected.items(), key=lambda kv: -len(kv[1])):
    print(f'{mn:10} {len(v):6}  e.g. {v[0][0]} {v[0][1]}')
print('--- different bytes (by mnemonic)')
for mn, v in sorted(diffs.items(), key=lambda kv: -len(kv[1])):
    print(f'{mn:10} {len(v):6}  e.g. {v[0][0]} {v[0][1]} -> {v[0][2]}')

sys.exit(1 if stats['different'] else 0)
