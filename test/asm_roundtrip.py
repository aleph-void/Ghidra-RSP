#!/usr/bin/env python3
"""asm_roundtrip.py <forms.txt> <workdir> : assemble every form with armips, decode with Ghidra
(test/dis.sh) and compare Ghidra's text with the source line.  Prints counts; exit 1 if any form
fails to decode or decodes to something else."""
import os, re, subprocess, sys
forms = [l.strip() for l in open(sys.argv[1]) if l.strip()]
wd = sys.argv[2]
os.makedirs(wd, exist_ok=True)
armips = os.environ.get('ARMIPS', 'armips')
here = os.path.dirname(os.path.abspath(__file__))
lines = ['.rsp']
chunk = -1
where = {}
ln = 1
for i, t in enumerate(forms):
    c = i // 1024
    if c != chunk:
        if chunk >= 0:
            lines.append('.close'); ln += 1
        lines.append('.create "%s/f%d.bin",0x1000' % (wd, c)); ln += 1
        chunk = c
    lines.append('.org 0x%x' % (0x1000 + 4 * (i & 1023))); ln += 1
    lines.append(t); ln += 1
    where[ln] = i
lines.append('.close')
open(wd + '/f.asm', 'w').write('\n'.join(lines) + '\n')
r = subprocess.run([armips, wd + '/f.asm'], capture_output=True, text=True)
bad = re.findall(r'f\.asm\((\d+)\) error: (.*)', r.stdout + r.stderr)
if bad:
    for l, m in bad[:10]:
        print('armips rejects:', forms[where[int(l)]], m)
    print(len(bad), 'forms rejected by armips'); sys.exit(1)
words = []
for c in range((len(forms) + 1023) // 1024):
    d = open('%s/f%d.bin' % (wd, c), 'rb').read()
    words += ['%08x' % int.from_bytes(d[j:j + 4], 'big') for j in range(0, len(d), 4)]
words = words[:len(forms)]
open(wd + '/f.words', 'w').write('\n'.join(words) + '\n')
subprocess.run([here + '/dis.sh', wd + '/f.words', wd + '/f.gh'], check=True)
gh = [l.rstrip('\n').split(' ', 2) for l in open(wd + '/f.gh')]


def norm(s):
    s = s.lower()
    s = re.sub(r'0x([0-9a-f]+)', lambda m: str(int(m.group(1), 16)), s)
    return s.replace(' ', '')


NAMES = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
         's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra']
GH = ['zero'] + ['r%d' % i for i in range(1, 29)] + ['sp', 'r30', 'ra']


def regs(s):
    # source text uses MIPS names; Ghidra names r1..; map source names to Ghidra's.  Vector registers
    # v0..v31 are only ever followed by [ or , in vector context; a source register named v0/v1 is a GPR.
    out = []
    for tok in re.split(r'([,()\[\] ])', s):
        out.append(tok)
    return ''.join(out)


def src_norm(t):
    m = re.match(r'(\w+)\s*(.*)', t)
    mn, ops = m.group(1), m.group(2)
    VEC = set('vmulf vmulu vrndp vmulq vmudl vmudm vmudn vmudh vmacf vmacu vrndn vmacq vmadl vmadm vmadn vmadh vadd vsub '
              'vsut vabs vaddc vsubc vaddb vsubb vaccb vsucb vsad vsac vsum vsar vacc vsuc vlt veq vne vge vcl vch vcr '
              'vmrg vand vnand vor vnor vxor vnxor vextt vextq vextn vinst vinsq vinsn vrcp vrcpl vrcph vmov vrsq vrsql vrsqh'.split())
    parts = [p for p in re.split(r',(?![^\[]*\])', ops) if p]
    res = []
    for k, p in enumerate(parts):
        p = p.strip()
        if p in NAMES and not (mn in VEC):
            p = GH[NAMES.index(p)]
        elif p in ('vco', 'vcc', 'vce'):
            p = p.upper()
        elif p in ('sp_mem_addr sp_dram_addr sp_rd_len sp_wr_len sp_status sp_dma_full sp_dma_busy sp_semaphore '
                   'dpc_start dpc_end dpc_current dpc_status dpc_clock dpc_bufbusy dpc_pipebusy dpc_tmem').split():
            p = p.upper()
        elif re.fullmatch(r'\d+', p) and mn in ('mfc0', 'mtc0') and k == 1:
            p = ['SP_MEM_ADDR', 'SP_DRAM_ADDR', 'SP_RD_LEN', 'SP_WR_LEN', 'SP_STATUS', 'SP_DMA_FULL', 'SP_DMA_BUSY',
                 'SP_SEMAPHORE', 'DPC_START', 'DPC_END', 'DPC_CURRENT', 'DPC_STATUS', 'DPC_CLOCK', 'DPC_BUFBUSY',
                 'DPC_PIPEBUSY', 'DPC_TMEM'][int(p)]
        else:
            m2 = re.fullmatch(r'(-?\d+)\((\w+)\)', p)
            if m2:
                p = '%s(%s)' % (m2.group(1), GH[NAMES.index(m2.group(2))])
            m3 = re.fullmatch(r'(v\d+)\[(\d+)\]', p)
        res.append(p)
    if mn == 'jalr' and len(res) == 2 and res[1] == 'ra':
        res = res[:1]                       # jalr rs,ra is printed as jalr rs
    if mn == 'vmacq':
        res = res[:1]                       # only vd is used
    return mn + ' ' + ','.join(res) if res else mn


bad = 0
ok = 0
for t, (w, n, g) in zip(forms, gh):
    s = norm(src_norm(t))
    gg = norm(g)
    # e=0 prints without brackets in both; vector ops with "[0]" element are e=8 (lane broadcast)
    if s == gg:
        ok += 1
    else:
        bad += 1
        if bad <= 15:
            print('DIFF', t, '|', g, '|', w)
print(f'{ok} of {len(forms)} assembler forms decode to the same text, {bad} differ')
sys.exit(1 if bad else 0)
