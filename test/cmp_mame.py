#!/usr/bin/env python3
"""cmp_mame.py <ghidra.txt> <mame.txt> [--show CLASS]: compare Ghidra with MAME unidasm (-arch rsp).

Both texts are parsed to a canonical form (register numbers, element numbers).  Every difference
falls in a named class; a run with unexplained differences exits 1."""
import collections, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rspnorm import *

gh = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[1])]
ma = [l.rstrip('\n').split(' ', 1) for l in open(sys.argv[2])]
show = sys.argv[sys.argv.index('--show') + 1] if '--show' in sys.argv else None
assert len(gh) == len(ma)

VEC3 = set('vmulf vmulu vrndp vmulq vmudl vmudm vmudn vmudh vmacf vmacu vrndn vmadl vmadm vmadn vmadh vadd vsub '
           'vabs vaddc vsubc vsar vlt veq vne vge vcl vch vcr vmrg vand vnand vor vnor vxor vnxor'.split())
SCALAR = set('vrcp vrcpl vrcph vmov vrsq vrsql vrsqh'.split())
LS = set('lbv lsv llv ldv lqv lrv lpv luv lhv lfv ltv sbv ssv slv sdv sqv srv spv suv shv sfv swv stv'.split())
BRANCH = set('j jal beq bne blez bgtz bltz bgez bltzal bgezal'.split())
RESERVED = set('vsut vaddb vsubb vaccb vsucb vsad vsac vsum vacc vsuc vextt vextq vextn vinst vinsq vinsn vzero'.split())
stats = collections.Counter()
ex = collections.defaultdict(list)


def cls(k, item):
    stats[k] += 1
    ex[k].append(item)


def elem(x, who, mn, dest=None):
    """-> canonical operand"""
    if x[0] != 'v' or x[2] is None:
        return x
    s = x[2]
    if who == 'gh' and s.startswith('0x'):
        s = str(int(s, 16))
    if mn in VEC3:
        table = GH_E if who == 'gh' else MAME_E
        return ('v', x[1], table.get(s, ('?', s)))
    if who == 'gh' and mn in SCALAR:
        return ('v', x[1], ('lane', int(s)) if s.isdigit() and x[1] == dest else GH_E.get(s, ('?', s)))
    return ('v', x[1], ('lane', int(s, 10)) if re.fullmatch(r'\d{1,2}', s) else ('?', s))


for (hw, hl, ht), (mw, mt) in zip(gh, ma):
    w = int(hw, 16)
    item = (hw, ht, mt)
    try:
        g = parse(ht)
    except Exception:
        cls('UNPARSED ghidra', item); continue
    try:
        m = parse(mt)
    except Exception:
        # MAME prints "???" in operand position for out-of-range COP0 registers
        if mt.startswith('vsaw') and g and g[0] == 'vsar' and g[1][0] == ('v', int(mt.split()[1].rstrip(',')[1:]), None):
            cls('explained: MAME spells VSAR "vsaw" and prints its source slice as ???', item)
        elif mt.startswith(('mfc0', 'mtc0')) and '???' in mt:
            cls('explained: MAME prints ??? for COP0 registers 16-31 (the RSP uses 4 bits)', item)
        else:
            cls('UNPARSED mame', item)
        continue
    if g is None and m is None:
        stats['both invalid'] += 1; continue
    if g is None:
        mn = m[0]
        if mn == 'lwv':
            cls('explained: MAME decodes LWC2 sub-opcode 10 (LWV); not present on the RSP', item)
        else:
            cls('UNEXPLAINED ghidra invalid, mame valid: ' + mn, item)
        continue
    if m is None:
        mn = g[0]
        if mn in RESERVED:
            cls('explained: function code the RSP does not implement (executes as VZERO)', item)
        elif mn == 'lwu':
            cls('explained: LWU is LW on the RSP; MAME does not decode it', item)
        elif mn in ('cfc2', 'ctc2', 'mfc0', 'mtc0'):
            cls('explained: register number beyond the RSP\'s (masked)', item)
        else:
            cls('UNEXPLAINED mame invalid, ghidra valid: ' + mn, item)
        continue
    gm, go = g
    mm, mo = m
    if gm in SCALAR and mm == gm:
        def lane_of(sx):
            return int(sx, 16) if sx.startswith('0x') else int(sx)
        e = (w >> 21) & 15
        d_ok = (go[0][1] == mo[0][1] and lane_of(go[0][2]) == lane_of(mo[0][2]) and go[1][1] == mo[1][1])
        if d_ok and e >= 8:
            if go[1][2] == str(e - 8) and lane_of(mo[1][2]) == e - 8:
                stats['exact'] += 1; continue
        elif d_ok:
            cls('explained: MAME prints another lane for the vt element when e < 8', item); continue
        cls('UNEXPLAINED %s/%s' % (gm, mm), item); continue
    go = [elem(x, 'gh', gm, go[0][1] if gm in SCALAR else None) for x in go]
    mo = [elem(x, 'ma', mm) for x in mo]
    if gm in BRANCH:
        go = [('n', x[1] & 0xFFF) if x[0] == 'n' else x for x in go]
    if mm in BRANCH:
        mo = [('n', x[1] & 0xFFF) if x[0] == 'n' else x for x in mo]
    if gm == mm and go == mo:
        stats['exact'] += 1; continue
    # ---- classes -------------------------------------------------------------------------------
    e = (w >> 21) & 15
    if gm == 'vsar' and mm == 'vsaw':
        if go[:2] == mo[:2]:
            cls('explained: MAME spells VSAR "vsaw" and prints the slice as ???', item); continue
    if gm in RESERVED and mm.startswith('v0') or gm in RESERVED and mm.startswith('vsut'):
        cls('explained: function code the RSP does not implement (MAME: vNNN / vsut???)', item); continue
    if gm == 'vzero' and mm.startswith('v'):
        cls('explained: function code the RSP does not implement (MAME: vNNN / vsut???)', item); continue
    if gm == mm == 'vmacq':
        cls('explained: VMACQ takes only vd; MAME also prints vs and vt', item); continue
    if gm == mm == 'lui' and len(mo) == 3:
        cls('explained: MAME prints LUI with a bogus rs operand', item); continue
    if gm == mm and gm in ('mfc2', 'mtc2'):
        # MAME takes the element from bits 10..6
        me = (w >> 6) & 31
        if mo[1][0] == 'v' and mo[1][2] == ('lane', me) and go[0] == mo[0] and go[1][1] == mo[1][1]:
            cls('explained: MAME reads the MFC2/MTC2 element from bits 10..6 (5 bits) instead of 10..7', item); continue
    if gm == mm and gm in SCALAR:
        # destination element must agree; MAME's source lane is only right for e >= 8
        if go[0] == mo[0] and (w >> 21) & 15 < 8:
            cls('explained: MAME prints another lane for the vt element when e < 8', item); continue
        if go[0] == mo[0] and e >= 8 and go[1][:2] == mo[1][:2] and go[1][2] == ('e', e) and mo[1][2] == ('lane', e - 8):
            stats['exact'] += 1; continue
    if gm == mm and gm in VEC3 and e == 1 and [x[:2] for x in go] == [x[:2] for x in mo]:
        cls('explained: e = 1 (same as 0); MAME prints [???]', item); continue
    if gm == mm == 'vsar':
        cls('UNEXPLAINED vsar', item); continue
    if gm == 'jalr' and mm == 'jalr':
        pass
    cls('UNEXPLAINED %s/%s' % (gm, mm), item)

un = 0
for k, v in sorted(stats.items(), key=lambda kv: -kv[1]):
    print(f"{v:8}  {k}")
    if k.startswith('UNEXPLAINED') or k.startswith('UNPARSED'):
        un += v
for k in ex:
    if k.startswith('UNEXPLAINED') or k.startswith('UNPARSED') or k == show:
        for it in ex[k][:3]:
            print('   ', k, it)
print('unexplained:', un)
sys.exit(1 if un else 0)
