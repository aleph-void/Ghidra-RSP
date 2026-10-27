#!/usr/bin/env python3
"""gen_sem_cases.py <out> <per-combination> <seed>: random single-instruction cases for the vector unit
(format: see ares/harness.cpp)."""
import random, sys

out, K, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rnd = random.Random(seed)
SPECIAL16 = [0, 1, 0xffff, 0x7fff, 0x8000, 0x8001, 0x7ffe, 2, 0xfffe, 0x00ff, 0xff00, 0x5555, 0xaaaa, 0x1234, 0xedcc]


def lane():
    return rnd.choice(SPECIAL16) if rnd.random() < 0.5 else rnd.getrandbits(16)


def vec():
    return ''.join('%04x' % lane() for _ in range(8))


def accvec(biased):
    return ''.join('%04x' % (lane() if biased else rnd.getrandbits(16)) for _ in range(8))


def state(mem_regs=False):
    s = []
    s += [vec() for _ in range(32)]
    mode = rnd.random()
    if mode < 0.3:      # small accumulator values: H is a sign extension of M
        acch, accm, accl = [], [], []
        for _ in range(8):
            m = lane()
            acch.append('%04x' % (0xffff if (m & 0x8000 and rnd.random() < 0.8) else 0))
            accm.append('%04x' % m); accl.append('%04x' % lane())
        s += [''.join(acch), ''.join(accm), ''.join(accl)]
    else:
        s += [accvec(True), accvec(True), accvec(True)]
    f = lambda: rnd.choice([0, 0xffff, rnd.getrandbits(16), rnd.getrandbits(16)])
    s += ['%04x' % f(), '%04x' % f(), '%02x' % rnd.choice([0, 0xff, rnd.getrandbits(8)])]
    s += ['%04x' % lane(), '%04x' % lane(), '%x' % rnd.getrandbits(1)]
    g = []
    for i in range(32):
        g.append('%08x' % (rnd.choice([0, 1, 0xffffffff, 0x7fff, 0x8000, rnd.getrandbits(32)]) if not mem_regs
                           else 0x200 + rnd.randrange(0, 0x40)))
    g[0] = '00000000'
    s += g
    s.append(''.join('%02x' % rnd.getrandbits(8) for _ in range(1280)))
    return s


W = []


def emit(word, mem=False):
    st = state(mem)
    W.append('%08x ' % word + ' '.join(st))


def r5(): return rnd.randrange(32)


# vector computational: every function x every e
for fn in range(64):
    for e in range(16):
        for _ in range(K):
            emit(0x12 << 26 | 1 << 25 | e << 21 | r5() << 16 | r5() << 11 | r5() << 6 | fn)
        # register aliasing: vd = vs = vt in all combinations
        for (a, b, c) in ((1, 1, 1), (1, 1, 2), (1, 2, 1), (2, 1, 1)):
            emit(0x12 << 26 | 1 << 25 | e << 21 | a << 16 | b << 11 | c << 6 | fn)
# register moves
for e in range(16):
    for _ in range(K):
        emit(0x12 << 26 | 0 << 21 | r5() << 16 | r5() << 11 | e << 7)
        emit(0x12 << 26 | 4 << 21 | r5() << 16 | r5() << 11 | e << 7)
for rd in range(4):
    for _ in range(K):
        emit(0x12 << 26 | 2 << 21 | r5() << 16 | rd << 11)
        emit(0x12 << 26 | 6 << 21 | r5() << 16 | rd << 11)
# loads and stores: base register holds 0x200..0x23f, offsets -32..31 (scaled)
for op in (0x32, 0x3a):
    for sub in range(12):
        if op == 0x32 and sub == 10:
            continue
        for e in range(16):
            for _ in range(K):
                imm = rnd.randrange(-32, 32) & 0x7f
                emit(op << 26 | r5() << 21 | r5() << 16 | sub << 11 | e << 7 | imm, mem=True)
open(out, 'w').write('\n'.join(W) + '\n')
print(len(W), 'cases')
