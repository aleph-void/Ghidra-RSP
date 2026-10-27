#!/usr/bin/env python3
"""Deterministic corpora of 32-bit instruction words for the decode comparisons.

  gen_words.py structured <out>    every opcode/function/sub-opcode/element combination, with
                                   several register/immediate fillings each
  gen_words.py random <n> <seed> <out>
"""
import random
import sys


def structured():
    rnd = random.Random(12345)
    W = []

    def regs():
        return rnd.randrange(32), rnd.randrange(32), rnd.randrange(32)

    # every primary opcode, random remainder x4
    for op in range(64):
        for _ in range(4):
            W.append(op << 26 | rnd.getrandbits(26))
    # SPECIAL: every function x 4 fillings, plus rs/rt/rd/sa extremes
    for fn in range(64):
        for _ in range(6):
            W.append(rnd.getrandbits(26) << 6 | fn)
        for sa in (0, 31):
            W.append(rnd.randrange(32) << 21 | rnd.randrange(32) << 16 | rnd.randrange(32) << 11 | sa << 6 | fn)
    # REGIMM: every rt x 3
    for rt in range(32):
        for _ in range(3):
            W.append(1 << 26 | rnd.randrange(32) << 21 | rt << 16 | rnd.getrandbits(16))
    # COP0: every rs x rd
    for rs in range(32):
        for rd in range(32):
            W.append(0x10 << 26 | rs << 21 | rnd.randrange(32) << 16 | rd << 11 | rnd.getrandbits(11))
    # COP2 moves: every rs x element x a few
    for rs in range(16):
        for e in range(16):
            for _ in range(2):
                W.append(0x12 << 26 | rs << 21 | rnd.randrange(32) << 16 | rnd.randrange(32) << 11 | e << 7 | rnd.getrandbits(7))
    for rd in range(32):
        for rs in (2, 6):
            W.append(0x12 << 26 | rs << 21 | rnd.randrange(32) << 16 | rd << 11 | rnd.getrandbits(11))
    # vector computational: every fn x every e x 3 register fillings
    for fn in range(64):
        for e in range(16):
            for _ in range(3):
                vt, vs, vd = regs()
                W.append(0x12 << 26 | 1 << 25 | e << 21 | vt << 16 | vs << 11 | vd << 6 | fn)
    # LWC2 / SWC2: every sub-opcode x every element x offsets
    for op in (0x32, 0x3a):
        for sub in range(32):
            for e in range(16):
                for off in (0, 1, 0x3f, 0x40, 0x7f, rnd.randrange(128)):
                    W.append(op << 26 | rnd.randrange(32) << 21 | rnd.randrange(32) << 16 | sub << 11 | e << 7 | off)
    return W


def main():
    if sys.argv[1] == 'structured':
        W, out = structured(), sys.argv[2]
    else:
        n, seed, out = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
        rnd = random.Random(seed)
        W = [rnd.getrandbits(32) for _ in range(n)]
    with open(out, 'w') as f:
        for w in W:
            f.write(f"{w:08x}\n")
    print(f"{len(W)} words -> {out}")


main()
