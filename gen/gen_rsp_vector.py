#!/usr/bin/env python3
"""Generates data/languages/rsp_vector.sinc: the RSP vector unit (COP2) in SLEIGH p-code.

Usage: gen_rsp_vector.py [output]     (default: ../data/languages/rsp_vector.sinc)

Vector registers are 16 bytes, big endian: lane (element) n is bits [(7-n)*16, 16] and byte k
is bits [(15-k)*8, 8].  Semantics follow the RSP's documented behaviour (see GHIDRA-RARE.md).
"""
import os, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'languages', 'rsp_vector.sinc')


def lane(n):          # bit offset of lane n (16 bits)
    return (7 - n) * 16


def byte(k):          # bit offset of byte k (8 bits)
    return (15 - k) * 8


class C:
    """One constructor under construction."""
    def __init__(s):
        s.lines = []
        s.n = 0

    def t(s, size, expr, name=None):
        if name is None:
            name = f"t{s.n}"
            s.n += 1
        s.lines.append(f"local {name}:{size} = {expr};")
        return name

    def a(s, text):
        s.lines.append(text)

    def body(s):
        return "\n".join("\t" + l for l in s.lines)


constructors = []


def cons(display, pattern, c):
    constructors.append(f":{display} is {pattern} {{\n{c.body()}\n}}")


# ---------------------------------------------------------------------------------------------
# Element (broadcast) selector for vector operations: vsel = bits 21-24
# ---------------------------------------------------------------------------------------------
BROADCAST = {
    0: [0, 1, 2, 3, 4, 5, 6, 7], 1: [0, 1, 2, 3, 4, 5, 6, 7],
    2: [0, 0, 2, 2, 4, 4, 6, 6], 3: [1, 1, 3, 3, 5, 5, 7, 7],
    4: [0, 0, 0, 0, 4, 4, 4, 4], 5: [1, 1, 1, 1, 5, 5, 5, 5],
    6: [2, 2, 2, 2, 6, 6, 6, 6], 7: [3, 3, 3, 3, 7, 7, 7, 7],
}
for e in range(8, 16):
    BROADCAST[e] = [e - 8] * 8
ENAME = {0: "", 1: "", 2: "[0q]", 3: "[1q]", 4: "[0h]", 5: "[1h]", 6: "[2h]", 7: "[3h]"}
for e in range(8, 16):
    ENAME[e] = f"[{e - 8}]"

head = []
for e in range(16):
    c = C()
    if e < 2:
        c.a("export vt_f;")
        disp = "vt_f"
    else:
        # note: the legacy EmulatorHelper cannot write sub-ranges of unique temporaries, so the
        # permuted vector is assembled with shifts and ORs instead of lane assignments
        terms = []
        for l in range(8):
            c.a(f"local p{l}:16 = zext(vt_f[{lane(BROADCAST[e][l])},16]);")
            terms.append(f"(p{l} << {lane(l)})")
        c.a("local r:16 = " + " | ".join(terms) + ";")
        c.a("export r;")
        disp = f'vt_f^"{ENAME[e]}"'
    head.append(f"vte: {disp} is vt_f & vsel={e} {{\n{c.body()}\n}}")


# ---------------------------------------------------------------------------------------------
# Helpers for lane arithmetic
# ---------------------------------------------------------------------------------------------
def sel(c, cond, a, b, size=2):
    """branch-free (cond ? a : b) for size-byte values; cond is a 1-byte bool local"""
    m = c.t(size, f"0 - zext({cond})")
    return c.t(size, f"({a} & {m}) | ({b} & ~{m})")


def clamp16(c, x32):
    """signed saturation of a 4-byte signed local to 16 bits (returns 2-byte local)"""
    hi = c.t(1, f"{x32} s> 0x7fff")
    lo = c.t(1, f"{x32} s< -0x8000")
    r = c.t(2, f"{x32}:2")
    r = sel(c, hi, "0x7fff", r)
    r = sel(c, lo, "0x8000", r)
    return r


def acc_load(c, l):
    h = c.t(8, f"sext(ACC_H[{lane(l)},16])")
    m = c.t(8, f"zext(ACC_M[{lane(l)},16])")
    lo = c.t(8, f"zext(ACC_L[{lane(l)},16])")
    return c.t(8, f"({h} << 32) | ({m} << 16) | {lo}")


def sext48(c, v):
    return c.t(8, f"({v} << 16) s>> 16")


def acc_store(c, v, l, parts="HML"):
    if "H" in parts:
        c.a(f"ACC_H[{lane(l)},16] = {v}[32,16];")
    if "M" in parts:
        c.a(f"ACC_M[{lane(l)},16] = {v}[16,16];")
    if "L" in parts:
        c.a(f"ACC_L[{lane(l)},16] = {v}[0,16];")


def flagbits(c, name_bits, shift0=0):
    """combine 1-byte bool locals (one per lane, lane order) into a 2-byte value; lane l -> bit l+shift0"""
    terms = []
    for l, b in enumerate(name_bits):
        if b is None:
            continue
        terms.append(f"(zext({b}) << {l + shift0})")
    if not terms:
        return c.t(2, "0")
    return c.t(2, " | ".join(terms))


def v3(mn, fnval, body, extra=None):
    """register one 'vd, vs, vte' op; body(c) emits p-code using helpers; vte copy in 'T'"""
    c = C()
    c.a("local T:16 = vte;")
    c.a("local S:16 = vs_f;")
    body(c)
    cons(f"{mn} vd_f, vs_f, vte", f"op=18 & bit25=1 & fn={fnval} & vd_f & vs_f & vte", c)


def L_S(l):
    return f"S[{lane(l)},16]"


def L_T(l):
    return f"T[{lane(l)},16]"


def lane_vals(c, l):
    s = c.t(4, f"sext({L_S(l)})")
    t = c.t(4, f"sext({L_T(l)})")
    return s, t


# --- multiplies -------------------------------------------------------------------------------
def clamp_vd(c, l, v, slice_m, neg_val, pos_val):
    """vd lane l = saturate(accumulator v (8-byte sext48)) taking slice M (True) or L"""
    pos = c.t(1, f"{v} s> 0x7fffffff")
    neg = c.t(1, f"{v} s< -0x80000000")
    r = c.t(2, f"ACC_M[{lane(l)},16]" if slice_m else f"ACC_L[{lane(l)},16]")
    r = sel(c, pos, str(pos_val), r)
    r = sel(c, neg, str(neg_val), r)
    c.a(f"vd_f[{lane(l)},16] = {r};")


def op_mulf(unsigned_, accumulate):
    def body(c):
        for l in range(8):
            s = c.t(8, f"sext({L_S(l)})")
            t = c.t(8, f"sext({L_T(l)})")
            p = c.t(8, f"{s} * {t} * 2")
            if accumulate:
                a = acc_load(c, l)
                v = c.t(8, f"{a} + {p}")
            else:
                v = c.t(8, f"{p} + 0x8000")
            v = sext48(c, v)
            acc_store(c, v, l)
            if not unsigned_:
                clamp_vd(c, l, v, True, "0x8000", "0x7fff")
            else:
                H = c.t(2, f"{v}[32,16]")
                M = c.t(2, f"{v}[16,16]")
                hneg = c.t(1, f"{H} s< 0")
                if not accumulate:
                    x = c.t(2, f"{H} ^ {M}")
                    ov = c.t(1, f"{x} s< 0")
                else:
                    hn = c.t(1, f"{H} != 0")
                    mn = c.t(1, f"{M} s< 0")
                    ov = c.t(1, f"{hn} || {mn}")
                r = sel(c, ov, "0xffff", M)
                r = sel(c, hneg, "0", r)
                c.a(f"vd_f[{lane(l)},16] = {r};")
    return body


def op_mud(kind, accumulate):
    # kind: 'l','m','n','h'
    def body(c):
        for l in range(8):
            if kind == 'h' and accumulate:
                # VMADH: (acc >> 16) + vs*vt, kept as H:M, L unchanged
                s, t = lane_vals(c, l)
                h = c.t(4, f"zext(ACC_H[{lane(l)},16])")
                m = c.t(4, f"zext(ACC_M[{lane(l)},16])")
                r = c.t(4, f"(({h} << 16) | {m}) + {s} * {t}")
                c.a(f"ACC_H[{lane(l)},16] = {r}[16,16];")
                c.a(f"ACC_M[{lane(l)},16] = {r}[0,16];")
                v = acc_load(c, l)
                clamp_vd(c, l, v, True, "0x8000", "0x7fff")
                continue
            if kind == 'l':
                s = c.t(4, f"zext({L_S(l)})")
                t = c.t(4, f"zext({L_T(l)})")
                p = c.t(4, f"({s} * {t}) >> 16")
                p8 = c.t(8, f"zext({p})")
            elif kind == 'm':
                s = c.t(4, f"sext({L_S(l)})")
                t = c.t(4, f"zext({L_T(l)})")
                p = c.t(4, f"{s} * {t}")
                p8 = c.t(8, f"sext({p})")
            elif kind == 'n':
                s = c.t(4, f"zext({L_S(l)})")
                t = c.t(4, f"sext({L_T(l)})")
                p = c.t(4, f"{s} * {t}")
                p8 = c.t(8, f"sext({p})")
            else:  # 'h' (VMUDH)
                s = c.t(4, f"sext({L_S(l)})")
                t = c.t(4, f"sext({L_T(l)})")
                p = c.t(4, f"{s} * {t}")
                p8 = c.t(8, f"sext({p})")
                p8 = c.t(8, f"{p8} << 16")
            if accumulate:
                a = acc_load(c, l)
                v = c.t(8, f"{a} + {p8}")
            else:
                v = p8
            v = sext48(c, v)
            acc_store(c, v, l)
            if kind == 'l':
                if accumulate:
                    clamp_vd(c, l, v, False, "0", "0xffff")
                else:
                    c.a(f"vd_f[{lane(l)},16] = ACC_L[{lane(l)},16];")
            elif kind == 'm':
                if accumulate:
                    clamp_vd(c, l, v, True, "0x8000", "0x7fff")
                else:
                    c.a(f"vd_f[{lane(l)},16] = ACC_M[{lane(l)},16];")
            elif kind == 'n':
                if accumulate:
                    clamp_vd(c, l, v, False, "0", "0xffff")
                else:
                    c.a(f"vd_f[{lane(l)},16] = ACC_L[{lane(l)},16];")
            else:
                clamp_vd(c, l, v, True, "0x8000", "0x7fff")
    return body


def op_mulq(c):
    for l in range(8):
        s, t = lane_vals(c, l)
        p = c.t(4, f"{s} * {t}")
        neg = c.t(1, f"{p} s< 0")
        p = c.t(4, f"{p} + (zext({neg}) * 31)")
        c.a(f"ACC_H[{lane(l)},16] = {p}[16,16];")
        c.a(f"ACC_M[{lane(l)},16] = {p}[0,16];")
        c.a(f"ACC_L[{lane(l)},16] = 0;")
        h = c.t(4, f"{p} s>> 1")
        r = clamp16(c, h)
        c.a(f"vd_f[{lane(l)},16] = {r} & 0xfff0;")


def op_macq(c):
    for l in range(8):
        h = c.t(4, f"zext(ACC_H[{lane(l)},16])")
        m = c.t(4, f"zext(ACC_M[{lane(l)},16])")
        p = c.t(4, f"({h} << 16) | {m}")
        neg = c.t(1, f"{p} s< 0")
        b5 = c.t(1, f"({p} & 0x20) != 0")
        nb5 = c.t(1, f"!{b5}")
        c1 = c.t(1, f"{neg} && {nb5}")
        ge = c.t(1, f"{p} s>= 32")
        nneg = c.t(1, f"!{neg}")
        c2a = c.t(1, f"{nneg} && {ge}")
        c2 = c.t(1, f"{c2a} && {nb5}")
        p = c.t(4, f"{p} + (zext({c1}) * 32) - (zext({c2}) * 32)")
        c.a(f"ACC_H[{lane(l)},16] = {p}[16,16];")
        c.a(f"ACC_M[{lane(l)},16] = {p}[0,16];")
        h2 = c.t(4, f"{p} s>> 1")
        r = clamp16(c, h2)
        c.a(f"vd_f[{lane(l)},16] = {r} & 0xfff0;")


def op_rnd(d, shift):
    def body(c):
        for l in range(8):
            t = c.t(8, f"sext({L_T(l)})")
            if shift:
                t = c.t(8, f"{t} << 16")
            a = sext48(c, acc_load(c, l))
            cond = c.t(1, f"{a} s< 0" if d == 0 else f"{a} s>= 0")
            add = c.t(8, f"{a} + {t}")
            add = sext48(c, add)
            v = sel(c, cond, add, a, 8)
            acc_store(c, v, l)
            sh8 = c.t(8, f"{v} s>> 16")
            sh = c.t(4, f"{sh8}:4")
            r = clamp16(c, sh)
            c.a(f"vd_f[{lane(l)},16] = {r};")
    return body


# --- adds -------------------------------------------------------------------------------------
def op_add(sub):
    def body(c):
        for l in range(8):
            s, t = lane_vals(c, l)
            f = c.t(4, f"zext(VCO[{l},1])")
            r = c.t(4, f"{s} - {t} - {f}" if sub else f"{s} + {t} + {f}")
            c.a(f"ACC_L[{lane(l)},16] = {r}[0,16];")
            v = clamp16(c, r)
            c.a(f"vd_f[{lane(l)},16] = {v};")
        c.a("VCO = 0;")
    return body


def op_abs(c):
    for l in range(8):
        s = c.t(2, L_S(l))
        t = c.t(2, L_T(l))
        neg = c.t(1, f"{s} s< 0")
        pos = c.t(1, f"{s} s> 0")
        nt = c.t(2, f"0 - {t}")
        r = sel(c, pos, t, "0")
        r = sel(c, neg, nt, r)
        c.a(f"ACC_L[{lane(l)},16] = {r};")
        mn = c.t(1, f"{t} == 0x8000")
        sp = c.t(1, f"{neg} && {mn}")
        v = c.t(2, f"{r} - zext({sp})")
        c.a(f"vd_f[{lane(l)},16] = {v};")


def op_addc(c):
    bits = []
    for l in range(8):
        s = c.t(4, f"zext({L_S(l)})")
        t = c.t(4, f"zext({L_T(l)})")
        r = c.t(4, f"{s} + {t}")
        c.a(f"ACC_L[{lane(l)},16] = {r}[0,16];")
        c.a(f"vd_f[{lane(l)},16] = {r}[0,16];")
        bits.append(c.t(1, f"{r}[16,1]"))
    v = flagbits(c, bits)
    c.a(f"VCO = {v};")


def op_subc(c):
    lo, hi = [], []
    for l in range(8):
        s = c.t(4, f"zext({L_S(l)})")
        t = c.t(4, f"zext({L_T(l)})")
        r = c.t(4, f"{s} - {t}")
        c.a(f"ACC_L[{lane(l)},16] = {r}[0,16];")
        c.a(f"vd_f[{lane(l)},16] = {r}[0,16];")
        lo.append(c.t(1, f"{s} < {t}"))
        hi.append(c.t(1, f"{r} != 0"))
    a = flagbits(c, lo)
    b = flagbits(c, hi, 8)
    c.a(f"VCO = {a} | {b};")


def op_logic(expr):
    def body(c):
        for l in range(8):
            r = c.t(2, expr.format(s=L_S(l), t=L_T(l)))
            c.a(f"ACC_L[{lane(l)},16] = {r};")
            c.a(f"vd_f[{lane(l)},16] = {r};")
    return body


# --- compare / select ---------------------------------------------------------------------------
def cmp_flags(c, ccl_bits, clear_all=True):
    v = flagbits(c, ccl_bits)
    c.a(f"VCC = {v};")
    c.a("VCO = 0;")


def op_cmp(kind):
    def body(c):
        bits = []
        for l in range(8):
            s = c.t(2, L_S(l))
            t = c.t(2, L_T(l))
            eq = c.t(1, f"{s} == {t}")
            co = c.t(1, f"VCO[{l},1]")
            ch = c.t(1, f"VCO[{8 + l},1]")
            if kind == 'lt':
                lt = c.t(1, f"{s} s< {t}")
                both = c.t(1, f"{co} && {ch}")
                e2 = c.t(1, f"{eq} && {both}")
                cond = c.t(1, f"{lt} || {e2}")
            elif kind == 'eq':
                nch = c.t(1, f"!{ch}")
                cond = c.t(1, f"{nch} && {eq}")
            elif kind == 'ne':
                ne = c.t(1, f"!{eq}")
                cond = c.t(1, f"{ne} || {ch}")
            else:  # ge
                gt = c.t(1, f"{s} s> {t}")
                both = c.t(1, f"{co} && {ch}")
                nb = c.t(1, f"!{both}")
                e2 = c.t(1, f"{eq} && {nb}")
                cond = c.t(1, f"{gt} || {e2}")
            r = sel(c, cond, s, t)
            c.a(f"ACC_L[{lane(l)},16] = {r};")
            c.a(f"vd_f[{lane(l)},16] = {r};")
            bits.append(cond)
        cmp_flags(c, bits)
    return body


def op_merge(c):
    for l in range(8):
        s = c.t(2, L_S(l))
        t = c.t(2, L_T(l))
        cc = c.t(1, f"VCC[{l},1]")
        r = sel(c, cc, s, t)
        c.a(f"ACC_L[{lane(l)},16] = {r};")
        c.a(f"vd_f[{lane(l)},16] = {r};")
    c.a("VCO = 0;")


def op_ch(c):
    cch, ccl, vco_l, vco_h, vce = [], [], [], [], []
    for l in range(8):
        s = c.t(2, L_S(l))
        t = c.t(2, L_T(l))
        x = c.t(2, f"{s} ^ {t}")
        sg = c.t(1, f"{x} s< 0")
        nt = c.t(2, f"0 - {t}")
        nvt = sel(c, sg, nt, t)
        diff = c.t(2, f"{s} - {nvt}")
        d0 = c.t(1, f"{diff} == 0")
        vtn = c.t(1, f"{t} s< 0")
        dgz = c.t(1, f"{diff} s> 0")
        dlez = c.t(1, f"!{dgz}")
        dgez = c.t(1, f"{diff} s>= 0")
        ch_ = c.t(1, f"({sg} && {vtn}) || (!{sg} && {dgez})")
        cl_ = c.t(1, f"({sg} && {dlez}) || (!{sg} && {vtn})")
        ce_ = c.t(1, f"{sg} && ({diff} == 0xffff)")
        d0e = c.t(1, f"{d0} || {ce_}")
        oh = c.t(1, f"!{d0e}")
        mask = c.t(1, f"({sg} && {cl_}) || (!{sg} && {ch_})")
        r = sel(c, mask, nvt, s)
        c.a(f"ACC_L[{lane(l)},16] = {r};")
        c.a(f"vd_f[{lane(l)},16] = {r};")
        cch.append(ch_); ccl.append(cl_); vco_l.append(sg); vco_h.append(oh); vce.append(ce_)
    c.a(f"VCC = {flagbits(c, ccl)} | {flagbits(c, cch, 8)};")
    c.a(f"VCO = {flagbits(c, vco_l)} | {flagbits(c, vco_h, 8)};")
    c.a(f"VCE = {flagbits(c, vce)}:1;")


def op_cl(c):
    cch, ccl = [], []
    for l in range(8):
        s = c.t(2, L_S(l))
        t = c.t(2, L_T(l))
        co = c.t(1, f"VCO[{l},1]")
        ch = c.t(1, f"VCO[{8 + l},1]")
        ce = c.t(1, f"VCE[{l},1]")
        ccl0 = c.t(1, f"VCC[{l},1]")
        cch0 = c.t(1, f"VCC[{8 + l},1]")
        nt = c.t(2, f"0 - {t}")
        nvt = sel(c, co, nt, t)
        diff = c.t(2, f"{s} - {nvt}")
        s4 = c.t(4, f"zext({s})")
        t4 = c.t(4, f"zext({t})")
        sm = c.t(4, f"{s4} + {t4}")
        ncarry = c.t(1, f"{sm} <= 0xffff")
        d0 = c.t(1, f"{diff} == 0")
        nce = c.t(1, f"!{ce}")
        a1 = c.t(1, f"{d0} && {ncarry}")
        lec1 = c.t(1, f"{nce} && {a1}")
        o2 = c.t(1, f"{d0} || {ncarry}")
        lec2 = c.t(1, f"{ce} && {o2}")
        leeq = c.t(1, f"{lec1} || {lec2}")
        geeq = c.t(1, f"{t} <= {s}")
        nch = c.t(1, f"!{ch}")
        usele = c.t(1, f"{co} && {nch}")
        le = c.t(1, f"({usele} && {leeq}) || (!{usele} && {ccl0})")
        usege = c.t(1, f"{co} || {ch}")
        ge = c.t(1, f"({usege} && {cch0}) || (!{usege} && {geeq})")
        mask = c.t(1, f"({co} && {le}) || (!{co} && {ge})")
        r = sel(c, mask, nvt, s)
        c.a(f"ACC_L[{lane(l)},16] = {r};")
        c.a(f"vd_f[{lane(l)},16] = {r};")
        cch.append(ge); ccl.append(le)
    c.a(f"VCC = {flagbits(c, ccl)} | {flagbits(c, cch, 8)};")
    c.a("VCO = 0;")
    c.a("VCE = 0;")


def op_cr(c):
    cch, ccl = [], []
    for l in range(8):
        s = c.t(2, L_S(l))
        t = c.t(2, L_T(l))
        x = c.t(2, f"{s} ^ {t}")
        sg = c.t(1, f"{x} s< 0")
        sm = c.t(2, f"0 - zext({sg})")
        dl = c.t(2, f"({s} & {sm}) + {t}")
        ccl_ = c.t(1, f"{dl} s< 0")
        dg = c.t(2, f"{s} | {sm}")
        cch_ = c.t(1, f"{t} s<= {dg}")
        nvt = c.t(2, f"{t} ^ {sm}")
        mask = c.t(1, f"({sg} && {ccl_}) || (!{sg} && {cch_})")
        r = sel(c, mask, nvt, s)
        c.a(f"ACC_L[{lane(l)},16] = {r};")
        c.a(f"vd_f[{lane(l)},16] = {r};")
        cch.append(cch_); ccl.append(ccl_)
    c.a(f"VCC = {flagbits(c, ccl)} | {flagbits(c, cch, 8)};")
    c.a("VCO = 0;")
    c.a("VCE = 0;")


def op_zero(c):
    for l in range(8):
        r = c.t(2, f"{L_S(l)} + {L_T(l)}")
        c.a(f"ACC_L[{lane(l)},16] = {r};")
        c.a(f"vd_f[{lane(l)},16] = 0;")


# --- reciprocal unit ----------------------------------------------------------------------------
def div_body(c, rsq, low, high):
    """VRCP/VRSQ and their L/H forms; one lane of vt chosen by vsel&7, result lane vd[de]"""
    c.a("local T:16 = vte;")
    c.a("local VTR:16 = vt_f;")
    c.a(f"local ln:16 = VTR >> ((7 - (vsel & 7)) * 16);")
    c.a("local inl:2 = ln:2;")
    c.a("local dsh:4 = (7 - dsel) * 16;")
    if high:
        c.a("ACC_L = T;")
        c.a("DIVDP = 1;")
        c.a("DIVIN = inl;")
        c.a("local o:16 = zext(DIVOUT);")
        c.a("local m:16 = 0xffff;")
        c.a("m = m << dsh;")
        c.a("o = o << dsh;")
        c.a("vd_f = (vd_f & ~m) | o;")
        return
    # input
    c.a("local input:4 = sext(inl);")
    if low:
        c.a("if (DIVDP == 0) goto <lb_plain>;")
        c.a("local hi4:4 = zext(DIVIN);")
        c.a("local lo4:4 = zext(inl);")
        c.a("input = (hi4 << 16) | lo4;")
        c.a("<lb_plain>")
    c.a("local mask:4 = input s>> 31;")
    c.a("local data:4 = input ^ mask;")
    c.a("if (input s<= -32768) goto <lb_nosub>;")
    c.a("data = data - mask;")
    c.a("<lb_nosub>")
    c.a("local result:4 = 0;")
    c.a("if (data == 0) goto <lb_zero>;")
    c.a("if (input == -32768) goto <lb_minval>;")
    c.a("local shift:4 = lzcount(data);")
    c.a("local data8:8 = zext(data);")
    c.a("local sh8:8 = zext(shift);")
    c.a("local idx:8 = ((data8 << sh8) & 0x7fc00000) >> 22;")
    if not rsq:
        c.a("local tab:8;")
        c.a("if (idx == 0) goto <lb_tab0>;")
        c.a("local q:8 = 0x400000000 / (idx + 512);")
        c.a("tab = ((q + 1) >> 8) & 0xffff;")
        c.a("goto <lb_gottab>;")
        c.a("<lb_tab0>")
        c.a("tab = 0xffff;")
        c.a("<lb_gottab>")
        c.a("local tab4:4 = tab:4;")
        c.a("result = ((0x10000 | tab4) << 14);")
        c.a("result = (result >> (31 - shift)) ^ mask;")
    else:
        c.a("local ti:8 = (idx & 0x1fe) | zext(shift & 1);")
        c.a("local a:8 = (ti + 512) >> (ti & 1);")
        c.a("local b:8 = 0;")
        c.a("local bit:8 = 0x40000;")
        c.a("<lb_loop>")
        c.a("local tt:8 = b | bit;")
        c.a("local sq:8 = a * tt * tt;")
        c.a("if (sq >= 0x100000000000) goto <lb_skip>;")
        c.a("b = tt;")
        c.a("<lb_skip>")
        c.a("bit = bit >> 1;")
        c.a("if (bit != 0) goto <lb_loop>;")
        c.a("local tb:8 = (b >> 1) & 0xffff;")
        c.a("local tab:4 = tb:4;")
        c.a("result = ((0x10000 | tab) << 14);")
        c.a("result = (result >> ((31 - shift) >> 1)) ^ mask;")
    c.a("goto <lb_done>;")
    c.a("<lb_zero>")
    c.a("result = 0x7fffffff;")
    c.a("goto <lb_done>;")
    c.a("<lb_minval>")
    c.a("result = 0xffff0000;")
    c.a("<lb_done>")
    c.a("DIVDP = 0;")
    c.a("local ro:4 = result s>> 16;")
    c.a("DIVOUT = ro:2;")
    c.a("ACC_L = T;")
    c.a("local rlow:2 = result:2;")
    c.a("local o:16 = zext(rlow);")
    c.a("local m:16 = 0xffff;")
    c.a("m = m << dsh;")
    c.a("o = o << dsh;")
    c.a("vd_f = (vd_f & ~m) | o;")


# ---------------------------------------------------------------------------------------------
# Emit the computational instructions
# ---------------------------------------------------------------------------------------------
v3("vmulf", 0x00, op_mulf(False, False))
v3("vmulu", 0x01, op_mulf(True, False))
v3("vmulq", 0x03, op_mulq)
v3("vmudl", 0x04, op_mud('l', False))
v3("vmudm", 0x05, op_mud('m', False))
v3("vmudn", 0x06, op_mud('n', False))
v3("vmudh", 0x07, op_mud('h', False))
v3("vmacf", 0x08, op_mulf(False, True))
v3("vmacu", 0x09, op_mulf(True, True))
v3("vmadl", 0x0c, op_mud('l', True))
v3("vmadm", 0x0d, op_mud('m', True))
v3("vmadn", 0x0e, op_mud('n', True))
v3("vmadh", 0x0f, op_mud('h', True))
v3("vadd", 0x10, op_add(False))
v3("vsub", 0x11, op_add(True))
v3("vabs", 0x13, op_abs)
v3("vaddc", 0x14, op_addc)
v3("vsubc", 0x15, op_subc)
v3("vlt", 0x20, op_cmp('lt'))
v3("veq", 0x21, op_cmp('eq'))
v3("vne", 0x22, op_cmp('ne'))
v3("vge", 0x23, op_cmp('ge'))
v3("vcl", 0x24, op_cl)
v3("vch", 0x25, op_ch)
v3("vcr", 0x26, op_cr)
v3("vmrg", 0x27, op_merge)
v3("vand", 0x28, op_logic("{s} & {t}"))
v3("vnand", 0x29, op_logic("~({s} & {t})"))
v3("vor", 0x2a, op_logic("{s} | {t}"))
v3("vnor", 0x2b, op_logic("~({s} | {t})"))
v3("vxor", 0x2c, op_logic("{s} ^ {t}"))
v3("vnxor", 0x2d, op_logic("~({s} ^ {t})"))

# VMACQ: no operands besides vd
c = C()
op_macq(c)
cons("vmacq vd_f", "op=18 & bit25=1 & fn=0x0b & vd_f", c)

# VRNDP / VRNDN: the shift depends on bit 0 of the vs field number
for mn, fnv, d in (("vrndp", 0x02, 1), ("vrndn", 0x0a, 0)):
    for b in (0, 1):
        c = C()
        c.a("local T:16 = vte;")
        op_rnd(d, b)(c)
        cons(f"{mn} vd_f, vs_f, vte", f"op=18 & bit25=1 & fn={fnv} & vd_f & vs_f & vsb0={b} & vte", c)

# VSAR: e selects the accumulator slice
for e, reg in ((8, "ACC_H"), (9, "ACC_M"), (10, "ACC_L")):
    c = C()
    c.a(f"vd_f = {reg};")
    cons("vsar vd_f, vs_f, vte", f"op=18 & bit25=1 & fn=0x1d & vsel={e} & vd_f & vs_f & vte", c)
c = C()
c.a("vd_f = 0;")
cons("vsar vd_f, vs_f, vte", "op=18 & bit25=1 & fn=0x1d & vd_f & vs_f & vte", c)

# Reciprocal unit
for mn, fnv, rsq, low, high in (("vrcp", 0x30, False, False, False), ("vrcpl", 0x31, False, True, False),
                                ("vrcph", 0x32, False, False, True), ("vrsq", 0x34, True, False, False),
                                ("vrsql", 0x35, True, True, False), ("vrsqh", 0x36, True, False, True)):
    c = C()
    div_body(c, rsq, low, high)
    # the source lane is vsel & 7 whatever vsel is (bit 3 and the broadcast patterns do not matter)
    cons(f'{mn} vd_f^"["^dsel^"]", vt_f^"["^esel^"]"', f"op=18 & bit25=1 & fn={fnv} & vd_f & dsel & vt_f & esel & vsel & vte", c)

# VMOV: vd[de] = vte[de]
c = C()
c.a("local T:16 = vte;")
c.a("local dsh:4 = (7 - dsel) * 16;")
c.a("local ln:16 = T >> dsh;")
c.a("ACC_L = T;")
c.a("local o:16 = zext(ln:2);")
c.a("local m:16 = 0xffff;")
c.a("m = m << dsh;")
c.a("o = o << dsh;")
c.a("vd_f = (vd_f & ~m) | o;")
cons('vmov vd_f^"["^dsel^"]", vte', "op=18 & bit25=1 & fn=0x33 & vd_f & dsel & vt_f & vsel & vte", c)

# nops
cons("vnop", "op=18 & bit25=1 & fn=0x37", C())
cons("vnull", "op=18 & bit25=1 & fn=0x3f", C())

# Function codes the hardware does not implement. They behave alike: ACC_L = vs + vte (lane-wise),
# vd = 0. The mnemonics are those commonly used for the unimplemented slots.
RESERVED = {0x12: "vsut", 0x16: "vaddb", 0x17: "vsubb", 0x18: "vaccb", 0x19: "vsucb", 0x1a: "vsad",
            0x1b: "vsac", 0x1c: "vsum", 0x1e: "vacc", 0x1f: "vsuc", 0x2e: "vzero", 0x2f: "vzero",
            0x38: "vextt", 0x39: "vextq", 0x3a: "vextn", 0x3b: "vzero", 0x3c: "vinst", 0x3d: "vinsq",
            0x3e: "vinsn"}
for fnv, mn in sorted(RESERVED.items()):
    v3(mn, fnv, op_zero)

# ---------------------------------------------------------------------------------------------
# COP2 register moves
# ---------------------------------------------------------------------------------------------
for e in range(16):
    c = C()
    c.a(f"local r:16 = (vs_f << {8 * e}) | (vs_f >> {128 - 8 * e});" if e else "local r:16 = vs_f;")
    c.a("local x:2 = r(14);")
    c.a("wrt = sext(x);")
    cons(f'mfc2 wrt, vs_f^"[{e}]"', f"op=18 & rs_f=0 & lsel={e} & wrt & vs_f", c)
for e in range(16):
    c = C()
    c.a("local t:4 = rt;")
    if e < 15:
        c.a(f"vs_f[{byte(e) - 8},16] = t:2;")
    else:
        c.a(f"vs_f[0,8] = t[8,8];")
    cons(f'mtc2 rt, vs_f^"[{e}]"', f"op=18 & rs_f=4 & lsel={e} & rt & vs_f", c)
for r, reg, nm in ((0, "VCO", "VCO"), (1, "VCC", "VCC"), (2, "VCE", "VCE"), (3, "VCE", "VCE")):
    c = C()
    if reg == "VCE":
        c.a(f"wrt = zext({reg});")
    else:
        c.a(f"wrt = sext({reg});")
    cons(f'cfc2 wrt, "{nm}"', f"op=18 & rs_f=2 & cr2={r} & wrt", c)
    c = C()
    c.a("local t:4 = rt;")
    c.a(f"{reg} = t:{1 if reg == 'VCE' else 2};")
    cons(f'ctc2 rt, "{nm}"', f"op=18 & rs_f=6 & cr2={r} & rt", c)

# ---------------------------------------------------------------------------------------------
# Vector loads and stores (LWC2 = op 0x32, SWC2 = op 0x3a); lsop = bits 11-15, lsel = bits 7-10
# ---------------------------------------------------------------------------------------------
LOADS = {}
STORES = {}


def ls_cons(mn, opc, lsop, scale, body, per_e=None, extra_pat=""):
    """emit the instruction(s); body(c, e) gets e as int when per_e is a range, else None (field)"""
    if per_e is None:
        c = C()
        c.a(f"local a:4 = ofs{scale};")
        body(c, None)
        cons(f'{mn} vt_f^"["^lsel^"]", ofs{scale}', f"op={opc} & lsop={lsop} & vt_f & lsel & ofs{scale}{extra_pat}", c)
        return
    for e in per_e:
        c = C()
        c.a(f"local a:4 = ofs{scale};")
        body(c, e)
        cons(f'{mn} vt_f^"[{e}]", ofs{scale}', f"op={opc} & lsop={lsop} & lsel={e} & vt_f & ofs{scale}{extra_pat}", c)


def seq_load(n):
    def body(c, e):
        cnt = min(n, 16 - e)
        if cnt == n:
            c.a(f"vt_f[{byte(e + n - 1)},{8 * n}] = *[ram]:{n} a;")
        else:
            for j in range(cnt):
                c.a(f"vt_f[{byte(e + j)},8] = *[ram]:1 ((a + {j}) & 0xFFF);")
    return body


def seq_store(n):
    def body(c, e):
        c.a("local r:16 = vt_f;")
        if e:
            c.a(f"r = (vt_f << {8 * e}) | (vt_f >> {128 - 8 * e});")
        c.a(f"*[ram]:{n} a = r({16 - n});")
    return body


for mn, lop, n in (("lbv", 0, 1), ("lsv", 1, 2), ("llv", 2, 4), ("ldv", 3, 8)):
    ls_cons(mn, 0x32, lop, n, seq_load(n), per_e=range(16))
for mn, sop, n in (("sbv", 0, 1), ("ssv", 1, 2), ("slv", 2, 4), ("sdv", 3, 8)):
    ls_cons(mn, 0x3a, sop, n, seq_store(n), per_e=range(16))


# LQV / LRV / SQV / SRV: block merges (address aligned down to 16)
def lqv(c, e):
    c.a("local sh:4 = a & 15;")
    c.a("local blk:4 = a & 0xFFF0;")
    c.a("local B:16 = *[ram]:16 blk;")
    c.a("local ones:16 = ~0;")
    c.a("local T:16 = (B << (sh * 8)) >> (lsel * 8);")
    c.a("local M:16 = (ones << (sh * 8)) >> (lsel * 8);")
    c.a("vt_f = (vt_f & ~M) | (T & M);")


def lrv(c, e):
    c.a("local sh:4 = a & 15;")
    c.a("local blk:4 = a & 0xFFF0;")
    c.a("local B:16 = *[ram]:16 blk;")
    c.a("local ones:16 = ~0;")
    c.a("local st:4 = (16 - sh + lsel) * 8;")
    c.a("local T:16 = B >> st;")
    c.a("local M:16 = ones >> st;")
    c.a("vt_f = (vt_f & ~M) | (T & M);")


def sqrv(c, e, right):
    c.a("local sh:4 = a & 15;")
    c.a("local blk:4 = a & 0xFFF0;")
    c.a("local B:16 = *[ram]:16 blk;")
    c.a("local ones:16 = ~0;")
    c.a("local rot:4 = (sh - lsel) & 15;")
    c.a("local S:16 = (vt_f >> (rot * 8)) | (vt_f << (128 - rot * 8));")
    c.a("local M:16 = ones >> (sh * 8);")
    if not right:
        c.a("B = (B & ~M) | (S & M);")
    else:
        c.a("B = (B & M) | (S & ~M);")
    c.a("*[ram]:16 blk = B;")


ls_cons("lqv", 0x32, 4, 16, lqv)
ls_cons("lrv", 0x32, 5, 16, lrv)
ls_cons("sqv", 0x3a, 4, 16, lambda c, e: sqrv(c, e, False))
ls_cons("srv", 0x3a, 5, 16, lambda c, e: sqrv(c, e, True))


# LPV / LUV / LHV / LFV
def packed_load(step, shift, wide_fv=False):
    def body(c, e):
        c.a("local idx:4 = (a & 7) - lsel;")
        c.a("local blk:4 = a & 0xFFF8;")
        if not wide_fv:
            for o in range(8):
                c.a(f"local x{o}:2 = zext(*[ram]:1 ((blk + ((idx + {o * step}) & 15)) & 0xFFF));")
                c.a(f"vt_f[{lane(o)},16] = x{o} << {shift};")
        else:
            terms = []
            for o in range(4):
                c.a(f"local xa{o}:2 = zext(*[ram]:1 ((blk + ((idx + {o * 4}) & 15)) & 0xFFF));")
                c.a(f"local xb{o}:2 = zext(*[ram]:1 ((blk + ((idx + {o * 4 + 8}) & 15)) & 0xFFF));")
                c.a(f"local ya{o}:16 = zext(xa{o} << 7);")
                c.a(f"local yb{o}:16 = zext(xb{o} << 7);")
                terms.append(f"(ya{o} << {lane(o)})")
                terms.append(f"(yb{o} << {lane(o + 4)})")
            c.a("local tmp:16 = " + " | ".join(terms) + ";")
            c.a("local ones:16 = ~0;")
            c.a("local M:16 = (ones >> (lsel * 8)) & ~(ones >> ((lsel + 8) * 8));")
            c.a("vt_f = (vt_f & ~M) | (tmp & M);")
    return body


ls_cons("lpv", 0x32, 6, 8, packed_load(1, 8))
ls_cons("luv", 0x32, 7, 8, packed_load(1, 7))
ls_cons("lhv", 0x32, 8, 16, packed_load(2, 7))
ls_cons("lfv", 0x32, 9, 16, packed_load(4, 7, True))


# SPV / SUV: per-e constructors (static byte selection)
def pack_store(unsigned_):
    def body(c, e):
        vals = []
        for j in range(8):
            o = e + j
            m = o & 7
            if (o & 15) < 8:
                first = True
            else:
                first = False
            if unsigned_:
                first = not first
            if first:       # byte (m*2) of vt (the high byte of lane m)
                vals.append(f"vt_f[{byte(m * 2)},8]")
            else:           # (lane m >> 7) & 0xff
                vals.append(f"vt_f[{lane(m) + 7},8]")
        terms = []
        for j, x in enumerate(vals):
            c.a(f"local q{j}:8 = zext({x});")
            terms.append(f"(q{j} << {(7 - j) * 8})")
        c.a("local v:8 = " + " | ".join(terms) + ";")
        c.a("*[ram]:8 a = v;")
    return body


ls_cons("spv", 0x3a, 6, 8, pack_store(False), per_e=range(16))
ls_cons("suv", 0x3a, 7, 8, pack_store(True), per_e=range(16))


def shv(c, e):
    c.a("local idx:4 = a & 7;")
    c.a("local blk:4 = a & 0xFFF8;")
    for o in range(8):
        b0, b1 = (e + o * 2) & 15, (e + o * 2 + 1) & 15
        c.a(f"local w{o}:2 = (zext(vt_f[{byte(b0)},8]) << 8) | zext(vt_f[{byte(b1)},8]);")
        c.a(f"*[ram]:1 ((blk + ((idx + {o * 2}) & 15)) & 0xFFF) = w{o}[7,8];")


ls_cons("shv", 0x3a, 8, 16, shv, per_e=range(16))

SFV = {0: (0, 1, 2, 3), 15: (0, 1, 2, 3), 1: (6, 7, 4, 5), 4: (1, 2, 3, 0), 5: (7, 4, 5, 6),
       8: (4, 5, 6, 7), 11: (3, 0, 1, 2), 12: (5, 6, 7, 4)}


def sfv(c, e):
    c.a("local base:4 = a & 7;")
    c.a("local blk:4 = a & 0xFFF8;")
    for k in range(4):
        if e in SFV:
            c.a(f"*[ram]:1 ((blk + ((base + {k * 4}) & 15)) & 0xFFF) = vt_f[{lane(SFV[e][k]) + 7},8];")
        else:
            c.a(f"*[ram]:1 ((blk + ((base + {k * 4}) & 15)) & 0xFFF) = 0;")


ls_cons("sfv", 0x3a, 9, 16, sfv, per_e=range(16))


def swv(c, e):
    c.a("local base:4 = a & 7;")
    c.a("local blk:4 = a & 0xFFF8;")
    for j in range(16):
        c.a(f"*[ram]:1 ((blk + ((base + {j}) & 15)) & 0xFFF) = vt_f[{byte((e + j) & 15)},8];")


ls_cons("swv", 0x3a, 10, 16, swv, per_e=range(16))

REGS = [f"v{i}" for i in range(32)]

# LTV / STV: touch the eight registers of vt's group. One constructor per (group, e>>1).
for g in range(4):
    for h in range(8):
        # LTV
        c = C()
        c.a("local a:4 = ofs16;")
        c.a("local begin:4 = a & 0xFFF8;")
        c.a("local st:4 = (lsel + (a & 8)) & 15;")
        for i in range(8):
            r = REGS[g * 8 + ((h + i) & 7)]
            for b in range(2):
                c.a(f"{r}[{byte(i * 2 + b)},8] = *[ram]:1 ((begin + ((st + {i * 2 + b}) & 15)) & 0xFFF);")
        cons('ltv vt_f^"["^lsel^"]", ofs16', f"op=0x32 & lsop=11 & vtgrp={g} & lsel_h={h} & vt_f & lsel & ofs16", c)
        # STV
        c = C()
        c.a("local a:4 = ofs16;")
        c.a("local blk:4 = a & 0xFFF8;")
        c.a("local base:4 = (a & 7) - (lsel & 14);")
        c.a("local el:4 = 16 - (lsel & 14);")
        for r in range(8):
            reg = REGS[g * 8 + r]
            for b in range(2):
                k = r * 2 + b
                c.a(f"local sx{k}:16 = {reg} >> ((15 - ((el + {k}) & 15)) * 8);")
                c.a(f"local sy{k}:1 = sx{k}:1;")
                c.a(f"*[ram]:1 ((blk + ((base + {k}) & 15)) & 0xFFF) = sy{k};")
        cons('stv vt_f^"["^lsel^"]", ofs16', f"op=0x3a & lsop=11 & vtgrp={g} & lsel_h={h} & vt_f & lsel & ofs16", c)

# ---------------------------------------------------------------------------------------------
# write the file
# ---------------------------------------------------------------------------------------------
pre = """# GENERATED by gen/gen_rsp_vector.py: do not edit.  RSP vector unit (COP2) and LWC2/SWC2.

# Effective address of vector loads/stores: base + (7-bit signed offset scaled by the access size),
# wrapped into DMEM.
"""
for scale in (1, 2, 4, 8, 16):
    pre += f'ofs{scale}: pos^"("^rs^")" is rs & loff & lneg=0 [ pos = loff * {scale}; ] {{ local a:4 = (rs + (loff * {scale})) & 0xFFF; export a; }}\n'
    pre += f'ofs{scale}: "-"^neg^"("^rs^")" is rs & loff & lneg=1 [ neg = (0 - loff) * {scale}; ] {{ local a:4 = (rs + (loff * {scale})) & 0xFFF; export a; }}\n'
pre += "\n"
with open(OUT, 'w') as f:
    f.write(pre)
    f.write("\n".join(head) + "\n\n")
    f.write("\n".join(constructors) + "\n")
print(f"wrote {OUT}: {len(constructors)} constructors")
