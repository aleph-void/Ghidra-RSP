"""Canonical forms of RSP disassembly text from Ghidra, MAME unidasm and armips-style syntax."""
import re

MIPS_NAMES = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
              's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']
GH_NAMES = ['zero'] + [f'r{i}' for i in range(1, 29)] + ['sp', 'r30', 'ra']
COP0 = ['SP_MEM_ADDR', 'SP_DRAM_ADDR', 'SP_RD_LEN', 'SP_WR_LEN', 'SP_STATUS', 'SP_DMA_FULL', 'SP_DMA_BUSY',
        'SP_SEMAPHORE', 'DPC_START', 'DPC_END', 'DPC_CURRENT', 'DPC_STATUS', 'DPC_CLOCK', 'DPC_BUFBUSY',
        'DPC_PIPEBUSY', 'DPC_TMEM']
MAME_E = {'00224466': 2, '11335577': 3, '00004444': 4, '11115555': 5, '22226666': 6, '33337777': 7}
for k in range(8):
    MAME_E[str(k) * 8] = 8 + k
GH_E = {'0q': 2, '1q': 3, '0h': 4, '1h': 5, '2h': 6, '3h': 7}
for k in range(8):
    GH_E[str(k)] = 8 + k


def num(s):
    s = s.strip()
    neg = s.startswith('-')
    if neg:
        s = s[1:]
    v = int(s, 16) if s.lower().startswith('0x') else int(s)
    return -v if neg else v


def reg(s):
    s = s.strip()
    if s.startswith('$'):
        s = s[1:]
        if s.isdigit():
            return ('r', int(s))
        return ('r', MIPS_NAMES.index(s))
    if s in GH_NAMES:
        return ('r', GH_NAMES.index(s))
    if s in MIPS_NAMES:
        return ('r', MIPS_NAMES.index(s))
    raise ValueError(s)


def operand(s, kind):
    s = s.strip()
    m = re.fullmatch(r'(-?0x[0-9a-fA-F]+|-?\d+)\((\$?\w+)\)', s)
    if m:
        return ('m', num(m.group(1)), reg(m.group(2)))
    m = re.fullmatch(r'(v\d+)\[([^\]]*)\]', s)
    if m:
        return ('v', int(m.group(1)[1:]), m.group(2))
    m = re.fullmatch(r'(v\d+)', s)
    if m:
        return ('v', int(m.group(1)[1:]), None)
    if s in COP0:
        return ('c0', COP0.index(s))
    m = re.fullmatch(r'FLAG(\d+)', s)
    if m:                       # MAME names the control register by number; the RSP masks it with 3
        n = int(m.group(1))
        return ('cr', 2 if n & 3 == 3 else n & 3)
    if s.upper() in ('VCO', 'VCC', 'VCE'):
        return ('cr', ['VCO', 'VCC', 'VCE'].index(s.upper()))
    if re.fullmatch(r'-?(0x[0-9a-fA-F]+|\d+)', s):
        return ('n', num(s))
    return reg(s)


def split_ops(s):
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch in '([':
            depth += 1
        if ch in ')]':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def parse(text):
    """-> (mnemonic, [operands]) or None for undecodable"""
    text = text.strip()
    if text in ('BAD', '???') or text.startswith('???') or text.startswith('BAD'):
        return None
    parts = text.split(None, 1)
    mn = parts[0].lower()
    ops = split_ops(parts[1]) if len(parts) > 1 else []
    return mn, [operand(o, mn) for o in ops]
