#!/usr/bin/env python3
"""fix_inc.py <in.INC> <out.INC>: Peter Lemon's N64.INC is written for an old bass (constant NAME(value));
current bass wants "constant NAME = value"."""
import re, sys
out = []
skip = 0
for l in open(sys.argv[1], errors='replace').read().split('\n'):
    m = re.match(r'constant\s+(\w+)\((.*?)\)\s*(//.*)?$', l)
    if m:
        l = 'constant %s = %s %s' % (m.group(1), m.group(2), m.group(3) or '')
    out.append(l)
open(sys.argv[2], 'w').write('\n'.join(out))
