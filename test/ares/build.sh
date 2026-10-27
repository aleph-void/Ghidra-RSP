#!/usr/bin/env bash
# Builds the ares vector-unit oracle: test/ares/build.sh <workdir>
# Fetches the ares emulator sources (ISC licence) at a pinned commit into <workdir> (never committed)
# and compiles harness.cpp around ares/n64/rsp/interpreter-vpu.cpp.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
ARES_COMMIT=5d093ad9e63c3715752a1d7b8e1a077892ae13fb
if [[ ! -f $W/ares-src/ares/n64/rsp/interpreter-vpu.cpp ]]; then
	git clone -q --filter=blob:none --sparse https://github.com/ares-emulator/ares "$W/ares-src"
	git -C "$W/ares-src" sparse-checkout set ares/n64/rsp
	git -C "$W/ares-src" checkout -q "$ARES_COMMIT"
fi
R=$W/ares-src/ares/n64/rsp
# class body: from "union r128" to the last VU declaration, plus the data members
python3 - "$R/rsp.hpp" "$HERE/harness.cpp" "$W/harness-full.cpp" <<'PY'
import re, sys
hpp = open(sys.argv[1]).read().split('\n')
i = next(k for k, l in enumerate(hpp) if 'union r128 {' in l)
j = next(k for k, l in enumerate(hpp) if 'auto VZERO(' in l)
body = '\n'.join(l for l in hpp[i:j + 1] if 'serialize' not in l and 'fast' not in l)
src = open(sys.argv[2]).read().replace('PASTE_CLASS_BODY', body + '\n  u16 reciprocals[512]; u16 inverseSquareRoots[512];')
open(sys.argv[3], 'w').write(src)
PY
g++ -O1 -std=c++20 -msse4.1 -fpermissive -w -I"$R" -o "$W/ares-vpu" "$W/harness-full.cpp"
echo "built $W/ares-vpu"
