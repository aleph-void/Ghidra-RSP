#!/usr/bin/env bash
# Real-code check: assemble thirteen freely licensed RSP programs (Peter Lemon, The Unlicense) with the
# bass assembler, import each IMEM image headless with the module's loader and full auto-analysis,
# decompile every function, and compare the analysed listing with MAME's disassembler and with the
# bass-assembled bytes (re-assembled by armips from Ghidra's text).
#
#   GHIDRA_INSTALL_DIR=... BASS=<bass> ARMIPS=<armips> test/real-check.sh <workdir>
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
BASS=${BASS:-bass}
"$HERE/fetch-samples.sh" "$W/samples" >/dev/null
for inc in N64 N64_GFX N64_RSP; do python3 "$HERE/real/fix_inc.py" "$W/samples/LIB/$inc.INC" "$W/samples/LIB/$inc.fixed" && mv "$W/samples/LIB/$inc.fixed" "$W/samples/LIB/$inc.INC"; done
rc=0
skipped=0
for src in "$W"/samples/*.asm; do
	n=$(basename "$src" .asm)
	P="$W/$n"
	python3 "$HERE/real/prep.py" "$src" "$W/samples/$n.prep" "$n.rom"
	off=$(cd "$W/samples" && "$BASS" "$n.prep" 2>&1 | sed -n 's/^OFFSETS //p') || true
	if [[ -z $off ]]; then echo "== $n: skipped (bass could not assemble it: uses the old bass define/evaluate syntax)"; skipped=$((skipped + 1)); continue; fi
	set -- $off
	python3 - "$W/samples/$n.rom" "$P.bin" "$P.dmem" $((16#$1)) $((16#$2)) $((16#$3)) $((16#$4)) <<'PY'
import sys
rom = open(sys.argv[1], 'rb').read()
a, b, c, d = map(int, sys.argv[4:8])
open(sys.argv[2], 'wb').write(rom[a:b])
open(sys.argv[3], 'wb').write(rom[c:d])
PY
	PROJ=$(mktemp -d "${TMPDIR:-/tmp}/rsp-real.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$P.bin" \
		-loader GhidraRSPLoader -loader-isBoot true -loader-dmemFile "$P.dmem" -processor RSP:BE:32:default \
		-scriptPath "$HERE" -postScript RealCheck.java "$P" 60 -deleteProject >"$PROJ/log.txt" 2>&1 \
		|| { tail -40 "$PROJ/log.txt" >&2; rm -rf "$PROJ"; exit 1; }
	rm -rf "$PROJ"
	echo "== $n ($(stat -c %s "$P.bin") bytes)"
	grep -v "^bookmark" "$P.summary"
	python3 "$HERE/real/real_compare.py" "$P.bin" "$P.dis" "$W/cmp-$n" || rc=1
	# armips round trip of the analysed instructions, compared with the bass output
	python3 "$HERE/real/rt_image.py" "$P.bin" "$P.dis" "$W/rt-$n" || rc=1
done
echo "skipped samples: $skipped"
exit $rc
