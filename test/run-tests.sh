#!/usr/bin/env bash
# Runs every RSP check that needs no non-redistributable input.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module linked into Ghidra/Processors/RSP, lib/RSP.jar built by
#     test/build-jar.sh> test/run-tests.sh [--real] [--n <random-words>] [--k <sem-cases-per-combination>] <workdir>
#
# Needs: python3, g++ and git (the ares vector-unit oracle is fetched and built), unidasm (MAME) on PATH,
# ARMIPS pointing at armips (test/build-tools.sh builds it). --real also needs BASS and network access
# (test/fetch-samples.sh) and runs test/real-check.sh. Exit status 0 only if every step passes.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(dirname "$HERE")
REAL=0; N=200000; K=4
while [[ ${1:-} == --* ]]; do
	case $1 in --real) REAL=1; shift ;; --n) N=$2; shift 2 ;; --k) K=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
W=$(mkdir -p "$1" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-$W}
command -v unidasm >/dev/null || { echo "unidasm (MAME) not found on PATH" >&2; exit 2; }
export ARMIPS=${ARMIPS:-armips}
command -v "$ARMIPS" >/dev/null || { echo "armips not found: set ARMIPS (test/build-tools.sh <dir> builds it)" >&2; exit 2; }
fail=0
step() { echo "== $*"; }
ok() { "$@" || { echo "FAILED: $*"; fail=1; }; }

step "spec compiles (sleigh -l: no unresolved pattern conflicts)"
out=$("$GHIDRA_INSTALL_DIR/support/sleigh" -l "$MOD/data/languages/rsp.slaspec" 2>&1)
if grep -q "ERROR" <<<"$out"; then echo "$out" | grep ERROR | head; echo FAILED; fail=1; else echo "rsp.slaspec compiles, no conflicts"; fi

step "generator reproduces data/languages/rsp_vector.sinc"
python3 "$MOD/gen/gen_rsp_vector.py" "$W/rsp_vector.sinc" >/dev/null
ok cmp "$W/rsp_vector.sinc" "$MOD/data/languages/rsp_vector.sinc"

step "decode: every form armips accepts, assembled and decoded back"
python3 "$HERE/asm_forms.py" > "$W/forms.txt"
ok python3 "$HERE/asm_roundtrip.py" "$W/forms.txt" "$W/forms"

step "decode: structured corpus and $N random words vs MAME unidasm and an armips round trip"
python3 "$HERE/gen_words.py" structured "$W/st.txt" >/dev/null
python3 "$HERE/gen_words.py" random "$N" 7 "$W/rnd.txt" >/dev/null
for c in st rnd; do
	python3 "$HERE/mame_dis.py" "$W/$c.txt" "$W/$c.mame"
	"$HERE/dis.sh" "$W/$c.txt" "$W/$c.gh"
	ok python3 "$HERE/cmp_mame.py" "$W/$c.gh" "$W/$c.mame"
	ok python3 "$HERE/armips_rt.py" "$W/$c.gh" "$W/rt-$c"
done

step "every constructor is reached"
cat "$W/st.txt" "$W/rnd.txt" > "$W/all.txt"
out=$("$HERE/every-entry.sh" "$W/all.txt" "$W/ee.txt")
echo "$out" | tail -3
grep -q " 0 not reached" <<<"$out" || { echo FAILED; fail=1; }

step "p-code: hand-computed emulator cases (58, one deliberately wrong)"
ok "$HERE/emu-test.sh" "$HERE/emu/cases.txt" "$W/emu"
tail -1 "$W/emu/emu.txt"

step "p-code: random single instructions vs the ares emulator's vector unit"
ok "$HERE/ares/build.sh" "$W/ares"
python3 "$HERE/gen_sem_cases.py" "$W/sem.txt" "$K" 3
"$W/ares/ares-vpu" < "$W/sem.txt" > "$W/sem.ares"
"$HERE/sem-diff.sh" "$W/sem.txt" "$W/sem.gh"
ok python3 "$HERE/sem_cmp.py" "$W/sem.txt" "$W/sem.ares" "$W/sem.gh"

if ((REAL)); then
	step "real code (Peter Lemon's RSP programs)"
	ok "$HERE/real-check.sh" "$W/real"
fi
((fail)) && { echo "SOME CHECKS FAILED"; exit 1; }
echo "ALL CHECKS PASSED"
