#!/usr/bin/env bash
# Every-entry test: test/every-entry.sh <cases.txt> <out.txt>
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
IN=$(readlink -f "$1"); OUT=$(readlink -m "$2")
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/rsp-ee.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 8192 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-loader-baseAddr 0 -processor RSP:BE:32:default -noanalysis -scriptPath "$HERE" \
	-postScript EveryEntry.java "$IN" "$OUT" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
cat "$OUT"
