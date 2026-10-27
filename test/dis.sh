#!/usr/bin/env bash
# test/dis.sh <cases.txt> <out.txt>   (GHIDRA_INSTALL_DIR set)
# Decodes each 8-digit hex word of cases.txt (word i placed at 0x1000+4*(i mod 1024), big endian) with RSP:BE:32:default
# and writes "<hex> <len> <text>" ("BAD" if the language rejects it).
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
IN=$(readlink -f "$1"); OUT=$(readlink -m "$2")
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/rsp-dis.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 8192 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-loader-baseAddr 0 -processor RSP:BE:32:default -noanalysis -scriptPath "$HERE" \
	-postScript DisCases.java "$IN" "$OUT" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
