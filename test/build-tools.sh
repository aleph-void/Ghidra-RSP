#!/usr/bin/env bash
# Builds the reference tools of the RSP test suite into <dir> (needs git, cmake, g++, make):
#   <dir>/armips  the MIT-licensed armips assembler (RSP mode), pinned commit
#   <dir>/bass    ARM9's bass assembler (the one Peter Lemon's RSP samples use), pinned commit
# MAME's unidasm is taken from PATH (apt install mame-tools or build MAME's unidasm target).
#   test/build-tools.sh <dir>
set -euo pipefail
D=$(mkdir -p "$1" && cd "$1" && pwd)
ARMIPS_COMMIT=62adab4ef30da765f5cf22a451eb08a59c54dc8b
BASS_COMMIT=c3962ec01f4768be1667db0d09c12141c28241f3
if [[ ! -x $D/armips ]]; then
	[[ -d $D/armips-src ]] || git clone -q --recurse-submodules https://github.com/Kingcom/armips "$D/armips-src"
	git -C "$D/armips-src" checkout -q "$ARMIPS_COMMIT"
	git -C "$D/armips-src" submodule update -q --init --recursive
	mkdir -p "$D/armips-src/b" && (cd "$D/armips-src/b" && cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null && make -j"$(nproc)" >/dev/null)
	cp "$D/armips-src/b/armips" "$D/armips"
fi
if [[ ! -x $D/bass ]]; then
	[[ -d $D/bass-src ]] || git clone -q https://github.com/ARM9/bass "$D/bass-src"
	git -C "$D/bass-src" checkout -q "$BASS_COMMIT"
	(cd "$D/bass-src/bass" && make -j"$(nproc)" >/dev/null 2>&1)
	cp "$D/bass-src/bass/out/bass" "$D/bass"
fi
echo "armips: $D/armips"
echo "bass:   $D/bass"
