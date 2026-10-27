#!/usr/bin/env bash
# Fetch the real-code samples used by test/real-check.sh into <dir> (never committed).
#
# Thirteen RSP programs by Peter Lemon ("krom"), written in the bass assembler's n64.rsp syntax, from
# https://github.com/PeterLemon/N64 (RSP/, The Unlicense: public domain), pinned to a commit and
# verified by SHA-256. Only the .asm sources and the three LIB/*.INC include files (constants and macros)
# are fetched; the repository's ROM images, ROM header sources and boot-code binaries are not used.
#
#   test/fetch-samples.sh <dir>
set -euo pipefail
DIR=$(mkdir -p "$1" && cd "$1" && pwd)
SHA=7085543e4a19d8c539fc9e0a4d2869e788b4ed4b
BASE="https://raw.githubusercontent.com/PeterLemon/N64/$SHA/RSP"
mkdir -p "$DIR/LIB"
fetch() {   # <path under RSP/> <file> <sha256>
	if [[ ! -f $DIR/$2 ]] || [[ $(sha256sum "$DIR/$2" | cut -d' ' -f1) != "$3" ]]; then
		curl -fsSL "$BASE/$1" -o "$DIR/$2"
	fi
	[[ $(sha256sum "$DIR/$2" | cut -d' ' -f1) == "$3" ]] || { echo "checksum mismatch: $2" >&2; exit 1; }
}
fetch Gradient/LIB/N64.INC LIB/N64.INC cc02124557725eb8aafa4ea70f941c082f48f9e66e956b6a8c5525ecdb7172cc
fetch Gradient/LIB/N64_GFX.INC LIB/N64_GFX.INC cf6605984ec709c5d172101ade9183f0d46284bdea47da8326cc840fc274e057
fetch Gradient/LIB/N64_RSP.INC LIB/N64_RSP.INC f8a6db5b7ea065d4d9227090b2577cc2a7c49ad63a46da17c79125e145ac2302
fetch DCT/FastDCTBlockDecode/RSPFastDCTBlockDecode.asm DCT_FastDCTBlockDecode_RSPFastDCTBlockDecode.asm 392149f35113b7c68aeca8be42bb03b00a06d380d592b3e4891d14c7c338beab
fetch DCT/FastQuantizationBlockDecode/RSPFastQuantizationBlockDecode.asm DCT_FastQuantizationBlockDecode_RSPFastQuantizationBlockDecode.asm 62f9d0c7ad177957aed2033af27abf9155eb20ac9d98ebc4ed194aba61af902a
fetch DCT/FastQuantizationMultiBlock16BIT/RSPFastQuantizationMultiBlock16BIT.asm DCT_FastQuantizationMultiBlock16BIT_RSPFastQuantizationMultiBlock16BIT.asm 04d10ba87270f8ee8a3856ae9eee1c254d65d2edbe38b028208de502508805d7
fetch DCT/FastZigZagQuantizationBlockDecode/RSPFastZigZagQuantizationBlockDecode.asm DCT_FastZigZagQuantizationBlockDecode_RSPFastZigZagQuantizationBlockDecode.asm ab1f6fbe82e97656fcd752e4d46a59caf9ac6e9cf5d05e920997d48d50005b6b
fetch DCT/FastZigZagQuantizationMultiBlock16BIT/RSPFastZigZagQuantizationMultiBlock16BIT.asm DCT_FastZigZagQuantizationMultiBlock16BIT_RSPFastZigZagQuantizationMultiBlock16BIT.asm 8695680e793151de658412fd071f70fd840b03c18e72f556103a827d0486ceb5
fetch DCT/FastZigZagQuantizationMultiBlock16BITYUV/RSPFastZigZagQuantizationMultiBlock16BITYUV.asm DCT_FastZigZagQuantizationMultiBlock16BITYUV_RSPFastZigZagQuantizationMultiBlock16BITYUV.asm 25649948a5c35187fa18ea39a446d78ae8349146e1e478c64b8ca78f770eacd6
fetch DMAStride/RSPDMAStride.asm DMAStride_RSPDMAStride.asm 5f1f30c67ed2e17c0450e9f4d7993f9d33c35ce55377abb2b4fd0326fa17fbc8
fetch Gradient/RSPGradient.asm Gradient_RSPGradient.asm 075ad9792d18ce9dc0fb09e6d757486131e173ca05a578ec716cee11bf57ac1a
fetch XBUS/RSPPlotTriangle/RSPPlotTriangle.asm XBUS_RSPPlotTriangle_RSPPlotTriangle.asm 6637b5687c460f965908c0bb21c7b4c01a0313ff956884e82edb6a9a6bfc2203
fetch XBUS/RSPTrans2DRectangleDouble/RSPTrans2DRectangle.asm XBUS_RSPTrans2DRectangleDouble_RSPTrans2DRectangle.asm eea9fe4bb06fe5bdb6ce9df4e4c0ce2d9c419a002fbbe2dc7e9d17682d7bedb0
fetch XBUS/RSPTrans2DRectangle/RSPTrans2DRectangle.asm XBUS_RSPTrans2DRectangle_RSPTrans2DRectangle.asm d46c6957af38da9310b8fa0fd0cd34f6c6d80f4139f2eb2105cf56d6a417d90e
fetch XBUS/RSPTrans3DRectangleDouble/RSPTrans3DRectangle.asm XBUS_RSPTrans3DRectangleDouble_RSPTrans3DRectangle.asm 3b9fd718de8eeeb59d530da08a33cc0a368a649c6c817efae9d3b8ca8fc099ee
fetch XBUS/RSPTrans3DRectangle/RSPTrans3DRectangle.asm XBUS_RSPTrans3DRectangle_RSPTrans3DRectangle.asm 658c9a6daf3b467d33bfefc2105bc49ed5375c2cc49721aeefa7510dd0886aaa
echo "fetched into $DIR"
