// Differential oracle for the RSP vector unit: runs single COP2/LWC2/SWC2 instructions through the
// vector-unit code of the ares emulator (ISC licence, fetched by build.sh, never committed) and prints
// the resulting state.  Built as a black box; the test compares its output with Ghidra's emulator.
//
// Input (stdin), one case per line, all hex:
//   word  v0..v31 (32 digits each, element 0 first)  acch accm accl  vco vcc (4 digits: bit n = lane n lo,
//   bit 8+n = lane n hi)  vce (2)  divin divout (4)  divdp (1)  r0..r31 (8)  dmem[0..1279]
// Output: the same fields after executing the word (without the word), then a line "flags/gprs/dmem"
// is included in the same order.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <immintrin.h>
#include <algorithm>
#include <iostream>
#include <sstream>

#define ARCHITECTURE_SUPPORTS_SSE4_1 1
#define order_msb2(a, b) b, a
using u8 = uint8_t; using u16 = uint16_t; using u32 = uint32_t; using u64 = uint64_t;
using s8 = int8_t; using s16 = int16_t; using s32 = int32_t; using s64 = int64_t;
using v128 = __m128i;
template<typename A, typename B> inline auto min(A a, B b) { using T = std::common_type_t<A, B>; return (T)a < (T)b ? (T)a : (T)b; }
struct serializer {};
struct Byte {};
template<typename T> struct maybe;
template<typename T> struct maybe<T&> { T* p = nullptr; maybe& operator=(T& r) { p = &r; return *this; } T* operator->() { return p; } };
struct rangeit { u32 i; u32 operator*() const { return i; } rangeit& operator++() { ++i; return *this; } bool operator!=(const rangeit& o) const { return i != o.i; } };
struct range { u32 n; u32 b = 0; range(u32 n) : n(n) {} range(u32 b, u32 n) : n(n), b(b) {} rangeit begin() const { return {b}; } rangeit end() const { return {n}; } };
template<int N, typename T> inline s64 sclamp(T v) { s64 lo = -(s64(1) << (N - 1)), hi = (s64(1) << (N - 1)) - 1; return (s64)v < lo ? lo : (s64)v > hi ? hi : (s64)v; }
template<int N, typename T> inline s64 sclip(T v) { return (s64)((u64)v << (64 - N)) >> (64 - N); }
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif
#define unreachable abort()
namespace Accuracy { namespace RSP { static constexpr bool SISD = false, SIMD = true; } }
struct r32 { u32 u32; };
using cr32 = const r32;

struct RSP {
PASTE_CLASS_BODY
  struct { r32 r[32]; } ipu;
  struct Dmem {
    u8 data[4096];
    template<typename T> u8 read(u32 a) const { return data[a & 0xfff]; }
    template<typename T> void write(u32 a, u8 v) { data[a & 0xfff] = v; }
  } dmem;
  RSP() {
    reciprocals[0] = u16(~0);
    for(u16 index : range(1, 512)) { u64 a = index + 512; u64 b = (u64(1) << 34) / a; reciprocals[index] = u16(b + 1 >> 8); }
    for(u16 index : range(0, 512)) {
      u64 a = index + 512 >> (index % 2 == 1); u64 b = 1 << 17;
      while(a * (b + 1) * (b + 1) < (u64(1) << 44)) b++;
      inverseSquareRoots[index] = u16(b >> 1);
    }
  }
};
#include "interpreter-vpu.cpp"

static std::string hexs(const u8* p, int n) { std::string s; char b[3]; for (int i = 0; i < n; i++) { snprintf(b, 3, "%02x", p[i]); s += b; } return s; }
static void rd(const std::string& s, u8* out, int n) { for (int i = 0; i < n; i++) out[i] = (u8)strtoul(s.substr(2 * i, 2).c_str(), 0, 16); }

static std::string regs128(const RSP::r128& r) { std::string s; char b[5]; for (int e = 0; e < 8; e++) { snprintf(b, 5, "%04x", r.element(e)); s += b; } return s; }
static void set128(RSP::r128& r, const std::string& s) { for (int e = 0; e < 8; e++) r.element(e) = (u16)strtoul(s.substr(4 * e, 4).c_str(), 0, 16); }
static u32 flags16(const RSP::r128& hi, const RSP::r128& lo) { u32 v = 0; for (int n = 0; n < 8; n++) { v |= lo.get(n) << n; v |= hi.get(n) << (8 + n); } return v; }
static void setflags(RSP::r128& hi, RSP::r128& lo, u32 v) { for (int n = 0; n < 8; n++) { lo.set(n, v >> n & 1); hi.set(n, v >> (8 + n) & 1); } }

template<class F> static void withE(u32 e, F&& f) {
  switch (e) {
#define C(i) case i: f(std::integral_constant<u8, i>{}); return;
  C(0) C(1) C(2) C(3) C(4) C(5) C(6) C(7) C(8) C(9) C(10) C(11) C(12) C(13) C(14) C(15)
#undef C
  }
}

int main() {
  static RSP rsp;
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream is(line);
    std::string tok;
    is >> tok; u32 op = strtoul(tok.c_str(), 0, 16);
    for (int i = 0; i < 32; i++) { is >> tok; set128(rsp.vpu.r[i], tok); }
    is >> tok; set128(rsp.vpu.acch, tok); is >> tok; set128(rsp.vpu.accm, tok); is >> tok; set128(rsp.vpu.accl, tok);
    is >> tok; setflags(rsp.vpu.vcoh, rsp.vpu.vcol, strtoul(tok.c_str(), 0, 16));
    is >> tok; setflags(rsp.vpu.vcch, rsp.vpu.vccl, strtoul(tok.c_str(), 0, 16));
    is >> tok; { u32 v = strtoul(tok.c_str(), 0, 16); for (int n = 0; n < 8; n++) rsp.vpu.vce.set(n, v >> n & 1); }
    is >> tok; rsp.vpu.divin = (s16)strtoul(tok.c_str(), 0, 16);
    is >> tok; rsp.vpu.divout = (s16)strtoul(tok.c_str(), 0, 16);
    is >> tok; rsp.vpu.divdp = strtoul(tok.c_str(), 0, 16) != 0;
    for (int i = 0; i < 32; i++) { is >> tok; rsp.ipu.r[i].u32 = strtoul(tok.c_str(), 0, 16); }
    memset(rsp.dmem.data, 0, sizeof rsp.dmem.data);
    is >> tok; rd(tok, rsp.dmem.data, 1280);

    auto& v = rsp.vpu.r;
    u32 VDn = op >> 6 & 31, VSn = op >> 11 & 31, VTn = op >> 16 & 31, RSn = op >> 21 & 31, RTn = op >> 16 & 31;
    s8 imm = (s8)((op & 0x7f) << 1) >> 1;
    u32 prim = op >> 26;
    if (prim == 0x12) {
      u32 sub = op >> 21 & 31;
      if (sub == 0) { u32 e = op >> 7 & 15; withE(e, [&](auto E) { rsp.MFC2<decltype(E)::value>(rsp.ipu.r[RTn], v[VSn]); }); }
      else if (sub == 2) { rsp.CFC2(rsp.ipu.r[RTn], op >> 11 & 31); }
      else if (sub == 4) { u32 e = op >> 7 & 15; withE(e, [&](auto E) { rsp.MTC2<decltype(E)::value>(rsp.ipu.r[RTn], v[VSn]); }); }
      else if (sub == 6) { rsp.CTC2(rsp.ipu.r[RTn], op >> 11 & 31); }
      else if (sub >= 16) {
        u32 e = op >> 21 & 15, de = op >> 11 & 7;
        auto& VD = v[VDn]; auto& VS = v[VSn]; auto& VT = v[VTn];
#define VU(id, name, ...) case id: withE(e, [&](auto E) { rsp.name<decltype(E)::value>(__VA_ARGS__); }); break;
        switch (op & 0x3f) {
        VU(0x00, VMULF, VD, VS, VT) VU(0x01, VMULU, VD, VS, VT) VU(0x02, VRNDP, VD, VSn, VT) VU(0x03, VMULQ, VD, VS, VT)
        VU(0x04, VMUDL, VD, VS, VT) VU(0x05, VMUDM, VD, VS, VT) VU(0x06, VMUDN, VD, VS, VT) VU(0x07, VMUDH, VD, VS, VT)
        VU(0x08, VMACF, VD, VS, VT) VU(0x09, VMACU, VD, VS, VT) VU(0x0a, VRNDN, VD, VSn, VT)
        case 0x0b: rsp.VMACQ(VD); break;
        VU(0x0c, VMADL, VD, VS, VT) VU(0x0d, VMADM, VD, VS, VT) VU(0x0e, VMADN, VD, VS, VT) VU(0x0f, VMADH, VD, VS, VT)
        VU(0x10, VADD, VD, VS, VT) VU(0x11, VSUB, VD, VS, VT) VU(0x13, VABS, VD, VS, VT) VU(0x14, VADDC, VD, VS, VT)
        VU(0x15, VSUBC, VD, VS, VT) VU(0x1d, VSAR, VD, VS)
        VU(0x20, VLT, VD, VS, VT) VU(0x21, VEQ, VD, VS, VT) VU(0x22, VNE, VD, VS, VT) VU(0x23, VGE, VD, VS, VT)
        VU(0x24, VCL, VD, VS, VT) VU(0x25, VCH, VD, VS, VT) VU(0x26, VCR, VD, VS, VT) VU(0x27, VMRG, VD, VS, VT)
        VU(0x28, VAND, VD, VS, VT) VU(0x29, VNAND, VD, VS, VT) VU(0x2a, VOR, VD, VS, VT) VU(0x2b, VNOR, VD, VS, VT)
        VU(0x2c, VXOR, VD, VS, VT) VU(0x2d, VNXOR, VD, VS, VT)
        VU(0x30, VRCP, VD, de, VT) VU(0x31, VRCPL, VD, de, VT) VU(0x32, VRCPH, VD, de, VT) VU(0x33, VMOV, VD, de, VT)
        VU(0x34, VRSQ, VD, de, VT) VU(0x35, VRSQL, VD, de, VT) VU(0x36, VRSQH, VD, de, VT)
        case 0x37: case 0x3f: break;
        default: VU(0x12, VZERO, VD, VS, VT) break;
        }
      }
    } else if (prim == 0x32 || prim == 0x3a) {
      u32 e = op >> 7 & 15, sub = op >> 11 & 31;
      auto& VT = v[VTn]; auto& RS = rsp.ipu.r[RSn];
      if (prim == 0x32) {
        switch (sub) {
#define LD(id, name) case id: withE(e, [&](auto E) { rsp.name<decltype(E)::value>(VT, RS, imm); }); break;
        LD(0, LBV) LD(1, LSV) LD(2, LLV) LD(3, LDV) LD(4, LQV) LD(5, LRV) LD(6, LPV) LD(7, LUV) LD(8, LHV) LD(9, LFV)
        case 11: withE(e, [&](auto E) { rsp.LTV<decltype(E)::value>(VTn, RS, imm); }); break;
        }
      } else {
        switch (sub) {
#define ST(id, name) case id: withE(e, [&](auto E) { rsp.name<decltype(E)::value>(VT, RS, imm); }); break;
        ST(0, SBV) ST(1, SSV) ST(2, SLV) ST(3, SDV) ST(4, SQV) ST(5, SRV) ST(6, SPV) ST(7, SUV) ST(8, SHV) ST(9, SFV) ST(10, SWV)
        case 11: withE(e, [&](auto E) { rsp.STV<decltype(E)::value>(VTn, RS, imm); }); break;
        }
      }
    }
    // state out
    std::string out;
    for (int i = 0; i < 32; i++) { out += regs128(v[i]); out += ' '; }
    out += regs128(rsp.vpu.acch) + ' ' + regs128(rsp.vpu.accm) + ' ' + regs128(rsp.vpu.accl) + ' ';
    char b[64];
    snprintf(b, sizeof b, "%04x %04x ", flags16(rsp.vpu.vcoh, rsp.vpu.vcol), flags16(rsp.vpu.vcch, rsp.vpu.vccl)); out += b;
    u32 vce = 0; for (int n = 0; n < 8; n++) vce |= rsp.vpu.vce.get(n) << n;
    snprintf(b, sizeof b, "%02x %04x %04x %x ", vce, (u16)rsp.vpu.divin, (u16)rsp.vpu.divout, rsp.vpu.divdp ? 1 : 0); out += b;
    for (int i = 0; i < 32; i++) { snprintf(b, sizeof b, "%08x ", rsp.ipu.r[i].u32); out += b; }
    out += hexs(rsp.dmem.data, 1280);
    puts(out.c_str());
  }
}
