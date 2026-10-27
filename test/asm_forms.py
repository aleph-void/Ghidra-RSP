#!/usr/bin/env python3
"""Every instruction form the armips assembler (RSP mode) accepts, as assembler text, one per line:
asm_forms.py > forms.txt   (registers/immediates filled from a fixed seed; every element, every
sub-opcode, every shift amount and every COP0/vector-control register is covered)."""
import random
rnd = random.Random(99)
R = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
     's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra']
COP0 = ['sp_mem_addr', 'sp_dram_addr', 'sp_rd_len', 'sp_wr_len', 'sp_status', 'sp_dma_full', 'sp_dma_busy',
        'sp_semaphore', 'dpc_start', 'dpc_end', 'dpc_current', 'dpc_status', 'dpc_clock', 'dpc_bufbusy',
        'dpc_pipebusy', 'dpc_tmem']
EL = ['', '0q', '1q', '0h', '1h', '2h', '3h'] + [str(i) for i in range(8)]
L = []


def r(): return rnd.choice(R)
def v(): return 'v%d' % rnd.randrange(32)


for m in 'add addu sub subu and or xor nor slt sltu'.split():
    for _ in range(40): L.append(f'{m} {r()},{r()},{r()}')
for m in 'sllv srlv srav'.split():
    for _ in range(40): L.append(f'{m} {r()},{r()},{r()}')
for m in 'sll srl sra'.split():
    for sa in range(32):
        for _ in range(2): L.append(f'{m} {r()},{r()},{sa}')
for m in 'addi addiu slti sltiu'.split():
    for imm in (0, 1, -1, 0x7fff, -0x8000, 0x1234, -0x1234):
        for _ in range(3): L.append(f'{m} {r()},{r()},{imm}')
for m in 'andi ori xori'.split():
    for imm in (0, 1, 0xffff, 0x8000, 0x1234):
        for _ in range(3): L.append(f'{m} {r()},{r()},{imm}')
for imm in (0, 1, 0xffff, 0x8000, 0x1234): L.append(f'lui {r()},{imm}')
for m in 'lb lh lw lbu lhu sb sh sw'.split():
    for off in (0, 1, -1, 0x7fff, -0x8000, 0x123, -0x234):
        for _ in range(3): L.append(f'{m} {r()},{off}({r()})')
for m in 'beq bne'.split():
    for d in (-100, -3, 0, 1, 2, 50, 200, 400):
        L.append(f'{m} {r()},{r()},0x{0x1000 + (d & 0x3ff) * 4:x}')
for m in 'blez bgtz bltz bgez bltzal bgezal'.split():
    for d in (-100, -3, 0, 1, 2, 50, 200, 400):
        L.append(f'{m} {r()},0x{0x1000 + (d & 0x3ff) * 4:x}')
for m in ('j', 'jal'):
    for t in (0x1000, 0x1004, 0x1ffc, 0x1abc, 0x1f00): L.append(f'{m} 0x{t:x}')
for _ in range(20): L.append(f'jr {r()}')
for _ in range(20): L.append(f'jalr {r()}')
for _ in range(20): L.append(f'jalr {r()},{r()}')
L.append('break'); L.append('nop')
for i in range(16):
    for _ in range(2):
        L.append(f'mfc0 {r()},{COP0[i]}'); L.append(f'mtc0 {r()},{COP0[i]}')
for e in range(16):
    for _ in range(2):
        L.append(f'mfc2 {r()},{v()}[{e}]'); L.append(f'mtc2 {r()},{v()}[{e}]')
for c in ('vco', 'vcc', 'vce'):
    for _ in range(3):
        L.append(f'cfc2 {r()},{c}'); L.append(f'ctc2 {r()},{c}')
V3 = ('vmulf vmulu vrndp vmulq vmudl vmudm vmudn vmudh vmacf vmacu vrndn vmacq vmadl vmadm vmadn vmadh vadd vsub '
      'vsut vabs vaddc vsubc vaddb vsubb vaccb vsucb vsad vsac vsum vsar vacc vsuc vlt veq vne vge vcl vch vcr '
      'vmrg vand vnand vor vnor vxor vnxor vextt vextq vextn vinst vinsq vinsn').split()
for m in V3:
    for e in EL:
        for _ in range(2):
            if m == 'vmacq':
                continue
            L.append(f'{m} {v()},{v()},{v()}' + (f'[{e}]' if e else ''))
for _ in range(10): L.append(f'vmacq {v()},{v()},{v()}')
for m in 'vrcp vrcpl vrcph vmov vrsq vrsql vrsqh'.split():
    for de in range(8):
        for lane in range(8):
            L.append(f'{m} {v()}[{de}],{v()}[{lane}]')
L.append('vnop'); L.append('vnull')
LD = 'lbv lsv llv ldv lqv lrv lpv luv lhv lfv ltv'.split()
ST = 'sbv ssv slv sdv sqv srv spv suv shv sfv swv stv'.split()
SCALE = dict(zip('b s l d q r p u h f t w v'.split(), [1, 2, 4, 8, 16, 16, 8, 8, 16, 16, 16, 16, 1]))
SC = {'lbv': 1, 'lsv': 2, 'llv': 4, 'ldv': 8, 'lqv': 16, 'lrv': 16, 'lpv': 8, 'luv': 8, 'lhv': 16, 'lfv': 16,
      'ltv': 16, 'sbv': 1, 'ssv': 2, 'slv': 4, 'sdv': 8, 'sqv': 16, 'srv': 16, 'spv': 8, 'suv': 8, 'shv': 16,
      'sfv': 16, 'swv': 16, 'stv': 16}
for m in LD + ST:
    for e in range(16):
        for k in (0, 1, -1, 63, -64, rnd.randrange(-64, 64)):
            L.append(f'{m} {v()}[{e}],{k * SC[m]}({r()})')
print('\n'.join(L))
