from z3 import *

BW = 64
N = 45
f = [BitVec(f'flag_{i}', BW) for i in range(N)]

byte_mask = (1 << 8) - 1

vrambyte = 0xff
pallette = [0xe4, 0xe4, 0x1b, 0x00]
oambyte = 0xff

def BV(x): return BitVecVal(x, BW)
byte_constraints = [Or(And(f[i] >= BV(ord('a')),f[i] <= BV(ord('z'))),And(f[i] >= BV(ord('A')),f[i] <= BV(ord('Z'))),And(f[i] >= BV(ord('0')),f[i] <= BV(ord('9'))),f[i] == BV(ord('_')),f[i] == BV(ord('{')),f[i] == BV(ord('}')))for i in range(N)]

constraints = []
constraints.append( f[42] ^ BV(0x92 - 0x3) == BV(0xfd) )
constraints.append( f[1] == BV(0x69) )
constraints.append( f[14] ^ BV(vrambyte) == BV(0xa0) )
constraints.append( (f[32] & f[1]) == ((f[14] ^ BV(0xda)) ^ BV(pallette[1])) )
rhs5 = LShR(f[0] ^ BV(0x7839), 0x1f) | BV(0x388)
constraints.append( (f[24] ^ BV(0x3fc)) == rhs5 )
const_1998_and_oam = 0x1998 & oambyte
constraints.append( (f[0] + BV(const_1998_and_oam)) ^ f[32] == BV(0x165) )
left7 = (f[7] << 0x18) ^ BV(0x3f2d15ab)
right7 = BV((0x4a2d1539651a >> 0x10)) + f[42]
constraints.append( left7 == right7 )
lhs8 = ((f[44] - f[28]) + BV(vrambyte << 8)) ^ BV(0x284d)
rhs8 = ((BV(pallette[1]) ^ f[22]) << 8) + BV(0xb)
constraints.append(lhs8 == rhs8)
constraints.append( (f[28] ^ f[4]) == (f[37] ^ BV(0x2f)) )
constraints.append((f[0]+f[18])^BV(0x15c) == f[35]+BV(vrambyte)^BV(oambyte))
constraints.append((BV(0x9432494)^f[44])>>0x5 ==  f[18]^pallette[3]^BV(0x4a1927)^f[43])
constraints.append(f[10] == f[27])
constraints.append(f[27]^0x8ba42 == (((vrambyte|BV(0x342))<<0x8)^f[0]+f[1])^BV(0xb45ca))
constraints.append((f[9]<<0x18)^BV(0xd86f12a0) == (BV(0xbc6f1229f372)>>0x10)+ f[40])
constraints.append(f[35]^f[26] == pallette[3]&oambyte)
constraints.append(f[17] & f[44] | 0x3 == f[23]+1)
constraints.append((~f[37]&0xFF)^f[44] == pallette[0]-BV(0x3))
constraints.append(f[11]^f[26] == (~f[40]&0xFF) ^ 0x83)
constraints.append((((f[2] ^ f[43]) << 0x12)|f[12])^ BV(0xea8b2a2) == BV(0x9125afa)^BV(0x7fae858)^f[33])
constraints.append((((f[16] ^ f[3]) << 0x12)|f[20])^ BV(0x51ccfde) == BV(0x231ba98)^BV(0x82a1ddd)^f[36]^BV(0xe5768d1))
constraints.append((f[8]+f[19])^pallette[2] == BV(0xb1)^f[29]^f[39]&(vrambyte^pallette[3]))
constraints.append(f[6] == f[41])
constraints.append(f[5]^f[13]^f[21]^f[31]^f[38] == f[22] + BV(0x2))
constraints.append(f[11]^f[15]^f[25]^f[34] == f[38] - BV(0x4))
constraints.append(~f[17]&0xff +oambyte^f[42] == 0x1e2)
constraints.append(f[9]^f[28]^pallette[0] == f[17]+BV(0x49))
constraints.append(f[9] == f[17] - 0xa)
constraints.append(~(f[22]^pallette[1]^(~f[12]&0xff))&0xff == pallette[0]+(f[40]&pallette[3])+BV(0x3))
constraints.append((f[3]<<0x18)^BV(0xb1ca10c0a) == (BV(0xb79a10bab6b18)>>0x10)+ f[21])
constraints.append(f[30] ^ f[2] ^ f[10]^f[34] == pallette[2] + BV(0xf))
constraints.append((BV(0xefb2d13)^f[1])>>0x5 == f[18]^pallette[2]^f[30]^BV(0x77d927))
constraints.append(f[6]+f[38]^vrambyte == f[19]^BV(0xa9))
constraints.append(f[41]^vrambyte^oambyte^pallette[2]^BV(0x8212) == BV(0x8234)^f[37]^(BV(0x6e12)>>0x8))
constraints.append(f[28]^f[38] == (vrambyte|oambyte) & pallette[3])
constraints.append(pallette[2]+BV(0x2) == f[35]^f[24]^pallette[2])
constraints.append(f[5] == f[40] - BV(0x20))
constraints.append( ~f[2]&0xff +oambyte^f[38] == BV(0x1bd))
constraints.append(f[8]^f[0] == pallette[3]^BV(0x2))
constraints.append((f[8]<<0x18)^BV(0x16aa8dbc) == (BV(0x7aaa8d430242)>>0x10)+f[20])
constraints.append(f[25]^f[43]^f[12]^f[26] == pallette[2] - BV(0x6))
constraints.append(~f[8]&0xff == pallette[0]-f[5]+BV(0x6))
constraints.append(BV(0xebdd321)>>0x5 ==  f[31]^pallette[3]^f[0]^f[16]^0x75ee99)
constraints.append(f[39] == f[31])

s = Solver()
s.add(byte_constraints)
s.add(constraints)

if s.check() == sat:
    m = s.model()
    max_used = 45
    recovered = []
    for i in range(max_used):
        bv = m.eval(f[i])
        val = bv.as_long()
        recovered.append(val)
    flag_bytes = bytes(recovered)
    print(flag_bytes)

else:
    print("not sat")

