#ifndef ALU_H
#define ALU_H

#include <stdint.h>


#define zy(flag) (flag & 0x1)
#define ny(flag) ((flag >> 1) & 0x1)
#define zx(flag) ((flag >> 2) & 0x1)
#define nx(flag) ((flag >> 3) & 0x1) 
#define no(flag)  ((flag >> 4) & 0x1)
#define f(flag) ((flag >> 5) & 0x1)
#define cin(flag) (flag >> 6) & 0x1

#define zr(out_flag) ((out_flag) & 0x1)
#define ng(out_flag) ((out_flag >> 1) & 0x1)
#define cout(out_flag) ((out_flag >> 2) & 0x1)

// f == 0 then x + y else x & y
// Bit order: cin(6), f(5), no(4), nx(3), zx(2), ny(1), zy(0)
#define OUTX            0x23
#define OUTY            0x2C
#define ALU_OP_ZERO     0x05 // 0
#define ALU_OP_ONE      0x45 // 1
#define ALU_OP_NEG_ONE  0x06 // -1

#define ALU_OP_X        0x01 // x
#define ALU_OP_Y        0x04 // y
#define ALU_OP_NOT_X    0x08 // ~x
#define ALU_OP_NOT_Y    0x02 // ~y
#define ALU_OP_NEG_X    0x4D // -x
#define ALU_OP_NEG_Y    0x46 // -y
#define ALU_OP_INC_X    0x41 // x+1
#define ALU_OP_INC_Y    0x44 // y+1
#define ALU_OP_DEC_X    0x03 // x-1
#define ALU_OP_DEC_Y    0x0C // y-1

#define ALU_OP_ADD_XY   0x00 // x+y
#define ALU_OP_SUB_XY   0x18 // x-y
#define ALU_OP_SUB_YX   0x12 // y-x
#define ALU_OP_ADC_XY   0x40 // x+y+cin
#define ALU_OP_SBC_XY   0x02 // x-y-cin (x+~y)

#define ALU_OP_AND_XY   0x20 // x&y
#define ALU_OP_OR_XY    0x3A // x|y
#define ALU_OP_NOT_OUT  0x10


typedef struct {
    uint16_t x;
    uint16_t y;
    uint8_t flag;   //zx, nx, zy, ny, f, no, cin
} ALU_IN;

typedef struct {
    uint16_t out;
    uint8_t out_flag; //zr, ng, cout
} ALU_OUT;

void ALU(ALU_IN* in, ALU_OUT* out);

#endif
