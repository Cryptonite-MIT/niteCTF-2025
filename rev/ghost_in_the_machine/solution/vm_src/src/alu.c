#include "alu.h"
#include <stdint.h>

#include "alu.h"
#include <stdint.h>

void ALU(ALU_IN* in, ALU_OUT* out) {
    uint8_t flag = in->flag;
    uint16_t x = in->x;
    uint16_t y = in->y;
    uint16_t result;
    uint32_t sum;

    if (zx(flag)) {
        x = 0;
    }
    if (nx(flag)) {
        x = ~x;
    }

    if (zy(flag)) {
        y = 0;
    }
    if (ny(flag)) {
        y = ~y;
    }

    if (f(flag)) {
        result = x & y;
        out->out_flag = 0;
    } else {
        sum = (uint32_t)x + (uint32_t)y + ((uint32_t) (cin(flag)));
        result = (uint16_t)sum;
        out->out_flag = (sum >> 16) & 0x1 ? (1 << 2) : 0;
    }

    if (no(flag)) {
        result = ~result;
    }

    out->out = result;

    out->out_flag |= (result == 0) ? 1 : 0;
    out->out_flag |= ((result >> 15) & 1) << 1;
}
